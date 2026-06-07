from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import websockets

from .config import Config
from .core import CoreHTTPClient
from .models import MercuryEvent

MAX_LOG_FRAME_LENGTH = 2000

log = logging.getLogger(__name__)

EventHandler = Callable[[MercuryEvent], Any | Awaitable[Any]]


class MercuryClient:
    """Async Mercury websocket client with handler dispatch and reconnection."""

    def __init__(self, core: CoreHTTPClient, config: Config) -> None:
        """Create a Mercury client.

        Args:
            core: Shared HTTP client carrying the Webex access token.
            config: Runtime configuration for Mercury timing and fallback URLs.

        Returns:
            None.
        """
        log.debug("MercuryClient.__init__: initialize Mercury client")
        self._core = core
        self._config = config
        self._ws: Any = None
        self._connected = False
        self._connecting = False
        self._has_connected = False
        self._closing = False
        self._handlers: dict[str, list[EventHandler]] = {}
        self._lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None
        self._ping_task: asyncio.Task[None] | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._device_provider: Any = None
        self._custom_websocket_url = ""
        self._time_offset_ms = 0

    def set_device_provider(self, provider: Any) -> None:
        """Set the provider used to register devices and fetch websocket URLs.

        Args:
            provider: Object exposing ``register`` and ``get_websocket_url`` methods.

        Returns:
            None.
        """
        log.debug(
            "MercuryClient.set_device_provider: set device provider type=%s",
            type(provider).__name__,
        )
        self._device_provider = provider

    def set_custom_websocket_url(self, url: str) -> None:
        """Set a custom websocket URL that bypasses device registration lookup.

        Args:
            url: Mercury websocket URL to use for future connections.

        Returns:
            None.
        """
        log.debug("MercuryClient.set_custom_websocket_url: set custom websocket URL url=%s", url)
        self._custom_websocket_url = url

    async def connect(self) -> None:
        """Connect to Mercury using a custom URL or registered device URL.

        Returns:
            None.
        """
        # Validate and mark connection state under lock.
        log.debug("MercuryClient.connect: check connection state")
        async with self._lock:
            if self._connected:
                log.debug("MercuryClient.connect: already connected")
                return
            if self._connecting:
                raise RuntimeError("connection attempt already in progress")
            self._connecting = True
            self._closing = False
            custom_url = self._custom_websocket_url
            device_provider = self._device_provider

        try:
            # Prefer an explicit websocket URL when callers provide one.
            if custom_url:
                log.debug(
                    "MercuryClient.connect: connect with custom websocket URL url=%s", custom_url
                )
                await self._connect_with_backoff(custom_url)
                return
            if device_provider is None:
                raise RuntimeError("no device provider or custom URL available")
            # Otherwise register the device and use its current Mercury URL.
            log.debug("MercuryClient.connect: register device provider for websocket URL")
            await device_provider.register()
            websocket_url = await device_provider.get_websocket_url()
            if not websocket_url:
                raise RuntimeError("device provider returned empty WebSocket URL")
            log.debug(
                "MercuryClient.connect: connect with device websocket URL url=%s", websocket_url
            )
            await self._connect_with_backoff(websocket_url)
        except Exception:
            async with self._lock:
                self._connecting = False
            log.debug("MercuryClient.connect: connection failed", exc_info=True)
            raise

    async def disconnect(self) -> None:
        """Disconnect Mercury and cancel background websocket tasks.

        Returns:
            None.
        """
        # Atomically clear connection state and collect resources to close.
        log.debug("MercuryClient.disconnect: clear connection state")
        async with self._lock:
            if not self._connected and not self._connecting:
                log.debug("MercuryClient.disconnect: skip because client is not connected")
                return
            self._closing = True
            ws = self._ws
            self._ws = None
            self._connected = False
            self._connecting = False
            tasks = [task for task in (self._reader_task, self._ping_task) if task is not None]
            self._reader_task = None
            self._ping_task = None

        # Cancel background loops before closing the websocket.
        log.debug("MercuryClient.disconnect: cancel background tasks count=%s", len(tasks))
        for task in tasks:
            task.cancel()
        if ws is not None:
            log.debug("MercuryClient.disconnect: close websocket")
            await ws.close(code=1000, reason="Disconnected by client")

    async def listen(self) -> None:
        """Alias for ``connect`` for callers that model Mercury as a listener.

        Returns:
            None.
        """
        log.debug("MercuryClient.listen: start listening")
        await self.connect()

    async def stop_listening(self) -> None:
        """Alias for ``disconnect`` for listener-oriented callers.

        Returns:
            None.
        """
        log.debug("MercuryClient.stop_listening: stop listening")
        await self.disconnect()

    def on(self, event_type: str, handler: EventHandler) -> None:
        """Register a handler for a Mercury event type.

        Args:
            event_type: Event type such as ``conversation.activity`` or ``*``.
            handler: Synchronous or asynchronous handler callable.

        Returns:
            None.
        """
        if handler is None:
            log.debug("MercuryClient.on: skip empty handler event_type=%s", event_type)
            return
        log.debug("MercuryClient.on: register event handler event_type=%s", event_type)
        self._handlers.setdefault(event_type, []).append(handler)

    def off(self, event_type: str, handler: EventHandler) -> None:
        """Remove a previously registered Mercury handler.

        Args:
            event_type: Event type whose handlers should be updated.
            handler: Handler object to remove by identity.

        Returns:
            None.
        """
        log.debug("MercuryClient.off: remove event handler event_type=%s", event_type)
        handlers = self._handlers.get(event_type)
        if not handlers:
            log.debug("MercuryClient.off: no handlers registered event_type=%s", event_type)
            return
        self._handlers[event_type] = [entry for entry in handlers if entry is not handler]
        if not self._handlers[event_type]:
            self._handlers.pop(event_type, None)

    def clear_handlers(self, event_type: str) -> None:
        """Remove all handlers for one Mercury event type.

        Args:
            event_type: Event type to clear.

        Returns:
            None.
        """
        log.debug("MercuryClient.clear_handlers: clear event handlers event_type=%s", event_type)
        self._handlers.pop(event_type, None)

    def event_handlers(self) -> dict[str, list[EventHandler]]:
        """Return a copy of the registered handler mapping.

        Returns:
            Dictionary mapping event types to copied handler lists.
        """
        log.debug(
            "MercuryClient.event_handlers: copy handler registry count=%s", len(self._handlers)
        )
        return {key: list(value) for key, value in self._handlers.items()}

    def is_connected(self) -> bool:
        """Return whether Mercury is currently connected.

        Returns:
            ``True`` when a websocket connection is active.
        """
        log.debug("MercuryClient.is_connected: read connection state result=%s", self._connected)
        return self._connected

    def prepare_websocket_url(self, websocket_url: str) -> str:
        """Add SDK-required query parameters to a Mercury websocket URL.

        Args:
            websocket_url: Raw websocket URL returned by WDM or supplied by caller.

        Returns:
            URL with Mercury client query parameters applied.
        """
        # Preserve existing query parameters while adding SDK-required Mercury flags.
        log.debug(
            "MercuryClient.prepare_websocket_url: add Mercury query parameters url=%s",
            websocket_url,
        )
        parsed = urlparse(websocket_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.update(
            {
                "outboundWireFormat": "text",
                "bufferStates": "true",
                "aliasHttpStatus": "true",
                "clientTimestamp": str(int(time.time() * 1000)),
            }
        )
        return urlunparse(parsed._replace(query=urlencode(query)))

    async def _connect_with_backoff(self, websocket_url: str) -> None:
        """Attempt to connect with exponential backoff.

        Args:
            websocket_url: Mercury websocket URL to connect to.

        Returns:
            None.
        """
        log.debug(
            "MercuryClient._connect_with_backoff: begin connection attempts url=%s", websocket_url
        )
        retry_count = 0
        current_backoff = self._config.mercury_backoff_time_reset
        max_retries = (
            self._config.mercury_max_retries
            if self._has_connected
            else self._config.mercury_initial_connection_max_retries
        )
        last_error: Exception | None = None
        while retry_count <= max_retries:
            try:
                # A successful attempt starts reader and ping background loops.
                log.debug(
                    "MercuryClient._connect_with_backoff: attempt connection attempt=%s max=%s",
                    retry_count + 1,
                    max_retries + 1,
                )
                await self._attempt_connection(websocket_url)
                return
            except Exception as err:
                last_error = err
                retry_count += 1
                if retry_count > max_retries:
                    break
                # Increase the delay until the configured cap is reached.
                log.debug(
                    "MercuryClient._connect_with_backoff: retry connection attempt=%s delay=%s",
                    retry_count,
                    current_backoff,
                    exc_info=True,
                )
                await asyncio.sleep(current_backoff)
                current_backoff = min(current_backoff * 2, self._config.mercury_backoff_time_max)

        async with self._lock:
            self._connecting = False
        log.debug(
            "MercuryClient._connect_with_backoff: connection attempts exhausted count=%s error=%s",
            retry_count,
            last_error,
        )
        raise RuntimeError(f"failed to connect after {retry_count} attempts: {last_error}")

    async def _attempt_connection(self, websocket_url: str) -> None:
        """Open and authenticate a single Mercury websocket connection.

        Args:
            websocket_url: Raw Mercury websocket URL.

        Returns:
            None.
        """
        # Prepare URL and headers before opening the websocket.
        log.debug(
            "MercuryClient._attempt_connection: prepare websocket request url=%s", websocket_url
        )
        prepared_url = self.prepare_websocket_url(websocket_url)
        headers = {
            "Authorization": f"Bearer {self._core.access_token}",
            "TrackingID": f"python-kms-sdk_{int(time.time() * 1000)}",
        }
        log.debug(
            "MercuryClient._attempt_connection: open websocket url=%s headers=%s",
            prepared_url,
            {"Authorization": "<redacted>", "TrackingID": headers["TrackingID"]},
        )
        ws = await _websockets_connect(prepared_url, headers)
        try:
            log.debug("MercuryClient._attempt_connection: authenticate websocket")
            await self._authenticate_connection(ws)
        except Exception:
            await ws.close()
            log.debug("MercuryClient._attempt_connection: authentication failed", exc_info=True)
            raise

        # Publish connected state once authorization has succeeded.
        log.debug("MercuryClient._attempt_connection: publish connected state")
        async with self._lock:
            self._ws = ws
            self._connected = True
            self._connecting = False
            self._has_connected = True

        # Start background receive and keepalive loops for the active websocket.
        log.debug("MercuryClient._attempt_connection: start reader and ping tasks")
        self._reader_task = asyncio.create_task(self._reader_loop())
        self._ping_task = asyncio.create_task(self._ping_loop())

    async def _authenticate_connection(self, ws: Any) -> None:
        """Send the Mercury authorization frame and wait for confirmation.

        Args:
            ws: Open websocket connection.

        Returns:
            None.
        """
        log.debug("MercuryClient._authenticate_connection: send authorization message")
        auth_id = str(int(time.time() * 1000))
        auth_message = {
            "id": auth_id,
            "type": "authorization",
            "data": {"token": self._core.access_token},
            "trackingId": f"python-kms-sdk_{int(time.time() * 1000)}",
        }
        await ws.send(json.dumps(auth_message, separators=(",", ":")))

        async def wait_for_confirmation() -> None:
            """Wait until Mercury sends a registration or buffer-state event.

            Returns:
                None.
            """
            while True:
                raw = await ws.recv()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                log.debug(
                    "MercuryClient._authenticate_connection.wait_for_confirmation: "
                    "receive authorization response frame=%s",
                    _frame_preview(raw),
                )
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    log.debug(
                        "MercuryClient._authenticate_connection.wait_for_confirmation: "
                        "skip invalid JSON"
                    )
                    continue

                data = event.get("data") if isinstance(event, dict) else None
                if isinstance(data, dict):
                    event_type = data.get("eventType")
                    # Mercury confirms auth by sending registration/buffer state.
                    if event_type in {"mercury.buffer_state", "mercury.registration_status"}:
                        log.debug(
                            "MercuryClient._authenticate_connection.wait_for_confirmation: "
                            "authorization confirmed event_type=%s",
                            event_type,
                        )
                        await self._send_initial_ping(ws)
                        return
                if isinstance(event, dict) and event.get("type") == "error":
                    log.debug(
                        "MercuryClient._authenticate_connection.wait_for_confirmation: "
                        "authorization error response=%s",
                        event,
                    )
                    raise RuntimeError(f"authorization failed: {event}")

        await asyncio.wait_for(wait_for_confirmation(), timeout=30.0)

    async def _send_initial_ping(self, ws: Any) -> None:
        """Send the first ping after Mercury authorization succeeds.

        Args:
            ws: Authorized websocket connection.

        Returns:
            None.
        """
        ping_message = {"id": str(int(time.time() * 1000)), "type": "ping"}
        log.debug("MercuryClient._send_initial_ping: send initial ping message=%s", ping_message)
        await ws.send(json.dumps(ping_message, separators=(",", ":")))

    async def _reader_loop(self) -> None:
        """Continuously read websocket frames and dispatch parsed events.

        Returns:
            None.
        """
        log.debug("MercuryClient._reader_loop: start reader loop")
        try:
            while True:
                ws = self._ws
                if ws is None:
                    return
                raw = await ws.recv()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                # Ignore malformed frames and continue reading the stream.
                log.debug(
                    "MercuryClient._reader_loop: receive Mercury frame frame=%s",
                    _frame_preview(raw),
                )
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    log.debug("MercuryClient._reader_loop: skip invalid JSON frame")
                    continue
                if isinstance(parsed, dict):
                    await self.process_event(MercuryEvent.from_dict(parsed))
        except asyncio.CancelledError:
            log.debug("MercuryClient._reader_loop: reader loop cancelled")
            raise
        except Exception as err:
            log.debug("MercuryClient._reader_loop: reader loop error", exc_info=True)
            await self._handle_connection_error(err)
        finally:
            log.debug("MercuryClient._reader_loop: mark disconnected")
            self._connected = False

    async def process_event(self, event: MercuryEvent) -> None:
        """Normalize and dispatch a Mercury event.

        Args:
            event: Mercury event to process.

        Returns:
            None.
        """
        # Refresh derived metadata in case the caller built the event manually.
        log.debug(
            "MercuryClient.process_event: process Mercury event id=%s event_type=%s",
            event.id,
            event.event_type,
        )
        event.apply_header_overrides()
        event.extract_metadata()
        if event.event_type in {"mercury.buffer_state", "mercury.registration_status"}:
            log.debug(
                "MercuryClient.process_event: skip Mercury state event type=%s", event.event_type
            )
            return
        # Conversation post/share events also fan out as message.created.
        if event.event_type == "conversation.activity":
            await self._handle_conversation_activity(event)
        await self._dispatch_event(event)

    async def _handle_conversation_activity(self, event: MercuryEvent) -> None:
        """Emit message-created compatibility events for post/share activities.

        Args:
            event: Conversation activity Mercury event.

        Returns:
            None.
        """
        if event.activity_type not in {"post", "share"}:
            log.debug(
                "MercuryClient._handle_conversation_activity: skip non-message activity type=%s",
                event.activity_type,
            )
            return
        # Copy the event so compatibility handlers see message.created without mutating original.
        message_event = MercuryEvent(**{field: getattr(event, field) for field in event.__slots__})
        message_event.event_type = "message.created"
        log.debug(
            "MercuryClient._handle_conversation_activity: schedule message.created "
            "handlers count=%s",
            len(self._handlers.get("message.created", [])),
        )
        for handler in list(self._handlers.get("message.created", [])):
            asyncio.create_task(_invoke_handler(handler, message_event))

    async def _dispatch_event(self, event: MercuryEvent) -> None:
        """Schedule handlers matching an event, activity subtype, or wildcard.

        Args:
            event: Mercury event to dispatch.

        Returns:
            None.
        """
        # Merge exact, activity-specific, and wildcard handlers in dispatch order.
        handlers = list(self._handlers.get(event.event_type, []))
        if event.event_type == "conversation.activity" and event.activity_type:
            handlers.extend(self._handlers.get(f"activity:{event.activity_type}", []))
        handlers.extend(self._handlers.get("*", []))
        log.debug(
            "MercuryClient._dispatch_event: schedule event handlers event_type=%s "
            "activity_type=%s count=%s",
            event.event_type,
            event.activity_type,
            len(handlers),
        )
        for handler in handlers:
            asyncio.create_task(_invoke_handler(handler, event))

    async def _ping_loop(self) -> None:
        """Send periodic ping frames while the websocket is connected.

        Returns:
            None.
        """
        log.debug(
            "MercuryClient._ping_loop: start ping loop interval=%s",
            self._config.mercury_ping_interval,
        )
        try:
            while True:
                await asyncio.sleep(self._config.mercury_ping_interval)
                await self.ping()
        except asyncio.CancelledError:
            log.debug("MercuryClient._ping_loop: ping loop cancelled")
            raise
        except Exception as err:
            log.debug("MercuryClient._ping_loop: ping loop error", exc_info=True)
            await self._handle_connection_error(err)

    async def ping(self) -> None:
        """Send one websocket ping and update observed time offset.

        Returns:
            None.
        """
        ws = self._ws
        if ws is None:
            raise RuntimeError("websocket connection is nil")
        # Use the ping payload to approximate round-trip timing against local time.
        ping_time_ms = int(time.time() * 1000)
        log.debug("MercuryClient.ping: send websocket ping timestamp_ms=%s", ping_time_ms)
        waiter = await ws.ping(str(ping_time_ms).encode("ascii"))
        await asyncio.wait_for(waiter, timeout=self._config.mercury_pong_timeout)
        self._time_offset_ms = int(time.time() * 1000) - ping_time_ms
        log.debug("MercuryClient.ping: receive websocket pong offset_ms=%s", self._time_offset_ms)

    async def _handle_connection_error(self, _err: Exception) -> None:
        """Handle an unexpected websocket read or ping failure.

        Args:
            _err: Connection error that triggered handling.

        Returns:
            None.
        """
        log.debug(
            "MercuryClient._handle_connection_error: handle connection error "
            "connected=%s closing=%s",
            self._connected,
            self._closing,
        )
        was_connected = self._connected
        self._connected = False
        # Reconnect only for established connections that are not intentionally closing.
        if was_connected and not self._closing:
            await self._start_reconnect()

    async def _start_reconnect(self) -> None:
        """Start one background reconnect task if none is already running.

        Returns:
            None.
        """
        if self._reconnect_task is not None and not self._reconnect_task.done():
            log.debug("MercuryClient._start_reconnect: reconnect already running")
            return
        log.debug("MercuryClient._start_reconnect: schedule reconnect task")
        self._reconnect_task = asyncio.create_task(self._reconnect())

    async def _reconnect(self) -> None:
        """Close the old websocket and reconnect with the freshest URL available.

        Returns:
            None.
        """
        # Drop the old websocket before resolving the reconnect URL.
        log.debug("MercuryClient._reconnect: close stale websocket and resolve URL")
        ws = self._ws
        self._ws = None
        self._connecting = True
        if ws is not None:
            await ws.close()
        reconnect_url = await self._get_reconnect_url()
        if not reconnect_url:
            self._connecting = False
            log.debug("MercuryClient._reconnect: no reconnect URL available")
            return
        try:
            # Reuse normal backoff behavior for reconnection attempts.
            log.debug("MercuryClient._reconnect: reconnect with URL url=%s", reconnect_url)
            await self._connect_with_backoff(reconnect_url)
        finally:
            self._connecting = False

    async def _get_reconnect_url(self) -> str:
        """Resolve the websocket URL to use for reconnection.

        Returns:
            Custom URL, refreshed device websocket URL, fallback URL, or empty string.
        """
        if self._custom_websocket_url:
            log.debug("MercuryClient._get_reconnect_url: use custom websocket URL")
            return self._custom_websocket_url
        if self._device_provider is not None:
            try:
                # Device registration can refresh stale Mercury URLs after disconnects.
                log.debug("MercuryClient._get_reconnect_url: refresh device websocket URL")
                await self._device_provider.register()
                websocket_url = await self._device_provider.get_websocket_url()
                if websocket_url:
                    log.debug("MercuryClient._get_reconnect_url: use device websocket URL")
                    return websocket_url
            except Exception:
                log.debug(
                    "MercuryClient._get_reconnect_url: device websocket lookup failed",
                    exc_info=True,
                )
                return ""
        log.debug("MercuryClient._get_reconnect_url: use fallback websocket URL")
        return self._config.mercury_fallback_websocket_url


async def _invoke_handler(handler: EventHandler, event: MercuryEvent) -> None:
    """Invoke a Mercury handler and await it when needed.

    Args:
        handler: Handler callable to invoke.
        event: Mercury event passed to the handler.

    Returns:
        None.
    """
    log.debug("_invoke_handler: invoke Mercury event handler event_type=%s", event.event_type)
    result = handler(event)
    if inspect.isawaitable(result):
        log.debug("_invoke_handler: await async Mercury event handler")
        await result


async def _websockets_connect(url: str, headers: dict[str, str]) -> Any:
    """Open a websocket connection across supported websockets versions.

    Args:
        url: Websocket URL to connect to.
        headers: Authentication and tracking headers.

    Returns:
        Open websocket connection object.
    """
    log.debug("_websockets_connect: open websocket url=%s", url)
    try:
        return await websockets.connect(url, additional_headers=headers, open_timeout=10)
    except TypeError:
        log.debug("_websockets_connect: retry websocket open with legacy header argument")
        return await websockets.connect(url, extra_headers=headers, open_timeout=10)


def _frame_preview(raw: str) -> str:
    """Return a bounded websocket frame preview for debug logs.

    Args:
        raw: Raw websocket frame text.

    Returns:
        Text preview with long frames truncated.
    """
    if len(raw) > MAX_LOG_FRAME_LENGTH:
        return f"{raw[:MAX_LOG_FRAME_LENGTH]}...<truncated {len(raw)} chars>"
    return raw

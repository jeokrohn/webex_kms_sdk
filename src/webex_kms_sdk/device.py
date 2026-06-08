from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .config import Config
from .core import CoreHTTPClient
from .errors import api_error_from_response
from .models import Device

log = logging.getLogger(__name__)


class DeviceClient:
    """Client that registers and maintains the Webex device used by Mercury."""

    def __init__(self, core: CoreHTTPClient, config: Config) -> None:
        """Create a device client.

        :param core: Shared HTTP client used for WDM calls.
        :param config: Runtime configuration containing WDM endpoint settings.
        :returns: None.
        """
        log.debug("DeviceClient.__init__: initialize device client")
        self._core = core
        self._config = config
        self._device: Device | None = None
        self._registered = False
        self._registering = False
        self._lock = asyncio.Lock()
        self._callbacks: list[Callable[[], Any | Awaitable[Any]]] = []

    async def register(self) -> None:
        """Register a Webex device if one is not already available.

        :returns: None.
        """
        # Mark registration in progress under lock so concurrent callers share state safely.
        log.debug("DeviceClient.register: check registration state")
        async with self._lock:
            if self._device is not None:
                log.debug("DeviceClient.register: reuse existing device url=%s", self._device.url)
                return
            self._registering = True

        # Build the WDM payload and browser-like headers expected by Webex.
        log.debug("DeviceClient.register: build WDM API registration message")
        payload = {
            "deviceType": "TEAMS_SDK_JS",
            "name": "Webex SDK",
            "model": "Webex Python KMS SDK",
            "localizedModel": "Cisco Webex Teams",
            "systemName": "Webex Python KMS SDK",
            "systemVersion": "1.0.0",
        }
        headers = {
            "Accept": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ),
            "TrackingID": f"PythonKmsSDK_{int(time.time() * 1000)}",
        }
        try:
            # Create the remote device and normalize the response into the local model.
            log.debug(
                "DeviceClient.register: send WDM API registration request url=%s payload=%s",
                self._config.wdm_url,
                payload,
            )
            response = await self._core.request_url(
                "POST",
                self._config.wdm_url,
                params={"includeUpstreamServices": "all"},
                json=payload,
                headers=headers,
            )
            if response.status_code not in {200, 201}:
                log.debug(
                    "DeviceClient.register: WDM API registration failed status=%s response=%s",
                    response.status_code,
                    response.text,
                )
                raise api_error_from_response(response)
            data = response.json()
            log.debug(
                "DeviceClient.register: WDM API registration response status=%s url=%s",
                response.status_code,
                data.get("url") if isinstance(data, dict) else "",
            )
            device = Device.from_dict(data, etag=response.headers.get("ETag", ""))
        except Exception:
            async with self._lock:
                self._registering = False
            log.debug("DeviceClient.register: registration failed", exc_info=True)
            raise

        # Publish the registered device and snapshot callbacks outside the lock.
        log.debug("DeviceClient.register: store registered device url=%s", device.url)
        async with self._lock:
            self._device = device
            self._registered = True
            self._registering = False
            callbacks = list(self._callbacks)

        # Notify registered listeners without blocking registration completion.
        log.debug("DeviceClient.register: invoke registration callbacks count=%s", len(callbacks))
        for callback in callbacks:
            result = callback()
            if hasattr(result, "__await__"):
                asyncio.ensure_future(result)

    async def unregister(self) -> None:
        """Unregister the current Webex device.

        :returns: None.
        """
        # Snapshot the device to delete without holding the lock during I/O.
        log.debug("DeviceClient.unregister: read registered device state")
        async with self._lock:
            device = self._device
        if device is None or not device.url:
            log.debug("DeviceClient.unregister: skip unregister because device is missing")
            return
        # Delete the remote registration, then clear local state.
        log.debug("DeviceClient.unregister: send WDM API delete request url=%s", device.url)
        response = await self._core.request_url("DELETE", device.url)
        if response.status_code not in {200, 204}:
            log.debug(
                "DeviceClient.unregister: WDM API delete failed status=%s response=%s",
                response.status_code,
                response.text,
            )
            raise api_error_from_response(response)
        log.debug("DeviceClient.unregister: WDM API delete response status=%s", response.status_code)
        async with self._lock:
            self._device = None
            self._registered = False

    async def refresh(self) -> None:
        """Refresh the current Webex device registration from WDM.

        :returns: None.
        """
        # Read the current device snapshot before making the refresh request.
        log.debug("DeviceClient.refresh: read registered device state")
        async with self._lock:
            device = self._device
        if device is None or not device.url:
            raise RuntimeError("device not registered, cannot refresh")

        # Use the ETag when present so WDM can return 304 for unchanged registrations.
        headers = {"If-None-Match": device.etag} if device.etag else None
        log.debug(
            "DeviceClient.refresh: send WDM API refresh request url=%s etag_present=%s",
            device.url,
            bool(device.etag),
        )
        response = await self._core.request_url("PUT", device.url, headers=headers)
        if response.status_code == 304:
            log.debug("DeviceClient.refresh: WDM API refresh unchanged status=304")
            return
        if response.status_code < 200 or response.status_code >= 300:
            log.debug(
                "DeviceClient.refresh: WDM API refresh failed status=%s response=%s",
                response.status_code,
                response.text,
            )
            raise api_error_from_response(response)
        data = response.json()
        log.debug(
            "DeviceClient.refresh: WDM API refresh response status=%s url=%s",
            response.status_code,
            data.get("url") if isinstance(data, dict) else "",
        )
        refreshed = Device.from_dict(data, etag=response.headers.get("ETag", ""))
        # Store the refreshed representation for future Mercury/KMS calls.
        async with self._lock:
            self._device = refreshed
            self._registered = True

    async def get_websocket_url(self) -> str:
        """Return the Mercury websocket URL for the registered device.

        :returns: Websocket URL returned by WDM.
        """
        log.debug("DeviceClient.get_websocket_url: ensure registered device")
        await self._ensure_registered()
        async with self._lock:
            assert self._device is not None
            log.debug(
                "DeviceClient.get_websocket_url: return websocket URL present=%s",
                bool(self._device.web_socket_url),
            )
            return self._device.web_socket_url

    async def get_device_url(self) -> str:
        """Return the WDM URL for the registered device.

        :returns: Device resource URL.
        """
        log.debug("DeviceClient.get_device_url: ensure registered device")
        await self._ensure_registered()
        async with self._lock:
            assert self._device is not None
            log.debug("DeviceClient.get_device_url: return device URL url=%s", self._device.url)
            return self._device.url

    async def get_user_id(self) -> str:
        """Return the Webex user ID associated with the registered device.

        :returns: Webex user ID from WDM.
        """
        log.debug("DeviceClient.get_user_id: ensure registered device")
        await self._ensure_registered()
        async with self._lock:
            assert self._device is not None
            log.debug(
                "DeviceClient.get_user_id: return user ID present=%s",
                bool(self._device.user_id),
            )
            return self._device.user_id

    async def get_device(self) -> Device:
        """Return a copy of the current registered device.

        :returns: Device snapshot suitable for caller inspection.
        """
        log.debug("DeviceClient.get_device: ensure registered device")
        await self._ensure_registered()
        async with self._lock:
            assert self._device is not None
            log.debug("DeviceClient.get_device: return device snapshot url=%s", self._device.url)
            return Device.from_dict(self._device.raw, etag=self._device.etag)

    def on_registered(self, callback: Callable[[], Any | Awaitable[Any]]) -> None:
        """Register a callback that runs after device registration succeeds.

        :param callback: Synchronous or asynchronous callable with no arguments.
        :returns: None.
        """
        log.debug("DeviceClient.on_registered: add registration callback")
        self._callbacks.append(callback)
        # If registration already happened, invoke the callback immediately.
        if self._registered:
            log.debug("DeviceClient.on_registered: invoke callback immediately")
            result = callback()
            if hasattr(result, "__await__"):
                asyncio.ensure_future(result)

    def is_registered(self) -> bool:
        """Return whether this client currently has a registered device.

        :returns: ``True`` when a device registration is stored locally.
        """
        log.debug("DeviceClient.is_registered: read registration state result=%s", self._registered)
        return self._registered

    async def wait_for_registration(self, timeout: float) -> None:
        """Wait for the device to become registered.

        :param timeout: Maximum number of seconds to wait.
        :returns: None.
        """
        log.debug("DeviceClient.wait_for_registration: wait for registration timeout=%s", timeout)
        if self.is_registered():
            log.debug("DeviceClient.wait_for_registration: device already registered")
            return
        event = asyncio.Event()

        def mark_ready() -> None:
            """Signal that device registration completed.

            :returns: None.
            """
            log.debug("DeviceClient.wait_for_registration.mark_ready: signal registration ready")
            event.set()

        # Reuse the callback mechanism so waiters are notified by normal registration flow.
        self.on_registered(mark_ready)
        await asyncio.wait_for(event.wait(), timeout=timeout)
        log.debug("DeviceClient.wait_for_registration: registration observed")

    async def _ensure_registered(self) -> None:
        """Register the device on demand when needed by an accessor.

        :returns: None.
        """
        # Check under lock, then perform I/O outside the lock if registration is missing.
        log.debug("DeviceClient._ensure_registered: check registered state")
        async with self._lock:
            registered = self._device is not None
        if not registered:
            log.debug("DeviceClient._ensure_registered: trigger registration")
            await self.register()

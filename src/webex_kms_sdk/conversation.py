from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .config import Config
from .core import CoreHTTPClient
from .encryption import EncryptionClient
from .mercury import MercuryClient
from .models import Activity, ConversationObject, MercuryEvent

log = logging.getLogger(__name__)

ActivityHandler = Callable[[Activity], Any | Awaitable[Any]]
MESSAGE_ACTIVITY_TYPES = {"post", "share"}
WILDCARD_HANDLER = "*"


class ConversationClient:
    """High-level client that turns Mercury events into conversation activities."""

    def __init__(
        self,
        core: CoreHTTPClient,
        config: Config,
        mercury: MercuryClient,
        encryption: EncryptionClient,
    ) -> None:
        """Create a conversation client wired to Mercury and KMS clients.

        Args:
            core: Shared HTTP client reserved for future conversation APIs.
            config: Runtime configuration shared with the sub-clients.
            mercury: Mercury client used to receive websocket events.
            encryption: Encryption client used to decrypt message content.

        Returns:
            None.
        """
        log.debug("ConversationClient.__init__: initialize conversation client")
        self._core = core
        self._config = config
        self._mercury = mercury
        self._encryption = encryption
        self._handlers: dict[str, list[ActivityHandler]] = {}
        self._wire_mercury()

    def on(self, verb: str, handler: ActivityHandler) -> None:
        """Register an activity handler for a conversation verb.

        Args:
            verb: Activity verb such as ``post``, ``share``, or ``*``.
            handler: Callable invoked with matching activities.

        Returns:
            None.
        """
        if handler is None:
            log.debug("ConversationClient.on: skip empty handler verb=%s", verb)
            return
        log.debug("ConversationClient.on: register activity handler verb=%s", verb)
        self._handlers.setdefault(verb, []).append(handler)

    def off(self, verb: str, handler: ActivityHandler) -> None:
        """Remove a previously registered activity handler.

        Args:
            verb: Activity verb whose handler list should be updated.
            handler: Handler object to remove by identity.

        Returns:
            None.
        """
        log.debug("ConversationClient.off: remove activity handler verb=%s", verb)
        handlers = self._handlers.get(verb)
        if not handlers:
            log.debug("ConversationClient.off: no handlers registered verb=%s", verb)
            return
        self._handlers[verb] = [entry for entry in handlers if entry is not handler]
        if not self._handlers[verb]:
            self._handlers.pop(verb, None)

    async def connect(self) -> None:
        """Connect Mercury after sharing device details with the encryption client.

        Returns:
            None.
        """
        # Provide device identity to KMS so outbound retrieve requests have a client ID.
        log.debug("ConversationClient.connect: wire encryption device info")
        await self._wire_encryption_device_info()
        log.debug("ConversationClient.connect: connect Mercury client")
        await self._mercury.connect()

    async def disconnect(self) -> None:
        """Disconnect the underlying Mercury websocket client.

        Returns:
            None.
        """
        log.debug("ConversationClient.disconnect: disconnect Mercury client")
        await self._mercury.disconnect()

    def process_activity_event(self, event: MercuryEvent) -> Activity:
        """Extract a conversation activity from a Mercury event.

        Args:
            event: Mercury event expected to contain conversation activity data.

        Returns:
            Parsed ``Activity`` model.
        """
        log.debug(
            "ConversationClient.process_activity_event: parse activity event id=%s event_type=%s",
            event.id,
            event.event_type,
        )
        if not event.data:
            raise ValueError("event data is nil")
        activity_data = event.data.get("activity")
        if not isinstance(activity_data, dict):
            raise ValueError("activity data is missing or invalid")
        return Activity.from_dict(activity_data, raw_data=event.data)

    async def get_message_content(self, activity: Activity) -> str:
        """Return plaintext message content for an activity when possible.

        Args:
            activity: Conversation activity to inspect and optionally decrypt.

        Returns:
            Plaintext content, falling back to display name when decryption fails.
        """
        # Prefer content that has already been decrypted or populated by dispatch.
        log.debug(
            "ConversationClient.get_message_content: resolve message content activity_id=%s",
            activity.id,
        )
        if activity.content:
            log.debug("ConversationClient.get_message_content: return cached content")
            return activity.content
        if activity.decrypted_object is not None and activity.decrypted_object.content:
            log.debug("ConversationClient.get_message_content: return decrypted object content")
            return activity.decrypted_object.content
        if not activity.object:
            raise ValueError("no content found in activity")

        display_name = activity.object.get("displayName")
        if not isinstance(display_name, str) or not display_name:
            raise ValueError("no displayName found in activity")

        # Decrypt encrypted displayName values when the activity includes a KMS key URL.
        if activity.encryption_key_url:
            try:
                log.debug(
                    "ConversationClient.get_message_content: decrypt activity content key_uri=%s",
                    activity.encryption_key_url,
                )
                return await self._encryption.decrypt_message_content(
                    activity.encryption_key_url,
                    display_name,
                )
            except Exception:
                log.debug(
                    "ConversationClient.get_message_content: decrypt failed, return fallback",
                    exc_info=True,
                )
                return display_name
        log.debug("ConversationClient.get_message_content: return displayName fallback")
        return display_name

    def process_event_kms_messages(self, event: MercuryEvent) -> None:
        """Extract and process KMS messages embedded in a Mercury event.

        Args:
            event: Mercury event that may contain KMS response JWEs.

        Returns:
            None.
        """
        log.debug(
            "ConversationClient.process_event_kms_messages: extract KMS messages event_id=%s",
            event.id,
        )
        if not event.data:
            return
        kms_messages: list[Any] = []

        # Support the nested shape used by newer encryption payloads.
        encryption_data = event.data.get("encryption")
        if isinstance(encryption_data, dict):
            nested = encryption_data.get("kmsMessages")
            if isinstance(nested, list):
                kms_messages = nested
                log.debug(
                    "ConversationClient.process_event_kms_messages: found nested KMS "
                    "messages count=%s",
                    len(kms_messages),
                )

        # Support flattened and direct shapes found in older Mercury payloads.
        if not kms_messages:
            dotted = event.data.get("encryption.kmsMessages")
            if isinstance(dotted, list):
                kms_messages = dotted
                log.debug(
                    "ConversationClient.process_event_kms_messages: found dotted KMS "
                    "messages count=%s",
                    len(kms_messages),
                )

        if not kms_messages:
            direct = event.data.get("kmsMessages")
            if isinstance(direct, list):
                kms_messages = direct
                log.debug(
                    "ConversationClient.process_event_kms_messages: found direct KMS "
                    "messages count=%s",
                    len(kms_messages),
                )

        # Some events serialize the encryption object as JSON text.
        if not kms_messages and isinstance(encryption_data, str):
            try:
                parsed = json.loads(encryption_data)
            except json.JSONDecodeError:
                parsed = {}
                log.debug(
                    "ConversationClient.process_event_kms_messages: serialized encryption "
                    "parse failed"
                )
            if isinstance(parsed, dict) and isinstance(parsed.get("kmsMessages"), list):
                kms_messages = parsed["kmsMessages"]
                log.debug(
                    "ConversationClient.process_event_kms_messages: found serialized KMS "
                    "messages count=%s",
                    len(kms_messages),
                )

        # Forward only non-empty JWE strings to the encryption client.
        jwe_strings = [item for item in kms_messages if isinstance(item, str) and item]
        if jwe_strings:
            log.debug(
                "ConversationClient.process_event_kms_messages: process KMS messages count=%s",
                len(jwe_strings),
            )
            self._encryption.process_kms_messages(jwe_strings)

    def encryption_client(self) -> EncryptionClient:
        """Return the encryption client used by this conversation client.

        Returns:
            Bound ``EncryptionClient`` instance.
        """
        log.debug("ConversationClient.encryption_client: return encryption client")
        return self._encryption

    def mercury_client(self) -> MercuryClient:
        """Return the Mercury client used by this conversation client.

        Returns:
            Bound ``MercuryClient`` instance.
        """
        log.debug("ConversationClient.mercury_client: return Mercury client")
        return self._mercury

    def _wire_mercury(self) -> None:
        """Register internal Mercury handlers needed by conversation dispatch.

        Returns:
            None.
        """
        log.debug("ConversationClient._wire_mercury: register internal Mercury handlers")
        self._mercury.on("conversation.activity", self._handle_conversation_event)
        self._mercury.on("encryption.kms_message", self._handle_kms_event)

    async def _wire_encryption_device_info(self) -> None:
        """Copy Mercury device identity into the encryption client when available.

        Returns:
            None.
        """
        # The Mercury device provider is intentionally optional for custom websocket URLs.
        log.debug(
            "ConversationClient._wire_encryption_device_info: inspect Mercury device provider"
        )
        provider = getattr(self._mercury, "_device_provider", None)
        if provider is None:
            log.debug(
                "ConversationClient._wire_encryption_device_info: no device provider available"
            )
            return
        try:
            # Register first so device URL and user ID accessors are populated.
            log.debug("ConversationClient._wire_encryption_device_info: register device provider")
            await provider.register()
            device_url = await provider.get_device_url()
            user_id = await provider.get_user_id()
        except Exception:
            log.debug(
                "ConversationClient._wire_encryption_device_info: device info unavailable",
                exc_info=True,
            )
            return
        log.debug(
            "ConversationClient._wire_encryption_device_info: set encryption device info "
            "device_url=%s user_id_present=%s",
            device_url,
            bool(user_id),
        )
        self._encryption.set_device_info(device_url, user_id)

    async def _handle_conversation_event(self, event: MercuryEvent) -> None:
        """Handle a raw conversation Mercury event.

        Args:
            event: Mercury conversation event.

        Returns:
            None.
        """
        # KMS messages can arrive alongside the activity that needs them.
        log.debug(
            "ConversationClient._handle_conversation_event: handle conversation event id=%s",
            event.id,
        )
        self.process_event_kms_messages(event)
        try:
            activity = self.process_activity_event(event)
        except ValueError:
            log.debug(
                "ConversationClient._handle_conversation_event: skip invalid activity event",
                exc_info=True,
            )
            return
        await self._dispatch_activity(activity)

    async def _handle_kms_event(self, event: MercuryEvent) -> None:
        """Handle a Mercury event that carries only KMS response messages.

        Args:
            event: Mercury encryption event.

        Returns:
            None.
        """
        log.debug("ConversationClient._handle_kms_event: handle KMS event id=%s", event.id)
        self.process_event_kms_messages(event)

    async def _dispatch_activity(self, activity: Activity) -> None:
        """Schedule handlers that match an activity verb.

        Args:
            activity: Activity to dispatch.

        Returns:
            None.
        """
        # Combine verb-specific handlers with wildcard observers.
        handlers = list(self._handlers.get(activity.verb, []))
        handlers.extend(self._handlers.get(WILDCARD_HANDLER, []))
        log.debug(
            "ConversationClient._dispatch_activity: schedule activity handlers activity_id=%s "
            "verb=%s count=%s",
            activity.id,
            activity.verb,
            len(handlers),
        )
        for handler in handlers:
            asyncio.create_task(self._invoke_activity_handler(handler, activity))

    async def _invoke_activity_handler(self, handler: ActivityHandler, activity: Activity) -> None:
        """Invoke one activity handler with optional message decryption first.

        Args:
            handler: Handler callable to invoke.
            activity: Activity passed to the handler.

        Returns:
            None.
        """
        # Populate message content before user code observes post/share activities.
        log.debug(
            "ConversationClient._invoke_activity_handler: invoke activity handler activity_id=%s "
            "verb=%s",
            activity.id,
            activity.verb,
        )
        if activity.verb in MESSAGE_ACTIVITY_TYPES:
            await self._process_message_content(activity)
        result = handler(activity)
        if inspect.isawaitable(result):
            log.debug("ConversationClient._invoke_activity_handler: await async handler")
            await result

    async def _process_message_content(self, activity: Activity) -> None:
        """Populate plaintext message content on an activity when possible.

        Args:
            activity: Activity whose object may contain encrypted message content.

        Returns:
            None.
        """
        log.debug(
            "ConversationClient._process_message_content: process message content activity_id=%s",
            activity.id,
        )
        if not activity.object:
            return
        # Normalize the nested activity object and keep it on the activity for callers.
        obj = ConversationObject.from_dict(activity.object)
        activity.decrypted_object = obj
        if not obj.display_name:
            return
        activity.content = obj.display_name
        # Try to decrypt encrypted displayName content while preserving the fallback.
        if activity.encryption_key_url:
            try:
                log.debug(
                    "ConversationClient._process_message_content: decrypt message content "
                    "key_uri=%s",
                    activity.encryption_key_url,
                )
                activity.content = await self._encryption.decrypt_message_content(
                    activity.encryption_key_url,
                    obj.display_name,
                )
            except Exception:
                log.debug(
                    "ConversationClient._process_message_content: decrypt failed, keep fallback",
                    exc_info=True,
                )
                return

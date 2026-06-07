from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url string that may omit padding.

    :param value: Base64url-encoded string.
    :returns: Decoded bytes.
    """
    import base64

    log.debug("_b64url_decode: decode base64url value length=%s", len(value))
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


@dataclass(slots=True)
class Device:
    """Registered Webex device metadata returned by WDM."""

    url: str = ""
    web_socket_url: str = ""
    user_id: str = ""
    device_type: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    etag: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], etag: str = "") -> Device:
        """Create a ``Device`` from a WDM response object.

        :param data: Raw WDM device response dictionary.
        :param etag: Optional entity tag from the HTTP response.
        :returns: Normalized ``Device`` instance.
        """
        log.debug(
            "Device.from_dict: parse API device response url=%s websocket_present=%s "
            "etag_present=%s",
            data.get("url"),
            bool(data.get("webSocketUrl")),
            bool(etag),
        )
        return cls(
            url=str(data.get("url") or ""),
            web_socket_url=str(data.get("webSocketUrl") or ""),
            user_id=str(data.get("userId") or ""),
            device_type=str(data.get("deviceType") or ""),
            raw=dict(data),
            etag=etag,
        )


@dataclass(slots=True)
class MercuryEvent:
    """Mercury websocket event with normalized routing metadata."""

    id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: int = 0
    tracking_id: str = ""
    alert_type: str = ""
    sequence_number: int = 0
    filter_message: bool = False
    ws_write_timestamp: int = 0
    headers: dict[str, Any] = field(default_factory=dict)
    event_type: str = ""
    activity_type: str = ""
    websocket_error: str = ""
    resource_type: str = ""
    actor_id: str = ""
    org_id: str = ""
    resource: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MercuryEvent:
        """Create a ``MercuryEvent`` from a raw websocket event.

        :param data: Raw Mercury event dictionary.
        :returns: Normalized event with header overrides and metadata extracted.
        """
        # Copy raw wire fields into stable attributes.
        log.debug(
            "MercuryEvent.from_dict: parse Mercury event id=%s event_type=%s",
            data.get("id"),
            (data.get("data") or {}).get("eventType") if isinstance(data.get("data"), dict) else "",
        )
        event = cls(
            id=str(data.get("id") or ""),
            data=dict(data.get("data") or {}),
            timestamp=int(data.get("timestamp") or 0),
            tracking_id=str(data.get("trackingId") or ""),
            alert_type=str(data.get("alertType") or ""),
            sequence_number=int(data.get("sequenceNumber") or 0),
            filter_message=bool(data.get("filterMessage") or False),
            ws_write_timestamp=int(data.get("wsWriteTimestamp") or 0),
            headers=dict(data.get("headers") or {}),
            raw=dict(data),
        )
        # Promote routing fields so dispatch code does not re-parse payloads.
        event.apply_header_overrides()
        event.extract_metadata()
        return event

    def apply_header_overrides(self) -> None:
        """Apply Mercury header IDs that override top-level event fields.

        :returns: None.
        """
        if not self.headers:
            return
        log.debug(
            "MercuryEvent.apply_header_overrides: apply header overrides event_id=%s",
            self.id,
        )
        if isinstance(self.headers.get("trackingId"), str):
            self.tracking_id = self.headers["trackingId"]
        if isinstance(self.headers.get("id"), str):
            self.id = self.headers["id"]

    def extract_metadata(self) -> None:
        """Extract event and activity metadata used by client dispatchers.

        :returns: None.
        """
        # Capture the broad event type first; only conversation events carry activity metadata.
        log.debug("MercuryEvent.extract_metadata: extract event metadata event_id=%s", self.id)
        event_type = self.data.get("eventType")
        if isinstance(event_type, str):
            self.event_type = event_type
        if self.event_type != "conversation.activity":
            return

        activity = self.data.get("activity")
        if not isinstance(activity, dict):
            return

        # Promote frequently used activity, actor, organization, and resource fields.
        verb = activity.get("verb")
        if isinstance(verb, str):
            self.activity_type = verb

        actor = activity.get("actor")
        if isinstance(actor, dict):
            if isinstance(actor.get("id"), str):
                self.actor_id = actor["id"]
            if isinstance(actor.get("orgId"), str):
                self.org_id = actor["orgId"]

        obj = activity.get("object")
        if isinstance(obj, dict):
            self.resource = dict(obj)
            if isinstance(obj.get("objectType"), str):
                self.resource_type = obj["objectType"]


@dataclass(slots=True)
class JWK:
    """JSON Web Key representation used by KMS and local crypto helpers."""

    kty: str = ""
    k: str = ""
    crv: str = ""
    x: str = ""
    y: str = ""
    d: str = ""
    n: str = ""
    e: str = ""
    kid: str = ""
    alg: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWK:
        """Create a ``JWK`` from a dictionary.

        :param data: JSON Web Key fields.
        :returns: Normalized ``JWK`` instance.
        """
        log.debug(
            "JWK.from_dict: parse JWK key_type=%s kid=%s fields=%s",
            data.get("kty"),
            data.get("kid"),
            sorted(data),
        )
        return cls(
            kty=str(data.get("kty") or ""),
            k=str(data.get("k") or ""),
            crv=str(data.get("crv") or ""),
            x=str(data.get("x") or ""),
            y=str(data.get("y") or ""),
            d=str(data.get("d") or ""),
            n=str(data.get("n") or ""),
            e=str(data.get("e") or ""),
            kid=str(data.get("kid") or ""),
            alg=str(data.get("alg") or ""),
        )

    def to_dict(self, include_private: bool = True) -> dict[str, str]:
        """Serialize the key to a compact JWK dictionary.

        :param include_private: Whether to include private key material such as ``d``.
        :returns: Dictionary containing only populated JWK fields.
        """
        log.debug(
            "JWK.to_dict: serialize JWK key_type=%s kid=%s include_private=%s",
            self.kty,
            self.kid,
            include_private,
        )
        result: dict[str, str] = {"kty": self.kty}
        # Only emit fields that have values so outbound JWKs stay compact.
        for name, value in (
            ("k", self.k),
            ("crv", self.crv),
            ("x", self.x),
            ("y", self.y),
            ("d", self.d if include_private else ""),
            ("n", self.n),
            ("e", self.e),
            ("kid", self.kid),
            ("alg", self.alg),
        ):
            if value:
                result[name] = value
        return result

    def symmetric_key(self) -> bytes:
        """Decode this JWK as an octet symmetric key.

        :returns: Raw symmetric key bytes.
        """
        log.debug("JWK.symmetric_key: decode symmetric key kid=%s key_type=%s", self.kid, self.kty)
        if self.kty != "oct":
            raise ValueError(f'key type is {self.kty!r}, expected "oct" for symmetric key')
        if not self.k:
            raise ValueError("symmetric key value (k) is empty")
        return _b64url_decode(self.k)


@dataclass(slots=True)
class Key:
    """KMS key envelope containing a URI and JWK material."""

    uri: str
    jwk: JWK

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Key:
        """Create a ``Key`` from a KMS response object.

        :param data: Raw key dictionary from KMS.
        :returns: Normalized ``Key`` instance.
        """
        log.debug("Key.from_dict: parse KMS key uri=%s", data.get("uri"))
        return cls(uri=str(data.get("uri") or ""), jwk=JWK.from_dict(dict(data.get("jwk") or {})))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the key envelope to a dictionary.

        :returns: Dictionary containing the key URI and JWK fields.
        """
        log.debug("Key.to_dict: serialize KMS key uri=%s", self.uri)
        return {"uri": self.uri, "jwk": self.jwk.to_dict()}


@dataclass(slots=True)
class KMSMessage:
    """Parsed KMS protocol message."""

    method: str = ""
    uri: str = ""
    resource_uri: str = ""
    request_id: str = ""
    status: Any = None
    key: Key | None = None
    keys: list[Key] = field(default_factory=list)
    user_ids: list[str] = field(default_factory=list)
    key_uris: list[str] = field(default_factory=list)
    resource: dict[str, Any] = field(default_factory=dict)
    jwk: JWK | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KMSMessage:
        """Create a ``KMSMessage`` from a raw KMS payload.

        :param data: Raw KMS message dictionary.
        :returns: Normalized ``KMSMessage`` instance.
        """
        # Parse optional single-key, multi-key, and ECDH JWK fields.
        log.debug(
            "KMSMessage.from_dict: parse KMS message method=%s uri=%s request_id=%s status=%s",
            data.get("method"),
            data.get("uri") or data.get("resourceUri"),
            data.get("requestId"),
            data.get("status"),
        )
        key_data = data.get("key")
        keys_data = data.get("keys") or []
        jwk_data = data.get("jwk")
        return cls(
            method=str(data.get("method") or ""),
            uri=str(data.get("uri") or ""),
            resource_uri=str(data.get("resourceUri") or ""),
            request_id=str(data.get("requestId") or ""),
            status=data.get("status"),
            key=Key.from_dict(key_data) if isinstance(key_data, dict) else None,
            keys=[Key.from_dict(k) for k in keys_data if isinstance(k, dict)],
            user_ids=[str(v) for v in data.get("userIds") or []],
            key_uris=[str(v) for v in data.get("keyUris") or []],
            resource=dict(data.get("resource") or {}),
            jwk=JWK.from_dict(jwk_data) if isinstance(jwk_data, dict) else None,
            raw=dict(data),
        )

    def is_success(self) -> bool:
        """Return whether the message status indicates a successful KMS operation.

        :returns: ``True`` for successful numeric or string KMS status values.
        """
        log.debug("KMSMessage.is_success: evaluate KMS status status=%s", self.status)
        if isinstance(self.status, str):
            return self.status in {"success", "200", "201"}
        if isinstance(self.status, int):
            return self.status in {200, 201}
        if isinstance(self.status, float):
            return int(self.status) in {200, 201}
        return False


@dataclass(slots=True)
class ConversationObject:
    """Conversation object embedded in a Webex activity."""

    object_type: str = ""
    display_name: str = ""
    content: str = ""
    content_type: str = ""
    id: str = ""
    url: str = ""
    published: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConversationObject:
        """Create a conversation object from activity object data.

        :param data: Raw activity object dictionary.
        :returns: Normalized ``ConversationObject`` instance.
        """
        log.debug(
            "ConversationObject.from_dict: parse conversation object id=%s type=%s",
            data.get("id"),
            data.get("objectType"),
        )
        return cls(
            object_type=str(data.get("objectType") or ""),
            display_name=str(data.get("displayName") or ""),
            content=str(data.get("content") or ""),
            content_type=str(data.get("contentType") or ""),
            id=str(data.get("id") or ""),
            url=str(data.get("url") or ""),
            published=str(data.get("published") or ""),
            raw=dict(data),
        )


@dataclass(slots=True)
class Activity:
    """High-level Webex conversation activity."""

    id: str = ""
    object_type: str = ""
    url: str = ""
    published: str = ""
    verb: str = ""
    actor: dict[str, Any] = field(default_factory=dict)
    object: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    client_temp_id: str = ""
    encryption_key_url: str = ""
    content: str = ""
    decrypted_object: ConversationObject | None = None
    message_type: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], raw_data: dict[str, Any] | None = None) -> Activity:
        """Create an activity from conversation payload data.

        :param data: Raw activity dictionary.
        :param raw_data: Optional parent event data to retain for callers.
        :returns: Normalized ``Activity`` instance.
        """
        log.debug(
            "Activity.from_dict: parse activity id=%s verb=%s encrypted=%s",
            data.get("id"),
            data.get("verb"),
            bool(data.get("encryptionKeyUrl")),
        )
        return cls(
            id=str(data.get("id") or ""),
            object_type=str(data.get("objectType") or ""),
            url=str(data.get("url") or ""),
            published=str(data.get("published") or ""),
            verb=str(data.get("verb") or ""),
            actor=dict(data.get("actor") or {}),
            object=dict(data.get("object") or {}),
            target=dict(data.get("target") or {}),
            client_temp_id=str(data.get("clientTempId") or ""),
            encryption_key_url=str(data.get("encryptionKeyUrl") or ""),
            message_type=str(data.get("verb") or ""),
            raw_data=dict(raw_data or {}),
        )

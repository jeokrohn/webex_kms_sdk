from __future__ import annotations

import asyncio
import base64
import os

import pytest

from webex_kms_sdk import JWK, Key, MercuryEvent, WebexClient
from webex_kms_sdk.encryption import wrap_with_shared_secret


def b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url text for test JWK values.

    Args:
        data: Bytes to encode.

    Returns:
        Base64url string without padding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_process_activity_event() -> None:
    """Verify that conversation activity payloads become ``Activity`` models.

    Returns:
        None.
    """
    # Arrange a Mercury event that carries the conversation activity shape.
    client = WebexClient("test-token")
    event = MercuryEvent.from_dict(
        {
            "data": {
                "eventType": "conversation.activity",
                "activity": {
                    "id": "activity-1",
                    "verb": "post",
                    "encryptionKeyUrl": "kms://test/keys/1",
                    "object": {"displayName": "encrypted"},
                },
            }
        }
    )

    # Act by parsing the event through the high-level conversation client.
    activity = client.conversation.process_activity_event(event)

    # Assert key activity fields are normalized.
    assert activity.id == "activity-1"
    assert activity.verb == "post"
    assert activity.encryption_key_url == "kms://test/keys/1"


@pytest.mark.asyncio
async def test_get_message_content_decrypts_cached_key() -> None:
    """Verify cached KMS keys decrypt message content.

    Returns:
        None.
    """
    # Arrange an encrypted display name with its key already cached.
    client = WebexClient("test-token")
    raw_key = os.urandom(32)
    key_uri = "kms://test/keys/conv"
    ciphertext = wrap_with_shared_secret(b"decrypted conversation", raw_key)
    client.encryption.cache_key(Key(uri=key_uri, jwk=JWK(kty="oct", k=b64url(raw_key))))
    event = MercuryEvent.from_dict(
        {
            "data": {
                "eventType": "conversation.activity",
                "activity": {
                    "verb": "post",
                    "encryptionKeyUrl": key_uri,
                    "object": {"displayName": ciphertext},
                },
            }
        }
    )
    activity = client.conversation.process_activity_event(event)

    # Act and assert that the conversation helper returns plaintext.
    assert await client.conversation.get_message_content(activity) == "decrypted conversation"
    await client.aclose()


@pytest.mark.asyncio
async def test_conversation_dispatch_auto_decrypts_message_content() -> None:
    """Verify dispatched message activities are decrypted before handlers run.

    Returns:
        None.
    """
    # Arrange a cached key and a handler that records observed activity content.
    client = WebexClient("test-token")
    raw_key = os.urandom(32)
    key_uri = "kms://test/keys/dispatch"
    ciphertext = wrap_with_shared_secret(b"handler sees plaintext", raw_key)
    client.encryption.cache_key(Key(uri=key_uri, jwk=JWK(kty="oct", k=b64url(raw_key))))
    seen = asyncio.get_running_loop().create_future()

    async def handler(activity) -> None:
        """Capture content seen by the dispatched activity handler.

        Args:
            activity: Activity delivered by the conversation dispatcher.

        Returns:
            None.
        """
        if not seen.done():
            seen.set_result(activity.content)

    client.conversation.on("post", handler)
    event = MercuryEvent.from_dict(
        {
            "data": {
                "eventType": "conversation.activity",
                "activity": {
                    "verb": "post",
                    "encryptionKeyUrl": key_uri,
                    "object": {"displayName": ciphertext},
                },
            }
        }
    )

    # Act by handling the raw Mercury event, which schedules the activity handler.
    await client.conversation._handle_conversation_event(event)

    # Assert the handler observed plaintext, not ciphertext.
    assert await asyncio.wait_for(seen, timeout=1.0) == "handler sees plaintext"
    await client.aclose()


def test_process_event_kms_messages_extracts_supported_shapes() -> None:
    """Verify KMS messages are extracted from supported Mercury payload shapes.

    Returns:
        None.
    """
    # Arrange a conversation client with a capture stub for KMS forwarding.
    client = WebexClient("test-token")
    captured: list[list[str]] = []
    client.encryption.process_kms_messages = captured.append  # type: ignore[method-assign]

    # Act across nested, flattened, direct, and serialized encryption payloads.
    for data in (
        {"encryption": {"kmsMessages": ["a"]}},
        {"encryption.kmsMessages": ["b"]},
        {"kmsMessages": ["c"]},
        {"encryption": '{"kmsMessages":["d"]}'},
    ):
        client.conversation.process_event_kms_messages(MercuryEvent(data=data))

    # Assert each supported shape forwarded only its KMS message strings.
    assert captured == [["a"], ["b"], ["c"], ["d"]]

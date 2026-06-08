from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any
from unittest import TestCase

import httpx
import pytest
import respx
import websockets
from cryptography.hazmat.primitives.asymmetric import ec
from dotenv import load_dotenv

import webex_kms_sdk.threaded as threaded_module
from webex_kms_sdk import JWK, Config, Key, ThreadedWebexClient
from webex_kms_sdk.encryption import ECDHContext, wrap_with_shared_secret


def b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url text for test JWK values.

    :param data: Bytes to encode.
    :returns: Base64url string without padding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class FakeEncryption:
    """Small async encryption double used by threaded facade tests."""

    def __init__(self) -> None:
        """Create the fake encryption client.

        :returns: None.
        """
        self.get_key_thread_id = 0
        self.decrypt_thread_id = 0

    async def get_key(self, key_uri: str) -> Key:
        """Return a fake key or raise a sentinel error.

        :param key_uri: KMS key URI to retrieve.
        :returns: Fake ``Key`` model.
        """
        self.get_key_thread_id = threading.get_ident()
        await asyncio.sleep(0.01)
        if key_uri == "kms://test/keys/error":
            raise ValueError("fake get_key failure")
        return Key(uri=key_uri, jwk=JWK(kty="oct", k=b64url(os.urandom(32)), kid="fake"))

    async def decrypt_text(self, key_uri: str, ciphertext: str) -> str:
        """Return deterministic fake plaintext.

        :param key_uri: KMS key URI.
        :param ciphertext: Ignored ciphertext.
        :returns: Fake plaintext.
        """
        self.decrypt_thread_id = threading.get_ident()
        await asyncio.sleep(0.01)
        return f"plain:{key_uri}:{ciphertext}"


class FakeMercury:
    """Small Mercury double that records custom websocket configuration."""

    def __init__(self) -> None:
        """Create the fake Mercury client.

        :returns: None.
        """
        self.custom_websocket_url = ""

    def set_custom_websocket_url(self, url: str) -> None:
        """Record the configured websocket URL.

        :param url: Mercury websocket URL.
        :returns: None.
        """
        self.custom_websocket_url = url


class FakeConversation:
    """Small async conversation double used for lifecycle assertions."""

    def __init__(self) -> None:
        """Create the fake conversation client.

        :returns: None.
        """
        self.connect_calls = 0
        self.connect_thread_id = 0

    async def connect(self) -> None:
        """Record a fake connect call.

        :returns: None.
        """
        self.connect_calls += 1
        self.connect_thread_id = threading.get_ident()


class FakeWebexClient:
    """Small async Webex client double used by threaded facade tests."""

    instances: list[FakeWebexClient] = []

    def __init__(self, access_token: str, config: Config | None = None) -> None:
        """Create a fake Webex client.

        :param access_token: Webex bearer token.
        :param config: Optional SDK configuration.
        :returns: None.
        """
        self.access_token = access_token
        self.config = config
        self.constructor_thread_id = threading.get_ident()
        self.encryption = FakeEncryption()
        self.mercury = FakeMercury()
        self.conversation = FakeConversation()
        self.close_calls = 0
        self.close_thread_id = 0
        FakeWebexClient.instances.append(self)

    async def aclose(self) -> None:
        """Record a fake close call.

        :returns: None.
        """
        self.close_calls += 1
        self.close_thread_id = threading.get_ident()


def install_fake_webex_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the fake async client into the threaded module.

    :param monkeypatch: Pytest monkeypatch fixture.
    :returns: None.
    """
    FakeWebexClient.instances = []
    monkeypatch.setattr(threaded_module, "WebexClient", FakeWebexClient)


def test_threaded_client_context_manager_connects_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify context manager startup, blocking calls, and cleanup.

    :returns: None.
    """
    install_fake_webex_client(monkeypatch)

    with ThreadedWebexClient("test-token", Config()) as client:
        fake = FakeWebexClient.instances[0]
        key = client.get_key("kms://test/keys/1")
        plaintext = client.decrypt_text("kms://test/keys/1", "ciphertext")

        assert fake.access_token == "test-token"
        assert fake.conversation.connect_calls == 1
        assert fake.constructor_thread_id != threading.get_ident()
        assert fake.encryption.get_key_thread_id == fake.constructor_thread_id
        assert key.uri == "kms://test/keys/1"
        assert plaintext == "plain:kms://test/keys/1:ciphertext"

    assert fake.close_calls == 1
    assert fake.close_thread_id == fake.constructor_thread_id


def test_threaded_client_connect_close_are_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify explicit connect and close are idempotent.

    :returns: None.
    """
    install_fake_webex_client(monkeypatch)
    client = ThreadedWebexClient("test-token", Config())
    client.set_custom_websocket_url("ws://127.0.0.1:12345/mercury/device")

    client.connect()
    client.connect()
    fake = FakeWebexClient.instances[0]
    assert fake.conversation.connect_calls == 1
    assert fake.mercury.custom_websocket_url == "ws://127.0.0.1:12345/mercury/device"

    with pytest.raises(RuntimeError, match="before connect"):
        client.set_custom_websocket_url("ws://127.0.0.1:54321/mercury/device")

    client.close()
    client.close()
    assert fake.close_calls == 1


def test_threaded_client_propagates_background_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify sync calls raise exceptions from the async client.

    :returns: None.
    """
    install_fake_webex_client(monkeypatch)
    client = ThreadedWebexClient("test-token", Config())
    try:
        client.connect()
        with pytest.raises(ValueError, match="fake get_key failure"):
            client.get_key("kms://test/keys/error")
    finally:
        client.close()


def test_threaded_client_rejects_blocking_call_from_background_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the sync facade refuses to deadlock its own event loop thread.

    :returns: None.
    """
    install_fake_webex_client(monkeypatch)
    client = ThreadedWebexClient("test-token", Config())
    try:
        client.connect()

        async def call_from_loop() -> str:
            """Call a blocking method from the background loop and return the error.

            :returns: Runtime error message.
            """
            try:
                client.get_key("kms://test/keys/1")
            except RuntimeError as err:
                return str(err)
            return ""

        assert "background loop" in client._run(call_from_loop())
    finally:
        client.close()


@pytest.mark.asyncio
@respx.mock
async def test_threaded_client_get_key_completes_from_mercury_response() -> None:
    """Verify blocking get_key completes from a Mercury-delivered KMS response.

    :returns: None.
    """
    responses: asyncio.Queue[str] = asyncio.Queue()

    async def handler(websocket: Any, *_args: object) -> None:
        """Serve a minimal Mercury-compatible websocket exchange.

        :param websocket: Server-side websocket connection.
        :param *_args: Additional positional arguments supplied by websockets.
        :returns: None.
        """
        await websocket.recv()
        await websocket.send(json.dumps({"data": {"eventType": "mercury.buffer_state"}}))
        await websocket.recv()
        response = await responses.get()
        await websocket.send(
            json.dumps(
                {
                    "id": "kms-event-1",
                    "data": {
                        "eventType": "encryption.kms_message",
                        "encryption": {"kmsMessages": [response]},
                    },
                }
            )
        )
        await websocket.wait_closed()

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        config = Config(kms_response_timeout=2.0, mercury_ping_interval=3600.0)
        client = ThreadedWebexClient("test-token", config)
        client.set_custom_websocket_url(f"ws://127.0.0.1:{port}/mercury/device")

        respx.post(re.compile(r"https://wdm-a\.wbx2\.com/wdm/api/v1/devices.*")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/device-123",
                    "webSocketUrl": f"ws://127.0.0.1:{port}/mercury/device",
                    "userId": "user-123",
                    "deviceType": "TEAMS_SDK_JS",
                },
            )
        )
        respx.post(re.compile(r"https://encryption-a\.wbx2\.com/encryption/api/v1/kms/messages")).mock(
            return_value=httpx.Response(202)
        )

        try:
            await asyncio.to_thread(client.connect)
            shared_secret = os.urandom(32)

            async def seed_ecdh_context() -> None:
                """Seed an established ECDH context in the background client.

                :returns: None.
                """
                assert client._client is not None
                client._client.encryption._ecdh_context = ECDHContext(
                    local_private_key=ec.generate_private_key(ec.SECP256R1()),
                    shared_secret=shared_secret,
                    ecdh_key_uri="kms://test/ecdhe/1",
                    kms_cluster="kms-a.wbx2.com",
                    created_at=time.time(),
                )

            await asyncio.to_thread(client._run, seed_ecdh_context())
            key_task = asyncio.create_task(asyncio.to_thread(client.get_key, "kms://ciscospark.com/keys/threaded"))

            request_id = ""
            for _ in range(100):

                async def pending_request_ids() -> list[str]:
                    """Return pending KMS request IDs from the background client.

                    :returns: Pending request ID list.
                    """
                    assert client._client is not None
                    return list(client._client.encryption._pending_requests)

                pending = await asyncio.to_thread(client._run, pending_request_ids())
                if pending:
                    request_id = pending[0]
                    break
                await asyncio.sleep(0.01)

            assert request_id
            key = {
                "uri": "kms://ciscospark.com/keys/threaded",
                "jwk": {"kty": "oct", "k": b64url(os.urandom(32)), "kid": "threaded"},
            }
            wrapped = wrap_with_shared_secret(
                json.dumps({"status": 200, "requestId": request_id, "key": key}).encode(),
                shared_secret,
            )
            await responses.put(wrapped)

            result = await asyncio.wait_for(key_task, timeout=3.0)
            assert result.uri == "kms://ciscospark.com/keys/threaded"
            assert result.jwk.kid == "threaded"
        finally:
            await asyncio.to_thread(client.close)


class TestGetKey(TestCase):
    def test_get_key(self) -> None:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s", force=True)
        load_dotenv(Path(__file__).parent.parent / ".env")
        kms_uri = "kms://kms-aore.wbx2.com/keys/c6a14801-8188-431e-af37-0ba0183c59d5"
        with ThreadedWebexClient(os.getenv("WEBEX_ACCESS_TOKEN")) as client:
            logging.info(f"get key KMS URI: {kms_uri}")
            key = client.get_key(kms_uri)
            logging.info(f"got key KMS URI: {kms_uri}m {key=}")
            print(f"{key=}")

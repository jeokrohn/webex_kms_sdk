from __future__ import annotations

import asyncio
import json
import re

import httpx
import pytest
import respx
import websockets

from webex_kms_sdk import Config, DeviceClient, MercuryClient, WebexClient
from webex_kms_sdk.core import CoreHTTPClient


def test_config_defaults() -> None:
    """Verify the default SDK configuration values used by clients.

    :returns: None.
    """
    # Arrange a default configuration object.
    config = Config()

    # Assert representative defaults across HTTP, Mercury, and KMS settings.
    assert config.base_url == "https://webexapis.com/v1"
    assert config.mercury_ping_interval == 30.0
    assert config.mercury_initial_connection_max_retries == 5
    assert config.kms_default_cluster == "a"


@pytest.mark.asyncio
@respx.mock
async def test_device_register_is_idempotent() -> None:
    """Verify repeated device registration reuses the first WDM response.

    :returns: None.
    """
    # Arrange a mocked WDM registration response.
    client = WebexClient("test-token")
    route = respx.post(re.compile(r"https://wdm-a\.wbx2\.com/wdm/api/v1/devices.*")).mock(
        return_value=httpx.Response(
            200,
            json={
                "url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/device-123",
                "webSocketUrl": "wss://mercury.example.test/device-123",
                "userId": "user-123",
                "deviceType": "TEAMS_SDK_JS",
            },
        )
    )

    # Act by registering twice through the same device client.
    await client.device.register()
    await client.device.register()

    # Assert only one network call happened and accessors return normalized values.
    assert route.call_count == 1
    assert await client.device.get_websocket_url() == "wss://mercury.example.test/device-123"
    assert await client.device.get_device_url() == "https://wdm-a.wbx2.com/wdm/api/v1/devices/device-123"
    assert await client.device.get_user_id() == "user-123"
    await client.aclose()


def test_mercury_prepare_websocket_url() -> None:
    """Verify Mercury URL preparation preserves and adds query parameters.

    :returns: None.
    """
    # Arrange a Mercury client and a URL with an existing query parameter.
    core = CoreHTTPClient("test-token", Config())
    mercury = MercuryClient(core, Config())

    # Act by preparing the URL for Mercury connection.
    prepared = mercury.prepare_websocket_url("wss://example.test/mercury/device?existing=1")

    # Assert existing and SDK-required query parameters are present.
    assert prepared.startswith("wss://example.test/mercury/device?")
    assert "existing=1" in prepared
    assert "outboundWireFormat=text" in prepared
    assert "bufferStates=true" in prepared
    assert "aliasHttpStatus=true" in prepared


def test_mercury_handler_registry() -> None:
    """Verify Mercury handler registration and removal.

    :returns: None.
    """
    # Arrange an empty handler registry.
    core = CoreHTTPClient("test-token", Config())
    mercury = MercuryClient(core, Config())

    def handler(_event) -> None:
        """No-op Mercury event handler used for registry assertions.

        :param _event: Ignored Mercury event argument.
        :returns: None.
        """
        return None

    # Act and assert handler add/remove behavior by identity.
    mercury.on("conversation.activity", handler)
    assert len(mercury.event_handlers()["conversation.activity"]) == 1
    mercury.off("conversation.activity", handler)
    assert mercury.event_handlers().get("conversation.activity") is None


@pytest.mark.asyncio
async def test_mercury_connect_authorizes_and_dispatches_event() -> None:
    """Verify Mercury connects, authorizes, pings, and dispatches an event.

    :returns: None.
    """
    # Arrange a local websocket server that behaves like Mercury.
    received_frames: list[dict] = []

    async def handler(websocket, *_args):
        """Serve one Mercury-like authorization and event exchange.

        :param websocket: Server-side websocket connection.
        :param *_args: Additional positional arguments supplied by websockets.
        :returns: None.
        """
        # Receive authorization, confirm registration, then receive the initial ping.
        auth = json.loads(await websocket.recv())
        received_frames.append(auth)
        await websocket.send(json.dumps({"data": {"eventType": "mercury.buffer_state"}}))
        ping = json.loads(await websocket.recv())
        received_frames.append(ping)
        # Send a conversation activity event for client dispatch.
        await websocket.send(
            json.dumps(
                {
                    "id": "evt-1",
                    "data": {
                        "eventType": "conversation.activity",
                        "activity": {
                            "verb": "post",
                            "actor": {"id": "actor-1", "orgId": "org-1"},
                            "object": {"objectType": "activity", "displayName": "hello"},
                        },
                    },
                    "sequenceNumber": 1,
                }
            )
        )
        await asyncio.sleep(0.1)

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        # Arrange a client pointed at the local Mercury-compatible server.
        port = server.sockets[0].getsockname()[1]
        config = Config(mercury_ping_interval=3600.0)
        client = WebexClient("test-token", config)
        client.mercury.set_custom_websocket_url(f"ws://127.0.0.1:{port}/mercury/device")
        event_seen = asyncio.get_running_loop().create_future()

        async def on_activity(event) -> None:
            """Capture the first dispatched conversation activity event.

            :param event: Mercury event delivered by the client dispatcher.
            :returns: None.
            """
            if not event_seen.done():
                event_seen.set_result(event)

        # Act by connecting and waiting for the dispatched event.
        client.mercury.on("conversation.activity", on_activity)
        await client.mercury.connect()
        event = await asyncio.wait_for(event_seen, timeout=2.0)

        # Assert authorization, ping, and event normalization behavior.
        assert received_frames[0]["type"] == "authorization"
        assert received_frames[0]["data"]["token"] == "test-token"
        assert received_frames[1]["type"] == "ping"
        assert event.event_type == "conversation.activity"
        assert event.activity_type == "post"
        await client.aclose()


@pytest.mark.asyncio
async def test_device_client_registration_callback() -> None:
    """Verify registration callbacks run immediately after registration is true.

    :returns: None.
    """
    # Arrange a device client and callback event.
    core = CoreHTTPClient("test-token", Config())
    device = DeviceClient(core, Config())
    called = asyncio.Event()

    # Act by registering callbacks before and after the registered flag is set.
    device.on_registered(called.set)
    device._registered = True
    device.on_registered(called.set)

    # Assert the immediate callback path signaled the event.
    await asyncio.wait_for(called.wait(), timeout=1.0)
    await core.aclose()

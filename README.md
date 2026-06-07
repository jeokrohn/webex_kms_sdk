# Webex KMS SDK

Async Python SDK slice for Webex Mercury communication and KMS-backed message decryption.

Based on https://github.com/WebexCommunity/webex-go-sdk, this package provides a focused implementation of the Webex Mercury protocol and KMS interactions needed for E2EE message decryption and conversation activity handling. It is designed to be used in conjunction with other Webex SDK components or as a standalone library for applications that need to interact with Webex conversations and messages.

This package intentionally covers a narrow part of the Webex Go SDK behavior:

- WDM device registration needed for Mercury
- Mercury WebSocket connection and event dispatch
- KMS ECDH setup, key retrieval, async Mercury response correlation, and key caching
- JWE text decryption and lightweight conversation activity helpers

It does not implement the full Webex REST API, WebRTC calling, outbound E2EE message encryption,
or KMS administration.

## Install

```bash
uv sync
```

## Quick Example

```python
import asyncio
import os

from webex_kms_sdk import WebexClient


async def main() -> None:
    client = WebexClient(os.environ["WEBEX_ACCESS_TOKEN"])
    conversation = client.conversation

    async def on_post(activity):
        content = await conversation.get_message_content(activity)
        print(content)

    conversation.on("post", on_post)
    await conversation.connect()

    try:
        await asyncio.Event().wait()
    finally:
        await conversation.disconnect()
        await client.aclose()


asyncio.run(main())
```

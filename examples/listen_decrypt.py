from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

from dotenv import load_dotenv

from webex_kms_sdk import Activity, WebexClient

log = logging.getLogger(__name__)


async def main() -> None:
    """Connect to Mercury and print decrypted post/share activity content.

    Returns:
        None.
    """
    # Load .env from the project root so local examples can run without shell exports.
    log.debug("main: load environment configuration")
    load_dotenv(Path(__file__).parent.parent.joinpath(".env"))
    token = os.environ.get("WEBEX_ACCESS_TOKEN")
    if not token:
        raise SystemExit("WEBEX_ACCESS_TOKEN environment variable is required")

    # Build the high-level conversation client and a shutdown event.
    log.debug("main: initialize Webex conversation client")
    client = WebexClient(token)
    conversation = client.conversation
    stop_event = asyncio.Event()

    async def on_message(activity: Activity) -> None:
        """Print one decrypted conversation message activity.

        Args:
            activity: Activity received from the conversation client.

        Returns:
            None.
        """
        log.debug("main.on_message: decrypt and print activity activity_id=%s", activity.id)
        actor = activity.actor.get("displayName") or activity.actor.get("id") or "unknown"
        content = await conversation.get_message_content(activity)
        print(f"{actor}: {content}")

    # Register the same printer for message-like conversation verbs.
    log.debug("main: register message handlers")
    conversation.on("post", on_message)
    conversation.on("share", on_message)

    # Stop cleanly when the process receives a normal termination signal.
    log.debug("main: register signal handlers")
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    # Connect, wait until signaled, and always release websocket/HTTP resources.
    log.debug("main: connect and wait for stop signal")
    await conversation.connect()
    print("Connected to Mercury. Listening for decrypted post/share activities.")
    try:
        await stop_event.wait()
    finally:
        log.debug("main: disconnect and close client")
        await conversation.disconnect()
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

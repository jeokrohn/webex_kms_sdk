from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from webex_kms_sdk import ThreadedWebexClient

log = logging.getLogger(__name__)


def main() -> None:
    """Retrieve one KMS key from synchronous code.

    :returns: None.
    """
    # Load .env from the project root so local examples can run without shell exports.
    log.debug("main: load environment configuration")
    load_dotenv(Path(__file__).parent.parent.joinpath(".env"))
    token = os.environ.get("WEBEX_ACCESS_TOKEN")
    key_uri = os.environ.get("KMS_KEY_URI")
    if not token:
        raise SystemExit("WEBEX_ACCESS_TOKEN environment variable is required")
    if not key_uri:
        raise SystemExit("KMS_KEY_URI environment variable is required")

    # The threaded client owns the Mercury websocket and async event loop in the background.
    log.debug("main: initialize threaded Webex client")
    with ThreadedWebexClient(token) as client:
        key = client.get_key(key_uri)

    print(f"Retrieved key: uri={key.uri} kid={key.jwk.kid or '<none>'} kty={key.jwk.kty}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()

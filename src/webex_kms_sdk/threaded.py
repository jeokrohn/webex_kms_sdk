from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from .config import Config
from .core import WebexClient
from .models import Key

log = logging.getLogger(__name__)

T = TypeVar("T")


class ThreadedWebexClient:
    """Synchronous facade that runs the async Webex client on a background loop."""

    def __init__(self, access_token: str, config: Config | None = None) -> None:
        """Create a thread-backed Webex client facade.

        :param access_token: Webex bearer token used by the async client.
        :param config: Optional runtime configuration. Defaults are used when omitted.
        :returns: None.
        """
        if not access_token:
            raise ValueError("access token cannot be empty")
        log.debug("ThreadedWebexClient.__init__: initialize threaded client facade")
        self._access_token = access_token
        self._config = config
        self._custom_websocket_url = ""
        self._lock = threading.RLock()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread_id: int | None = None
        self._client: WebexClient | None = None
        self._startup_error: BaseException | None = None
        self._connected = False
        self._closed = False

    def __enter__(self) -> ThreadedWebexClient:
        """Start the background client and return this sync facade.

        :returns: Started ``ThreadedWebexClient``.
        """
        log.debug("ThreadedWebexClient.__enter__: connect threaded client")
        self.connect()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        """Close background resources when leaving a context manager.

        :returns: None.
        """
        log.debug("ThreadedWebexClient.__exit__: close threaded client")
        self.close()

    def set_custom_websocket_url(self, url: str) -> None:
        """Set a custom Mercury websocket URL before the background client starts.

        :param url: Mercury websocket URL to use for future connections.
        :returns: None.
        """
        log.debug("ThreadedWebexClient.set_custom_websocket_url: set custom websocket url=%s", url)
        with self._lock:
            if self._thread is not None or self._connected:
                raise RuntimeError("custom websocket URL must be set before connect")
            if self._closed:
                raise RuntimeError("threaded client is closed")
            self._custom_websocket_url = url

    def connect(self) -> None:
        """Start the background loop and connect Mercury.

        :returns: None.
        """
        log.debug("ThreadedWebexClient.connect: connect threaded client")
        with self._lock:
            if self._closed:
                raise RuntimeError("threaded client is closed")
            if self._connected:
                log.debug("ThreadedWebexClient.connect: already connected")
                return
            self._ensure_thread_started()

        try:
            self._run(self._connect_async())
        except Exception:
            log.debug("ThreadedWebexClient.connect: connect failed; close background client")
            self.close()
            raise

        with self._lock:
            self._connected = True

    def close(self) -> None:
        """Close the async client, stop the background loop, and join the thread.

        :returns: None.
        """
        log.debug("ThreadedWebexClient.close: close threaded client")
        with self._lock:
            if self._closed:
                log.debug("ThreadedWebexClient.close: already closed")
                return
            self._closed = True
            loop = self._loop
            thread = self._thread
            loop_thread_id = self._loop_thread_id

        if loop is not None and thread is not None and thread.is_alive():
            if threading.get_ident() == loop_thread_id:
                raise RuntimeError("cannot close threaded client from its background loop")
            shutdown_error: BaseException | None = None
            try:
                future = asyncio.run_coroutine_threadsafe(self._shutdown_async(), loop)
                future.result()
            except BaseException as err:
                shutdown_error = err
                log.debug(
                    "ThreadedWebexClient.close: async shutdown failed",
                    exc_info=True,
                )
            finally:
                loop.call_soon_threadsafe(loop.stop)
                thread.join()
            if shutdown_error is not None:
                raise shutdown_error

        with self._lock:
            self._connected = False
            self._client = None
            self._loop = None
            self._loop_thread_id = None
            self._thread = None

    def get_key(self, key_uri: str) -> Key:
        """Retrieve a KMS key from synchronous code.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        log.debug("ThreadedWebexClient.get_key: retrieve key key_uri=%s", key_uri)
        return self._run(self._get_key_async(key_uri))

    def decrypt_text(self, key_uri: str, ciphertext: str) -> str:
        """Decrypt text from synchronous code.

        :param key_uri: KMS URI for the symmetric key.
        :param ciphertext: Compact JWE ciphertext.
        :returns: Decrypted UTF-8 plaintext.
        """
        log.debug(
            "ThreadedWebexClient.decrypt_text: decrypt text key_uri=%s ciphertext_length=%s",
            key_uri,
            len(ciphertext),
        )
        return self._run(self._decrypt_text_async(key_uri, ciphertext))

    def _ensure_thread_started(self) -> None:
        """Start the event loop thread and wait for async client construction.

        :returns: None.
        """
        if self._thread is not None:
            return
        log.debug("ThreadedWebexClient._ensure_thread_started: start background thread")
        self._ready = threading.Event()
        self._startup_error = None
        thread = threading.Thread(
            target=self._thread_main,
            name="webex-kms-sdk-threaded-client",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        self._ready.wait()
        if self._startup_error is not None:
            thread.join()
            self._thread = None
            self._loop = None
            self._loop_thread_id = None
            self._client = None
            raise self._startup_error

    def _thread_main(self) -> None:
        """Run the async client event loop until shutdown.

        :returns: None.
        """
        log.debug("ThreadedWebexClient._thread_main: start event loop thread")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._loop_thread_id = threading.get_ident()
        try:
            self._client = WebexClient(self._access_token, self._config)
            if self._custom_websocket_url:
                self._client.mercury.set_custom_websocket_url(self._custom_websocket_url)
        except BaseException as err:
            self._startup_error = err
            self._ready.set()
            loop.close()
            asyncio.set_event_loop(None)
            return

        self._ready.set()
        try:
            loop.run_forever()
        finally:
            log.debug("ThreadedWebexClient._thread_main: stop event loop thread")
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()
            asyncio.set_event_loop(None)

    def _run(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run a coroutine on the background loop and block for its result.

        :param coro: Coroutine to schedule on the background loop.
        :returns: Coroutine result.
        """
        with self._lock:
            loop = self._loop
            thread = self._thread
            closed = self._closed
            loop_thread_id = self._loop_thread_id
        if loop is None or thread is None or not thread.is_alive():
            coro.close()
            if closed:
                raise RuntimeError("threaded client is closed")
            raise RuntimeError("threaded client is not connected")
        if threading.get_ident() == loop_thread_id:
            coro.close()
            raise RuntimeError("cannot block on the threaded client from its background loop")
        log.debug("ThreadedWebexClient._run: submit coroutine to background loop")
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result()

    async def _connect_async(self) -> None:
        """Connect the underlying async conversation client.

        :returns: None.
        """
        log.debug("ThreadedWebexClient._connect_async: connect async conversation client")
        client = self._require_client()
        await client.conversation.connect()

    async def _shutdown_async(self) -> None:
        """Close the underlying async client.

        :returns: None.
        """
        log.debug("ThreadedWebexClient._shutdown_async: close async client")
        if self._client is not None:
            await self._client.aclose()

    async def _get_key_async(self, key_uri: str) -> Key:
        """Retrieve a KMS key on the background loop.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        client = self._require_client()
        return await client.encryption.get_key(key_uri)

    async def _decrypt_text_async(self, key_uri: str, ciphertext: str) -> str:
        """Decrypt text on the background loop.

        :param key_uri: KMS URI for the symmetric key.
        :param ciphertext: Compact JWE ciphertext.
        :returns: Decrypted UTF-8 plaintext.
        """
        client = self._require_client()
        return await client.encryption.decrypt_text(key_uri, ciphertext)

    def _require_client(self) -> WebexClient:
        """Return the loop-owned async client or raise when startup failed.

        :returns: Underlying async ``WebexClient``.
        """
        if self._client is None:
            raise RuntimeError("async client is not initialized")
        return self._client

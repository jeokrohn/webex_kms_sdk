from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

import httpx

from .config import Config
from .errors import api_error_from_response

RETRYABLE_STATUSES = {423, 429, 502, 503, 504}
SENSITIVE_LOG_KEYS = {"authorization", "bearer", "token", "access_token", "secret", "k", "d"}
MAX_LOG_VALUE_LENGTH = 2000

log = logging.getLogger(__name__)


class CoreHTTPClient:
    def __init__(self, access_token: str, config: Config) -> None:
        """Create the shared HTTP client used by SDK feature clients.

        :param access_token: Webex bearer token used for authenticated requests.
        :param config: Runtime configuration for endpoints, retries, and headers.
        :returns: None.
        """
        if not access_token:
            raise ValueError("access token cannot be empty")
        log.debug("CoreHTTPClient.__init__: initialize HTTP client")
        self.access_token = access_token
        self.config = config
        self.http = httpx.AsyncClient(timeout=config.timeout)

    async def aclose(self) -> None:
        """Close the underlying asynchronous HTTP session.

        :returns: None.
        """
        log.debug("CoreHTTPClient.aclose: close HTTP session")
        await self.http.aclose()

    def auth_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build authenticated headers for a Webex HTTP request.

        :param extra: Optional request-specific headers that override defaults.
        :returns: Header dictionary including the bearer token and configured defaults.
        """
        # Start with SDK-wide authentication and content defaults.
        log.debug(
            "CoreHTTPClient.auth_headers: build authenticated headers extra=%s",
            _redact_for_log(extra or {}),
        )
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            **self.config.default_headers,
        }
        # Let callers override or extend headers for individual requests.
        if extra:
            headers.update(extra)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send an HTTP request to a path relative to the configured base URL.

        :param method: HTTP method such as ``GET`` or ``POST``.
        :param path: Relative API path to append to ``Config.base_url``.
        :param params: Optional query parameters.
        :param json: Optional JSON-serializable request body.
        :param headers: Optional request-specific headers.
        :returns: Raw ``httpx.Response`` returned by the API.
        """
        url = f"{self.config.base_url.rstrip('/')}/{path.lstrip('/')}"
        log.debug(
            "CoreHTTPClient.request: resolve API path method=%s path=%s url=%s",
            method,
            path,
            url,
        )
        return await self.request_url(method, url, params=params, json=json, headers=headers)

    async def request_url(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send an HTTP request to an absolute URL with retry handling.

        :param method: HTTP method such as ``GET`` or ``POST``.
        :param url: Absolute URL to request.
        :param params: Optional query parameters.
        :param json: Optional JSON-serializable request body.
        :param headers: Optional request-specific headers.
        :returns: Final ``httpx.Response`` after retry attempts are exhausted or skipped.
        """
        delay = self.config.retry_base_delay or 1.0
        for attempt in range(self.config.max_retries + 1):
            # Issue the request with merged authentication headers.
            request_headers = self.auth_headers(headers)
            log.debug(
                "CoreHTTPClient.request_url: send API request method=%s url=%s attempt=%s params=%s json=%s headers=%s",
                method,
                url,
                attempt + 1,
                _redact_for_log(params or {}),
                _redact_for_log(json),
                _redact_for_log(request_headers),
            )
            response = await self.http.request(
                method,
                url,
                params=params,
                json=json,
                headers=request_headers,
            )
            log.debug(
                "CoreHTTPClient.request_url: receive API response method=%s url=%s attempt=%s status=%s response=%s",
                method,
                url,
                attempt + 1,
                response.status_code,
                _response_preview(response),
            )
            # Return immediately for non-retryable statuses or the final attempt.
            if response.status_code not in RETRYABLE_STATUSES or attempt == self.config.max_retries:
                return response

            # Respect server-directed backoff where available before retrying.
            sleep_for = _retry_delay(response, delay, attempt)
            log.debug(
                "CoreHTTPClient.request_url: retry API request method=%s url=%s attempt=%s delay=%s status=%s",
                method,
                url,
                attempt + 1,
                sleep_for,
                response.status_code,
            )
            await response.aclose()
            await asyncio.sleep(sleep_for)

        return response

    async def parse_json(self, response: httpx.Response) -> Any:
        """Parse a successful JSON response or raise a typed API error.

        :param response: Raw HTTP response to inspect and decode.
        :returns: JSON-decoded response payload.
        """
        if response.status_code >= 400:
            log.debug(
                "CoreHTTPClient.parse_json: API error response status=%s response=%s",
                response.status_code,
                _response_preview(response),
            )
            raise api_error_from_response(response)
        parsed = response.json()
        log.debug(
            "CoreHTTPClient.parse_json: parse API response status=%s json=%s",
            response.status_code,
            _redact_for_log(parsed),
        )
        return parsed


def _retry_delay(response: httpx.Response, base_delay: float, attempt: int) -> float:
    """Calculate the sleep interval before retrying a failed request.

    :param response: Response whose status and headers may influence retry timing.
    :param base_delay: Base retry delay in seconds.
    :param attempt: Zero-based retry attempt number.
    :returns: Delay in seconds before the next attempt.
    """
    # Honor Retry-After for statuses where Webex can explicitly throttle callers.
    if response.status_code in {423, 429}:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                seconds = float(retry_after)
            except ValueError:
                seconds = 0.0
            if seconds > 0:
                log.debug(
                    "_retry_delay: use Retry-After header status=%s delay=%s attempt=%s",
                    response.status_code,
                    seconds,
                    attempt + 1,
                )
                return seconds
    delay = base_delay * (2**attempt)
    log.debug(
        "_retry_delay: use exponential backoff status=%s delay=%s attempt=%s",
        response.status_code,
        delay,
        attempt + 1,
    )
    return delay


def _redact_for_log(value: Any) -> Any:
    """Return a redacted, compact representation suitable for debug logs.

    :param value: Arbitrary value to summarize.
    :returns: Redacted value with sensitive fields replaced.
    """
    if isinstance(value, Mapping):
        return {
            str(key): "<redacted>" if str(key).lower() in SENSITIVE_LOG_KEYS else _redact_for_log(val)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_redact_for_log(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_for_log(item) for item in value)
    if isinstance(value, bytes | bytearray):
        return f"<{len(value)} bytes>"
    if isinstance(value, str) and len(value) > MAX_LOG_VALUE_LENGTH:
        return f"{value[:MAX_LOG_VALUE_LENGTH]}...<truncated {len(value)} chars>"
    return value


def _response_preview(response: httpx.Response) -> str:
    """Return a bounded response body preview for debug logs.

    :param response: HTTP response whose content should be summarized.
    :returns: Human-readable response body preview.
    """
    try:
        body = response.text
    except UnicodeDecodeError:
        return f"<{len(response.content)} binary bytes>"
    redacted = str(_redact_for_log(body))
    if len(redacted) > MAX_LOG_VALUE_LENGTH:
        return f"{redacted[:MAX_LOG_VALUE_LENGTH]}...<truncated {len(redacted)} chars>"
    return redacted


class WebexClient:
    """Top-level async client for the Mercury/KMS SDK slice."""

    def __init__(self, access_token: str, config: Config | None = None) -> None:
        """Create a top-level SDK client with lazily initialized sub-clients.

        :param access_token: Webex bearer token used by all sub-clients.
        :param config: Optional runtime configuration. Defaults are used when omitted.
        :returns: None.
        """
        log.debug("WebexClient.__init__: initialize top-level client")
        self.config = config or Config()
        self.core = CoreHTTPClient(access_token, self.config)
        self._device = None
        self._mercury = None
        self._encryption = None
        self._conversation = None

    async def aclose(self) -> None:
        """Close open Mercury and HTTP resources owned by the client.

        :returns: None.
        """
        # Stop the websocket client before closing the shared HTTP session.
        log.debug("WebexClient.aclose: close client resources")
        if self._mercury is not None:
            await self._mercury.disconnect()
        await self.core.aclose()

    @property
    def device(self):
        """Return the lazily created device registration client.

        :returns: Device client bound to this top-level client's core HTTP client.
        """
        from .device import DeviceClient

        if self._device is None:
            log.debug("WebexClient.device: create device client")
            self._device = DeviceClient(self.core, self.config)
        return self._device

    @property
    def mercury(self):
        """Return the lazily created Mercury websocket client.

        :returns: Mercury client configured with this client's device provider.
        """
        from .mercury import MercuryClient

        if self._mercury is None:
            log.debug("WebexClient.mercury: create Mercury client")
            self._mercury = MercuryClient(self.core, self.config)
            self._mercury.set_device_provider(self.device)
        return self._mercury

    @property
    def encryption(self):
        """Return the lazily created KMS encryption client.

        :returns: Encryption client bound to this top-level client's core HTTP client.
        """
        from .encryption import EncryptionClient

        if self._encryption is None:
            log.debug("WebexClient.encryption: create encryption client")
            self._encryption = EncryptionClient(self.core, self.config)
        return self._encryption

    @property
    def conversation(self):
        """Return the lazily created high-level conversation client.

        :returns: Conversation client wired to Mercury and KMS decryption.
        """
        from .conversation import ConversationClient

        if self._conversation is None:
            log.debug("WebexClient.conversation: create conversation client")
            self._conversation = ConversationClient(self.core, self.config, self.mercury, self.encryption)
        return self._conversation

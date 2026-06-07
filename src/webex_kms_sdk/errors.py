from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TypedDict

import httpx

MAX_LOG_BODY_LENGTH = 2000

log = logging.getLogger(__name__)


class _APIErrorKwargs(TypedDict):
    """Keyword arguments shared by all API error subclasses."""

    status_code: int
    status: str
    message: str
    tracking_id: str
    retry_after: float | None
    raw_body: bytes


@dataclass(slots=True)
class APIError(Exception):
    """Base exception carrying structured Webex API error details."""

    status_code: int
    status: str
    message: str = ""
    tracking_id: str = ""
    retry_after: float | None = None
    raw_body: bytes = b""

    def __str__(self) -> str:
        """Render the API error as a concise human-readable message.

        :returns: Message containing status, optional API message, and tracking ID.
        """
        log.debug(
            "APIError.__str__: render API error status_code=%s tracking_id=%s",
            self.status_code,
            self.tracking_id,
        )
        msg = f"API error: {self.status_code}"
        if self.message:
            msg += f" - {self.message}"
        if self.tracking_id:
            msg += f" (trackingId: {self.tracking_id})"
        return msg


class RateLimitError(APIError):
    """API error raised for HTTP 429 responses."""

    pass


class AuthError(APIError):
    """API error raised for HTTP 401 responses."""

    pass


class ForbiddenError(APIError):
    """API error raised for HTTP 403 responses."""

    pass


class NotFoundError(APIError):
    """API error raised for HTTP 404 responses."""

    pass


class ConflictError(APIError):
    """API error raised for HTTP 409 responses."""

    pass


class GoneError(APIError):
    """API error raised for HTTP 410 responses."""

    pass


class LockedError(APIError):
    """API error raised for HTTP 423 responses."""

    pass


class PreconditionRequiredError(APIError):
    """API error raised for HTTP 428 responses."""

    pass


class ServerError(APIError):
    """API error raised for retryable HTTP 5xx responses."""

    pass


class KMSProtocolError(RuntimeError):
    """Error raised when a KMS response cannot satisfy the SDK protocol."""

    pass


def api_error_from_response(response: httpx.Response) -> APIError:
    """Build the most specific API error for an HTTP response.

    :param response: Error HTTP response returned by Webex.
    :returns: Typed ``APIError`` subclass matching the response status code.
    """
    # Extract structured error details from JSON payloads when available.
    log.debug(
        "api_error_from_response: parse API error response status=%s response=%s",
        response.status_code,
        _response_preview(response),
    )
    message = ""
    tracking_id = ""
    try:
        parsed = response.json()
    except ValueError:
        parsed = {}
    if isinstance(parsed, dict):
        message = str(parsed.get("message") or "")
        tracking_id = str(parsed.get("trackingId") or "")

    # Preserve retry timing metadata for callers that want adaptive backoff.
    retry_after = None
    retry_after_raw = response.headers.get("Retry-After")
    if retry_after_raw:
        try:
            retry_after = float(retry_after_raw)
        except ValueError:
            retry_after = None

    # Normalize common fields before selecting the most specific exception class.
    kwargs: _APIErrorKwargs = {
        "status_code": response.status_code,
        "status": f"{response.status_code} {response.reason_phrase}",
        "message": message,
        "tracking_id": tracking_id,
        "retry_after": retry_after,
        "raw_body": response.content,
    }
    log.debug(
        "api_error_from_response: map API error status=%s message=%s tracking_id=%s retry_after=%s",
        response.status_code,
        message,
        tracking_id,
        retry_after,
    )
    match response.status_code:
        case 401:
            return AuthError(**kwargs)
        case 403:
            return ForbiddenError(**kwargs)
        case 404:
            return NotFoundError(**kwargs)
        case 409:
            return ConflictError(**kwargs)
        case 410:
            return GoneError(**kwargs)
        case 423:
            return LockedError(**kwargs)
        case 428:
            return PreconditionRequiredError(**kwargs)
        case 429:
            return RateLimitError(**kwargs)
        case 500 | 502 | 503 | 504:
            return ServerError(**kwargs)
        case _:
            return APIError(**kwargs)


def is_rate_limited(err: BaseException) -> bool:
    """Return whether an exception represents API rate limiting.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``RateLimitError``.
    """
    result = isinstance(err, RateLimitError)
    log.debug("is_rate_limited: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_not_found(err: BaseException) -> bool:
    """Return whether an exception represents a missing API resource.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``NotFoundError``.
    """
    result = isinstance(err, NotFoundError)
    log.debug("is_not_found: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_auth_error(err: BaseException) -> bool:
    """Return whether an exception represents an authentication failure.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is an ``AuthError``.
    """
    result = isinstance(err, AuthError)
    log.debug("is_auth_error: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_forbidden(err: BaseException) -> bool:
    """Return whether an exception represents an authorization failure.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``ForbiddenError``.
    """
    result = isinstance(err, ForbiddenError)
    log.debug("is_forbidden: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_conflict(err: BaseException) -> bool:
    """Return whether an exception represents an API conflict.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``ConflictError``.
    """
    result = isinstance(err, ConflictError)
    log.debug("is_conflict: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_gone(err: BaseException) -> bool:
    """Return whether an exception represents a gone API resource.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``GoneError``.
    """
    result = isinstance(err, GoneError)
    log.debug("is_gone: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_locked(err: BaseException) -> bool:
    """Return whether an exception represents a locked API resource.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``LockedError``.
    """
    result = isinstance(err, LockedError)
    log.debug("is_locked: classify error type=%s result=%s", type(err).__name__, result)
    return result


def is_precondition_required(err: BaseException) -> bool:
    """Return whether an exception requires request preconditions.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``PreconditionRequiredError``.
    """
    result = isinstance(err, PreconditionRequiredError)
    log.debug(
        "is_precondition_required: classify error type=%s result=%s",
        type(err).__name__,
        result,
    )
    return result


def is_server_error(err: BaseException) -> bool:
    """Return whether an exception represents a retryable server failure.

    :param err: Exception instance to inspect.
    :returns: ``True`` when ``err`` is a ``ServerError``.
    """
    result = isinstance(err, ServerError)
    log.debug("is_server_error: classify error type=%s result=%s", type(err).__name__, result)
    return result


def _response_preview(response: httpx.Response) -> str:
    """Return a bounded API response body preview for debug logging.

    :param response: HTTP response whose body should be summarized.
    :returns: Text preview of the response body.
    """
    try:
        body = response.text
    except UnicodeDecodeError:
        return f"<{len(response.content)} binary bytes>"
    if len(body) > MAX_LOG_BODY_LENGTH:
        return f"{body[:MAX_LOG_BODY_LENGTH]}...<truncated {len(body)} chars>"
    return body

"""HTTP utilities with retry support."""

from __future__ import annotations

import dataclasses
import datetime as dt
import time
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tenacity import (
    RetryCallState,
    Retrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from aia_chaser.exceptions import InvalidUrlError
from aia_chaser.utils.url import extract_scheme_host_port_from_url


if TYPE_CHECKING:
    from collections.abc import Callable
    from http.client import HTTPResponse
    from typing import Final
    from urllib.request import OpenerDirector

# HTTP status codes of transient errors worth retrying
RETRYABLE_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
    },
)


@dataclasses.dataclass(frozen=True)
class RetryConfig:
    """Configuration for HTTP retry behavior.

    Attributes:
        max_attempts: Maximum number of total attempts. Set to <= 1 for
            no retries. Defaults to 3.
        wait_multiplier: Multiplier for exponential backoff in seconds.
            Defaults to 0.5.
        wait_max: Maximum wait time between retries in seconds.
            Defaults to 10.0.

        sleep: Callable used to wait between retries. Defaults to time.sleep.
    """

    max_attempts: int = 3
    wait_multiplier: float = 0.5
    wait_max: float = 10.0

    sleep: Callable[[float], None] = time.sleep


def extract_retry_after(error: HTTPError) -> float | None:
    """Extract a retry delay from an HTTP error's Retry-After header.

    Accepts non-negative integer seconds or a timezone-aware HTTP date.
    Past dates yield a delay of zero seconds.

    Args:
        error: HTTP error containing the response headers.

    Returns:
        The retry delay in seconds, or None if the header is missing,
        empty, invalid, or contains a date without a timezone.
    """
    value = error.headers.get("Retry-After", "").strip()
    if not value:
        return None

    try:
        if value.isascii() and value.isdigit():
            return float(value)

        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            return None

        retry_diff = retry_at - dt.datetime.now(dt.timezone.utc)
        return max(0.0, retry_diff.total_seconds())
    except (ValueError, TypeError, OverflowError):
        return None


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Check if an exception is a retryable HTTP error."""
    return isinstance(exc, HTTPError) and exc.code in RETRYABLE_STATUS_CODES


def urlopen_with_retry(
    url: str | Request,
    timeout: float | None = None,
    retry_config: RetryConfig | None = None,
    opener: OpenerDirector | None = None,
) -> HTTPResponse:
    """Open a URL with automatic retry on transient HTTP errors.

    Retries on HTTP 408, 429, 500, 502, 503, and 504 status codes.
    A valid Retry-After header supplies the delay as integer seconds or an
    HTTP date; missing or invalid headers fall back to exponential backoff.
    If the requested delay exceeds `retry_config.wait_max`, retries stop and
    the HTTP error is raised rather than retrying earlier than requested.

    Args:
        url: URL string or Request object to open.
        timeout: Optional timeout in seconds.
        retry_config: Optional retry configuration. If None, uses defaults.
            Set max_attempts=1 to disable retries.
        opener: Optional OpenerDirector to open the URL. If None, uses
            urllib.request.urlopen.

    Returns:
        HTTPResponse object.

    Raises:
        HTTPError: If the request fails after all retries or with
            a non-retryable status code, or the Retry-After delay exceeds
            the configured wait_max.
        URLError: If a network error occurs.
    """
    config = retry_config or RetryConfig()

    # Retry wait utilities
    backoff = wait_exponential(
        multiplier=config.wait_multiplier,
        max=config.wait_max,
    )

    def _wait_before_urlopen_retry(state: RetryCallState) -> float:
        error = state.outcome.exception() if state.outcome is not None else None

        if isinstance(error, HTTPError):
            delay = extract_retry_after(error)
            if delay is not None:
                # if server requested retry time is longer
                # than maximum wait time raise error
                if delay > config.wait_max:
                    raise error
                return delay

        return backoff(state)

    # Configure retry policy
    retrying = Retrying(
        stop=stop_after_attempt(max(1, config.max_attempts)),
        wait=_wait_before_urlopen_retry,
        retry=retry_if_exception(_is_retryable_http_error),
        reraise=True,
        sleep=config.sleep,
    )

    # Open with retry
    open_fn = opener.open if opener is not None else urlopen
    for attempt in retrying:
        with attempt:
            if timeout is not None:
                return open_fn(url, timeout=timeout)
            return open_fn(url)

    # Should never reach here, but for type checker
    msg = "Retry loop exited unexpectedly"
    raise RuntimeError(msg)


def validate_and_get_http_host_port(url_string: str) -> tuple[str, int]:
    """Validate an HTTP or HTTPS URL string and extract its host and port.

    If the port is not explicitly specified, it will be inferred from the
    scheme.

    Args:
        url_string: URL from which to extract the host and port.

    Returns:
        The host and port extracted from `url_string`.

    Raises:
        InvalidUrlError: If the URL is malformed, missing a host,
            or uses a scheme other than HTTP or HTTPS.
    """
    try:
        scheme, host, port = extract_scheme_host_port_from_url(url_string)
    except ValueError as err:
        raise InvalidUrlError(
            message=f"invalid HTTP URL: {url_string}",
            url_string=url_string,
        ) from err

    if scheme not in ("http", "https"):
        raise InvalidUrlError(
            message=f"invalid HTTP URL: {url_string}",
            url_string=url_string,
        )

    return host, port


def http_urlopen_with_retry(
    url: str | Request,
    timeout: float | None = None,
    retry_config: RetryConfig | None = None,
    opener: OpenerDirector | None = None,
) -> HTTPResponse:
    """Validate that `url` is HTTP(S), then open it with automatic retry.

    This is the HTTP(S)-only counterpart to `urlopen_with_retry`.

    Raises:
        InvalidUrlError: If the URL is malformed, missing a host, or
            uses a scheme other than HTTP or HTTPS.
        HTTPError: If the request fails after all retries or with
            a non-retryable status code.
        URLError: If a network error occurs.
    """
    url_string = url.full_url if isinstance(url, Request) else url
    validate_and_get_http_host_port(url_string)
    return urlopen_with_retry(
        url,
        timeout=timeout,
        retry_config=retry_config,
        opener=opener,
    )

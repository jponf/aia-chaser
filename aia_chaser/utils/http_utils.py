"""HTTP utilities with retry support."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tenacity import Retrying, retry_if_exception, stop_after_attempt, wait_exponential


if TYPE_CHECKING:
    from http.client import HTTPResponse
    from typing import Final

# HTTP status codes of transient errors worth retrying
RETRYABLE_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {
        429,  # Too Many Requests
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
    """

    max_attempts: int = 3
    wait_multiplier: float = 0.5
    wait_max: float = 10.0


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Check if an exception is a retryable HTTP error."""
    return isinstance(exc, HTTPError) and exc.code in RETRYABLE_STATUS_CODES


def urlopen_with_retry(
    url: str | Request,
    timeout: float | None = None,
    retry_config: RetryConfig | None = None,
) -> HTTPResponse:
    """Open a URL with automatic retry on transient HTTP errors.

    Retries on HTTP 429, 502, 503, and 504 status codes with
    exponential backoff.

    Args:
        url: URL string or Request object to open.
        timeout: Optional timeout in seconds.
        retry_config: Optional retry configuration. If None, uses defaults.
            Set max_attempts=1 to disable retries.

    Returns:
        HTTPResponse object.

    Raises:
        HTTPError: If the request fails after all retries or with
            a non-retryable status code.
        URLError: If a network error occurs.
    """
    config = retry_config or RetryConfig()

    retrying = Retrying(
        stop=stop_after_attempt(max(1, config.max_attempts)),
        wait=wait_exponential(multiplier=config.wait_multiplier, max=config.wait_max),
        retry=retry_if_exception(_is_retryable_http_error),
        reraise=True,
    )

    for attempt in retrying:
        with attempt:
            return urlopen(url, timeout=timeout)  # noqa: S310

    # Should never reach here, but for type checker
    msg = "Retry loop exited unexpectedly"
    raise RuntimeError(msg)

"""HTTP utilities with retry support."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tenacity import Retrying, retry_if_exception, stop_after_attempt, wait_exponential

from aia_chaser.exceptions import InvalidUrlError
from aia_chaser.utils.url import extract_scheme_host_port_from_url


if TYPE_CHECKING:
    from http.client import HTTPResponse
    from typing import Final
    from urllib.request import OpenerDirector

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
    opener: OpenerDirector | None = None,
) -> HTTPResponse:
    """Open a URL with automatic retry on transient HTTP errors.

    Retries on HTTP 429, 502, 503, and 504 status codes with
    exponential backoff.

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

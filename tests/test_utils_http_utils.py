from __future__ import annotations

from email.message import Message
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

from aia_chaser.utils.http_utils import (
    RETRYABLE_STATUS_CODES,
    RetryConfig,
    extract_retry_after,
    urlopen_with_retry,
    validate_and_get_http_host_port,
)


def test_validate_http_host_port_accepts_uppercase_scheme() -> None:
    """The HTTP validator should accept uppercase URL schemes."""
    assert validate_and_get_http_host_port("HTTPS://Example.com/path") == (
        "example.com",
        443,
    )


def test_urlopen_with_retry_uses_custom_opener() -> None:
    """urlopen_with_retry should use the provided opener."""
    opener = Mock()
    expected_response = Mock()
    opener.open.return_value = expected_response

    response = urlopen_with_retry(
        "http://example.com/crl",
        timeout=15.0,
        retry_config=RetryConfig(max_attempts=1),
        opener=opener,
    )

    assert response is expected_response
    opener.open.assert_called_once_with("http://example.com/crl", timeout=15.0)


def test_urlopen_with_retry_defaults_to_urlopen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """urlopen_with_retry should default to standard urlopen if no opener."""
    mock_urlopen = Mock()
    expected_response = Mock()
    mock_urlopen.return_value = expected_response
    monkeypatch.setattr("aia_chaser.utils.http_utils.urlopen", mock_urlopen)

    response = urlopen_with_retry(
        "http://example.com/crl",
        timeout=10.0,
        retry_config=RetryConfig(max_attempts=1),
    )

    assert response is expected_response
    mock_urlopen.assert_called_once_with("http://example.com/crl", timeout=10.0)


@pytest.mark.parametrize(
    "status_code",
    list(RETRYABLE_STATUS_CODES),
)
def test_urlopen_with_retry_recovers_from_transient_error(
    status_code: int,
) -> None:
    """The request should succeed after a transient HTTP error."""
    url = "http://example.com/crl"
    opener = Mock()
    expected_response = Mock()
    opener.open.side_effect = [
        HTTPError(url, status_code, "Transient error", Message(), None),
        expected_response,
    ]

    response = urlopen_with_retry(
        url,
        retry_config=RetryConfig(max_attempts=2, wait_multiplier=0),
        opener=opener,
    )

    assert response is expected_response
    assert opener.open.call_count == 2  # noqa: PLR2004


@pytest.mark.parametrize(
    "status_code",
    list(RETRYABLE_STATUS_CODES),
)
def test_urlopen_with_retry_stops_after_max_attempts(
    status_code: int,
) -> None:
    """The request should raise the last HTTP error after exhausting retries."""
    url = "http://example.com/crl"
    opener = Mock()
    error = HTTPError(url, status_code, "Transient error", Message(), None)
    opener.open.side_effect = error

    with pytest.raises(HTTPError) as exc_info:
        urlopen_with_retry(
            url,
            retry_config=RetryConfig(max_attempts=2, wait_multiplier=0),
            opener=opener,
        )

    assert exc_info.value is error
    assert opener.open.call_count == 2  # noqa: PLR2004


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("5", 5.0),
        ("0", 0.0),
        ("", None),
        ("invalid", None),
        ("-1", None),
        ("1.5", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
    ],
)
def test_extract_retry_after(header: str, expected: float | None) -> None:
    """The parser should return the delay or reject invalid values."""
    headers = Message()
    headers["Retry-After"] = header
    error = HTTPError("http://example.com/crl", 503, "Unavailable", headers, None)

    assert extract_retry_after(error) == expected


@pytest.mark.parametrize(
    ("header", "expected_delay"),
    [("5", 5.0), ("0", 0.0), ("10", 10.0), ("invalid", 0.5), (None, 0.5)],
)
def test_urlopen_with_retry_selects_delay(
    header: str | None,
    expected_delay: float,
) -> None:
    """The request should honor Retry-After or fall back to backoff."""
    # Mock opener that raises a retryable error on first
    # attempt and a mocked response on second one
    headers = Message()
    if header is not None:
        headers["Retry-After"] = header
    url = "http://example.com/crl"
    response = Mock()

    opener = Mock()
    opener.open.side_effect = [
        HTTPError(url, 503, "Unavailable", headers, None),
        response,
    ]

    # Mock sleep function used to wait until next retry
    sleep = Mock()

    # Run open with retry
    result = urlopen_with_retry(
        url,
        retry_config=RetryConfig(
            max_attempts=2,
            sleep=sleep,
        ),
        opener=opener,
    )

    assert result is response
    sleep.assert_called_once_with(expected_delay)


def test_urlopen_with_retry_rejects_excessive_delay() -> None:
    """The request should stop without sleeping when the delay exceeds the limit."""
    # Mock opener that raises a retryable error on first
    # attempt and a mocked response on second one
    headers = Message()
    headers["Retry-After"] = "11"
    url = "http://example.com/crl"
    error = HTTPError(url, 503, "Unavailable", headers, None)
    opener = Mock()
    opener.open.side_effect = error

    # Mock sleep function used to wait until next retry
    sleep = Mock()

    # Run open with retry
    with pytest.raises(HTTPError) as exc_info:
        urlopen_with_retry(
            url,
            opener=opener,
            retry_config=RetryConfig(
                wait_max=10,
                sleep=sleep,
            ),
        )

    assert exc_info.value is error
    opener.open.assert_called_once_with(url)
    sleep.assert_not_called()

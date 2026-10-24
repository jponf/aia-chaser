from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

from aia_chaser.utils.http_utils import (
    RetryConfig,
    urlopen_with_retry,
    validate_and_get_http_host_port,
)


if TYPE_CHECKING:
    import pytest


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

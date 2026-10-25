from __future__ import annotations

import socket
from email.message import Message
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock
from urllib.error import HTTPError, URLError

import pytest

from aia_chaser import chaser
from aia_chaser.exceptions import (
    AiaChaseExhaustedError,
    CertificateDownloadError,
    InvalidUrlError,
    NonGlobalAddressError,
    NoValidAiaCaUrlError,
)
from aia_chaser.utils import http_pinning
from aia_chaser.utils.http_utils import RetryConfig


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def clear_certificate_opener_cache() -> Iterator[None]:
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    http_pinning.get_cached_certificate_opener.cache_clear()
    yield
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    http_pinning.get_cached_certificate_opener.cache_clear()


def test_default_private_ip_option_preserves_aia_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=[object()]),
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(side_effect=AssertionError("default behavior must not resolve-check")),
    )
    assert chaser.try_download_certificate(["http://internal.example/issuer.crt"])
    opener.open.assert_called_once()


def test_download_uses_opener_for_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"

    opener = Mock()
    opener.open.return_value = response

    get_opener = Mock(return_value=opener)
    monkeypatch.setattr(chaser, "get_cached_certificate_opener", get_opener)
    monkeypatch.setattr(chaser, "_try_parse_certificate", Mock(return_value=[object()]))

    url = "http://public.example/issuer.crt"
    assert chaser.try_download_certificate(
        [url],
        allow_private_ip=False,
    )

    get_opener.assert_called_once_with(allow_private_ip=False)
    opener.open.assert_called_once()
    assert opener.open.call_args.args[0] == url


def test_download_cache_separates_address_policies(  # noqa: ANN201
    monkeypatch: pytest.MonkeyPatch,
):
    """The cache should reuse results only within the same address policy."""
    # Fake cached certificate opener that returns fake response
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"

    opener = Mock()
    opener.open.return_value = response
    get_opener = Mock(return_value=opener)
    monkeypatch.setattr(chaser, "get_cached_certificate_opener", get_opener)

    certificates = [object()]
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=certificates),
    )
    urls = ["http://public.example/issuer.crt"]

    # Distinct policy must call get_opener twice (not cached)
    assert chaser.try_download_certificate(urls, allow_private_ip=True) == certificates
    assert chaser.try_download_certificate(urls, allow_private_ip=False) == certificates

    assert opener.open.call_count == 2  # noqa: PLR2004
    assert get_opener.call_count == 2  # noqa: PLR2004
    assert [call.kwargs["allow_private_ip"] for call in get_opener.call_args_list] == [
        True,
        False,
    ]


@pytest.mark.parametrize("max_attempts", [1, 2])
def test_aia_download_respects_retry_attempts(  # noqa: ANN201
    monkeypatch: pytest.MonkeyPatch,
    max_attempts: int,
):
    """AIA downloads should honor the configured number of attempts."""
    # Set up mock response
    url = "http://public.example/retry.crt"
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"

    # Opener fakes a 503 (retryable) error and returns fake response on next attempt
    opener = Mock()
    opener.open.side_effect = [
        HTTPError(url, 503, "Unavailable", Message(), None),
        response,
    ]
    monkeypatch.setattr(
        chaser,
        "get_cached_certificate_opener",
        Mock(return_value=opener),
    )

    # Parse function returns a fake certificate object
    certificates = [object()]
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=certificates),
    )

    # Retry configuration
    sleep = Mock()
    config = RetryConfig(max_attempts=max_attempts, sleep=sleep)

    # If only one attempt is allowed it should raise otherwise
    # succeed with fake certificate
    if max_attempts == 1:
        with pytest.raises(AiaChaseExhaustedError):
            chaser.try_download_certificate([url], retry_config=config)
        sleep.assert_not_called()
    else:
        assert (
            chaser.try_download_certificate([url], retry_config=config) == certificates
        )
        sleep.assert_called_once_with(config.wait_multiplier)

    assert opener.open.call_count == max_attempts


def test_aia_cache_ignores_retry_configuration(  # noqa: ANN201
    monkeypatch: pytest.MonkeyPatch,
):
    """Cached certificates should be reused across different retry configurations."""
    # Set up mock response
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"

    # Opener returns the fake response on a cache miss
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(
        chaser,
        "get_cached_certificate_opener",
        Mock(return_value=opener),
    )

    # Parse function returns a fake certificate object
    certificates = [object()]
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=certificates),
    )

    # Custom sleep should not affect configuration equality or hashing
    sleep = Mock()

    # Use default settings, disabled retries, and an increased attempt limit
    configs = [
        None,
        RetryConfig(max_attempts=1, sleep=sleep),
        RetryConfig(max_attempts=5),
    ]

    # First call populates the cache; other configurations reuse the result
    for config in configs:
        assert (
            chaser.try_download_certificate(
                ["http://public.example/cached.crt"],
                retry_config=config,
            )
            == certificates
        )

    # Only one download should occur, with no retry sleeps
    opener.open.assert_called_once()
    sleep.assert_not_called()


def test_download_certificate_warns_on_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    monkeypatch.setattr(chaser, "_try_parse_certificate", Mock(return_value=[object()]))

    with pytest.warns(
        UserWarning,
        match="Trying to download an intermediate CA certificate using HTTPS",
    ):
        chaser.try_download_certificate(["https://secure.example/cert.crt"])


def test_try_download_certificate_accepts_uppercase_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    certificate = object()
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=[certificate]),
    )
    url = "HTTP://Example.com/CaseSensitivePath"

    assert chaser.try_download_certificate([url]) == [certificate]
    assert opener.open.call_args.args[0] == url


def test_try_download_certificate_continues_after_non_global_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The downloader should try the next URL after an unsafe host is rejected."""
    certificate = object()
    download = Mock(
        side_effect=[
            NonGlobalAddressError("internal.example", "127.0.0.1"),
            [certificate],
        ],
    )
    monkeypatch.setattr(chaser, "_download_certificate", download)
    urls = [
        "http://internal.example/issuer.crt",
        "http://public.example/issuer.crt",
    ]

    assert chaser.try_download_certificate(
        urls,
        allow_private_ip=False,
    ) == [certificate]

    assert download.call_count == len(urls)


def test_try_download_certificate_aggregates_non_global_url_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The downloader should report address-policy errors after all URLs fail."""
    errors = [
        NonGlobalAddressError("internal-one.example", "127.0.0.1"),
        NonGlobalAddressError("internal-two.example", "10.0.0.1"),
    ]
    download = Mock(side_effect=errors)
    monkeypatch.setattr(chaser, "_download_certificate", download)

    with pytest.raises(AiaChaseExhaustedError) as exc_info:
        chaser.try_download_certificate(
            [
                "http://internal-one.example/issuer.crt",
                "http://internal-two.example/issuer.crt",
            ],
            allow_private_ip=False,
        )

    assert exc_info.value.errors == errors
    assert download.call_count == len(errors)


@pytest.mark.parametrize(
    "url",
    [
        "ldap://ldap.example/certs?certificateName=issuer",
        "file:///etc/ssl/certs/issuer.crt",
    ],
)
def test_try_download_certificate_raises_without_http_url(url: str) -> None:
    """The downloader should raise NoValidAiaCaUrlError when no AIA URL is HTTP(S)."""
    with pytest.raises(NoValidAiaCaUrlError) as exc_info:
        chaser.try_download_certificate([url])

    assert exc_info.value.urls == [url]


@pytest.mark.parametrize("url", ["ftp://example.com/cert.crt", "http"])
def test_download_certificate_raises_on_invalid_scheme(url: str) -> None:
    """The downloader should reject unsupported or missing schemes."""
    with pytest.raises(InvalidUrlError, match="invalid HTTP URL"):
        chaser._download_certificate(url)  # noqa: SLF001


def test_download_certificate_wraps_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = Mock()
    opener.open.side_effect = URLError("connection refused")
    monkeypatch.setattr(
        chaser,
        "get_cached_certificate_opener",
        Mock(return_value=opener),
    )

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate(  # noqa: SLF001
            "http://failing.example/cert.crt",
        )


def test_download_certificate_raises_on_non_ok_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=404)
    response.__enter__.return_value = response
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(
        chaser,
        "get_cached_certificate_opener",
        Mock(return_value=opener),
    )

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate(  # noqa: SLF001
            "http://notfound.example/cert.crt",
        )

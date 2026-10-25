from __future__ import annotations

import socket
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock
from urllib.error import URLError

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
        chaser._download_certificate(url, opener=Mock())  # noqa: SLF001


def test_download_certificate_wraps_network_error() -> None:
    opener = Mock()
    opener.open.side_effect = URLError("connection refused")

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate(  # noqa: SLF001
            "http://failing.example/cert.crt",
            opener=opener,
        )


def test_download_certificate_raises_on_non_ok_status() -> None:
    response = MagicMock(status=404)
    response.__enter__.return_value = response
    opener = Mock()
    opener.open.return_value = response

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate(  # noqa: SLF001
            "http://notfound.example/cert.crt",
            opener=opener,
        )

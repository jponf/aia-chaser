from __future__ import annotations

import socket
from unittest.mock import MagicMock, Mock
from urllib.error import URLError
from urllib.request import ProxyHandler

import pytest

from aia_chaser import chaser
from aia_chaser.exceptions import (
    AiaChaseExhaustedError,
    CertificateDownloadError,
    NonGlobalAddressError,
)
from aia_chaser.utils import http_pinning
from aia_chaser.utils.http_pinning import AiaHTTPHandler, AiaHTTPSHandler


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
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    assert chaser._download_certificate(  # noqa: SLF001
        "http://internal.example/issuer.crt",
    )
    opener.open.assert_called_once()

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_download_uses_pinned_handlers_and_disables_proxy_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"

    opener = Mock()
    opener.open.return_value = response

    build_opener = Mock(return_value=opener)
    monkeypatch.setattr(http_pinning, "build_opener", build_opener)
    monkeypatch.setattr(chaser, "_try_parse_certificate", Mock(return_value=[object()]))

    chaser._download_certificate.cache_clear()  # noqa: SLF001
    assert chaser._download_certificate(  # noqa: SLF001
        "http://public.example/issuer.crt",
        allow_private_ip=False,
    )

    handlers = build_opener.call_args.args
    assert any(isinstance(handler, AiaHTTPHandler) for handler in handlers)
    assert any(isinstance(handler, AiaHTTPSHandler) for handler in handlers)
    proxy_handler = next(
        handler for handler in handlers if isinstance(handler, ProxyHandler)
    )
    assert proxy_handler.proxies == {}  # type: ignore[attr-defined]
    chaser._download_certificate.cache_clear()  # noqa: SLF001


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
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.warns(
        UserWarning,
        match="Trying to download an intermediate CA certificate using HTTPS",
    ):
        chaser._download_certificate("https://secure.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001


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
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    url = "HTTP://Example.com/CaseSensitivePath"

    assert chaser.try_download_certificate([url]) == [certificate]
    assert opener.open.call_args.args[0] == url

    chaser._download_certificate.cache_clear()  # noqa: SLF001


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


@pytest.mark.parametrize("url", ["ftp://example.com/cert.crt", "http"])
def test_download_certificate_raises_on_invalid_scheme(url: str) -> None:
    """The downloader should reject unsupported or missing schemes."""
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    with pytest.raises(
        CertificateDownloadError,
        match="URL scheme must be http or https",
    ):
        chaser._download_certificate(url)  # noqa: SLF001
    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_download_certificate_wraps_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = Mock()
    opener.open.side_effect = URLError("connection refused")
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate("http://failing.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_download_certificate_raises_on_non_ok_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=404)
    response.__enter__.return_value = response
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate("http://notfound.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001

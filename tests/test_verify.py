from __future__ import annotations

import datetime as dt
import io
import socket
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from aia_chaser import verify
from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    CertificateTimeZoneError,
    CrlDownloadError,
    InvalidUrlError,
    NonGlobalAddressError,
    OcspDownloadError,
    RootCertificateNotFoundError,
)
from aia_chaser.utils.http_pinning import get_cached_certificate_opener
from aia_chaser.verify import (
    VerifyCertificatesConfig,
    VerifyOcspConfig,
    _download_any_crl,
    _run_ocsp_request,
    verify_certificate_chain,
    verify_ocsp_status,
)
from tests.conftest import make_addrinfo


if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def _create_sample_crl() -> bytes:
    key = rsa.generate_private_key(65537, 2048)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")]),
    )
    builder = builder.last_update(dt.datetime.now(dt.timezone.utc))
    builder = builder.next_update(
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1),
    )
    crl = builder.sign(key, hashes.SHA256())
    return crl.public_bytes(Encoding.DER)


def _create_sample_ocsp_response(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    issuer_key: RSAPrivateKey,
) -> bytes:
    builder = x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=x509.ocsp.OCSPCertStatus.GOOD,
        this_update=dt.datetime.now(dt.timezone.utc),
        next_update=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1),
        revocation_time=None,
        revocation_reason=None,
    )
    builder = builder.responder_id(
        x509.ocsp.OCSPResponderEncoding.NAME,
        issuer,
    )
    resp = builder.sign(issuer_key, hashes.SHA256())
    return resp.public_bytes(Encoding.DER)


def test_verify_chain_of_2_ok(host_and_ca_chain: Sequence[x509.Certificate]) -> None:
    verify_certificate_chain(host_and_ca_chain)


def test_verify_chain_of_2_wrong_subject(
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    # By reversing the chain the issued's (host) issuer and
    # the issuer's subject will not match
    reversed_chain = reversed(host_and_ca_chain)
    with pytest.raises(CertificateChainError):
        verify_certificate_chain(reversed_chain)


def test_verify_chain_of_2_wrong_validity_period(
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    verification_time = dt.datetime.now(
        dt.timezone.utc,
    ) - dt.timedelta(days=1)

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(
            host_and_ca_chain,
            config=VerifyCertificatesConfig(
                verification_time=verification_time,
            ),
        )
    assert type(exc_info.value.__cause__) is CertificateExpiredError


def test_verify_chain_of_2_offset_naive_validation_time(
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    verification_time = dt.datetime.now()  # noqa: DTZ005

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(
            host_and_ca_chain,
            config=VerifyCertificatesConfig(
                verification_time=verification_time,
            ),
        )
    assert type(exc_info.value.reason) is CertificateTimeZoneError


def test_verify_chain_of_2_root_not_trusted(
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(host_and_ca_chain, trusted={})
    assert type(exc_info.value.reason) is RootCertificateNotFoundError


def test_verify_chain_of_2_root_trusted(
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    root_ca = host_and_ca_chain[-1]
    verify_certificate_chain(
        host_and_ca_chain,
        trusted={root_ca.subject: root_ca},
    )


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://internal.example/crl", "invalid-scheme"],
)
def test_download_any_crl_rejects_non_http_scheme(url: str) -> None:
    """_download_any_crl must reject non-http schemes."""
    for allow_private_ip in (True, False):
        with pytest.raises(CrlDownloadError) as exc_info:
            _download_any_crl([url], allow_private_ip=allow_private_ip)
        assert isinstance(exc_info.value.reason, InvalidUrlError)


def test_download_any_crl_falls_back_after_invalid_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_download_any_crl should fall back to next URL if scheme is invalid."""
    crl_bytes = _create_sample_crl()
    fake_response = MagicMock()
    fake_response.__enter__.return_value = fake_response
    fake_response.read.return_value = crl_bytes

    mock_urlopen = Mock(return_value=fake_response)
    monkeypatch.setattr(verify, "urlopen_with_retry", mock_urlopen)

    crl = _download_any_crl(
        ["file:///etc/passwd", "http://public.example/crl.crl"],
        allow_private_ip=False,
    )

    assert crl is not None
    assert mock_urlopen.call_count == 1
    assert mock_urlopen.call_args.args[0] == "http://public.example/crl.crl"


@pytest.mark.parametrize(
    "private_ip",
    ["127.0.0.1", "::1", "fe80::1", "fc00::1"],
)
def test_download_any_crl_strict_rejects_private_ip(
    monkeypatch: pytest.MonkeyPatch,
    private_ip: str,
) -> None:
    """_download_any_crl rejects private IP when allow_private_ip=False."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo(private_ip)]),
    )

    with pytest.raises(CrlDownloadError) as exc_info:
        _download_any_crl(["http://internal.example/crl.crl"], allow_private_ip=False)
    assert isinstance(exc_info.value.reason, NonGlobalAddressError)


@pytest.mark.parametrize(
    ("public_ip", "private_ip"),
    [
        ("8.8.8.8", "127.0.0.1"),
        ("2001:4860:4860::8888", "::1"),
    ],
)
def test_download_any_crl_dns_rebinding_toctou_prevention(
    monkeypatch: pytest.MonkeyPatch,
    public_ip: str,
    private_ip: str,
) -> None:
    """Ensure DNS rebinding (TOCTOU) cannot bypass CRL download protection."""
    public_addr = make_addrinfo(public_ip)
    private_addr = make_addrinfo(private_ip)

    crl_bytes = _create_sample_crl()
    http_response_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/pkix-crl\r\n"
        b"Content-Length: " + str(len(crl_bytes)).encode() + b"\r\n\r\n" + crl_bytes
    )

    fake_sock = MagicMock()
    fake_sock.makefile.return_value = io.BytesIO(http_response_data)
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_sock))

    getaddrinfo_mock = Mock(side_effect=[[public_addr], [private_addr]])
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_mock)

    crl = _download_any_crl(
        ["http://rebind.example/crl.crl"],
        allow_private_ip=False,
    )

    assert crl is not None
    assert getaddrinfo_mock.call_count == 1
    fake_sock.connect.assert_called_once_with(public_addr[4])
    assert fake_sock.connect.call_args.args[0] != private_addr[4]


def test_download_any_crl_uses_cached_opener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_download_any_crl should use get_cached_certificate_opener."""
    crl_bytes = _create_sample_crl()
    fake_response = MagicMock()
    fake_response.__enter__.return_value = fake_response
    fake_response.read.return_value = crl_bytes

    mock_urlopen = Mock(return_value=fake_response)
    monkeypatch.setattr(verify, "urlopen_with_retry", mock_urlopen)

    _download_any_crl(["http://public.example/crl.crl"], allow_private_ip=False)

    expected_opener = get_cached_certificate_opener(allow_private_ip=False)
    assert mock_urlopen.call_args.kwargs["opener"] is expected_opener


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://internal.example/ocsp", "bad-scheme"],
)
def test_ocsp_request_rejects_non_http_scheme(
    url: str,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """_run_ocsp_request must reject non-http schemes."""
    leaf_cert, root_cert = host_and_ca_chain
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, root_cert, hashes.SHA256())
    ocsp_req = builder.build()

    with pytest.raises(OcspDownloadError) as exc_info:
        _run_ocsp_request(
            ocsp_request=ocsp_req,
            ocsp_url=url,
            issuer=root_cert,
            config=VerifyOcspConfig(allow_private_ip=True),
        )
    assert isinstance(exc_info.value.reason, InvalidUrlError)


@pytest.mark.parametrize(
    "private_ip",
    ["127.0.0.1", "::1", "fe80::1", "fc00::1"],
)
def test_ocsp_request_strict_rejects_private_ip(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
    private_ip: str,
) -> None:
    """_run_ocsp_request rejects private IP when allow_private_ip=False."""
    leaf_cert, root_cert = host_and_ca_chain
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, root_cert, hashes.SHA256())
    ocsp_req = builder.build()

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo(private_ip)]),
    )

    with pytest.raises(OcspDownloadError) as exc_info:
        _run_ocsp_request(
            ocsp_request=ocsp_req,
            ocsp_url="http://internal.example/ocsp",
            issuer=root_cert,
            config=VerifyOcspConfig(allow_private_ip=False),
        )
    assert isinstance(exc_info.value.reason, NonGlobalAddressError)


@pytest.mark.parametrize(
    ("public_ip", "private_ip"),
    [
        ("8.8.8.8", "127.0.0.1"),
        ("2001:4860:4860::8888", "::1"),
    ],
)
def test_ocsp_request_dns_rebinding_toctou_prevention(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
    root_ca_key: RSAPrivateKey,
    public_ip: str,
    private_ip: str,
) -> None:
    """Ensure DNS rebinding (TOCTOU) cannot bypass OCSP request protection."""
    leaf_cert, root_cert = host_and_ca_chain
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, root_cert, hashes.SHA256())
    ocsp_req = builder.build()

    resp_bytes = _create_sample_ocsp_response(leaf_cert, root_cert, root_ca_key)
    http_response_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/ocsp-response\r\n"
        b"Content-Length: " + str(len(resp_bytes)).encode() + b"\r\n\r\n" + resp_bytes
    )

    fake_sock = MagicMock()
    fake_sock.makefile.return_value = io.BytesIO(http_response_data)
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_sock))

    public_addr = make_addrinfo(public_ip)
    private_addr = make_addrinfo(private_ip)
    getaddrinfo_mock = Mock(side_effect=[[public_addr], [private_addr]])
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_mock)

    status = _run_ocsp_request(
        ocsp_request=ocsp_req,
        ocsp_url="http://rebind.example/ocsp",
        issuer=root_cert,
        config=VerifyOcspConfig(allow_private_ip=False),
    )

    assert status == x509.ocsp.OCSPCertStatus.GOOD
    assert getaddrinfo_mock.call_count == 1
    fake_sock.connect.assert_called_once_with(public_addr[4])
    assert fake_sock.connect.call_args.args[0] != private_addr[4]


def test_ocsp_request_uses_pinned_opener(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """_run_ocsp_request should pass the appropriate opener to urlopen_with_retry."""
    leaf_cert, root_cert = host_and_ca_chain
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, root_cert, hashes.SHA256())
    ocsp_req = builder.build()

    mock_urlopen = Mock(side_effect=RuntimeError("stop after open"))
    monkeypatch.setattr(verify, "urlopen_with_retry", mock_urlopen)

    with pytest.raises(RuntimeError, match="stop after open"):
        _run_ocsp_request(
            ocsp_request=ocsp_req,
            ocsp_url="http://public.example/ocsp",
            issuer=root_cert,
            config=VerifyOcspConfig(allow_private_ip=False),
        )

    expected_opener = get_cached_certificate_opener(allow_private_ip=False)
    assert mock_urlopen.call_args.kwargs["opener"] is expected_opener


def test_verify_certificate_chain_passes_allow_private_ip(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """verify_certificate_chain should propagate allow_private_ip to CRL and OCSP."""
    mock_crl = Mock()
    mock_ocsp = Mock()
    monkeypatch.setattr(verify, "verify_crl_status", mock_crl)
    monkeypatch.setattr(verify, "verify_ocsp_status", mock_ocsp)

    verify_certificate_chain(
        host_and_ca_chain,
        config=VerifyCertificatesConfig(
            crl_enabled=True,
            ocsp_enabled=True,
            allow_private_ip=False,
        ),
    )

    assert mock_crl.call_args.kwargs["allow_private_ip"] is False
    assert mock_ocsp.call_args.kwargs["config"].allow_private_ip is False


def test_verify_certificate_chain_wraps_crl_download_error(
    host_and_ca_chain: Sequence[x509.Certificate],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verification should wrap a rejected CRL URL in CertificateChainError."""
    monkeypatch.setattr(
        verify,
        "extract_crl_urls",
        Mock(return_value=["file:///etc/passwd"]),
    )

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(
            host_and_ca_chain,
            config=VerifyCertificatesConfig(crl_enabled=True),
        )

    reason = exc_info.value.reason
    assert isinstance(reason, CrlDownloadError)
    assert isinstance(reason.reason, InvalidUrlError)


def test_verify_certificate_chain_wraps_ocsp_download_error(
    host_and_ca_chain: Sequence[x509.Certificate],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verification should wrap a blocked OCSP responder in CertificateChainError."""
    # path aia information and getaddrinfo to return a private IP
    monkeypatch.setattr(
        verify,
        "extract_aia_information",
        Mock(
            return_value=Mock(
                ca_issuers=[],
                ocsp_urls=["http://internal.example/ocsp"],
            ),
        ),
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("127.0.0.1")]),
    )

    # Verify ocsp should raise OcspDownloadError
    # which in turns is triggered by a NonGlobalAddressError
    with pytest.raises(OcspDownloadError) as base_exc_info:
        verify_ocsp_status(
            host_and_ca_chain[0],
            host_and_ca_chain[1],
            VerifyOcspConfig(allow_private_ip=False),
        )
    assert isinstance(base_exc_info.value.reason, NonGlobalAddressError)
    assert isinstance(base_exc_info.value.__cause__, NonGlobalAddressError)

    # Verify certificate chain should wrap the OcspDownloadError in
    # a CertificateChainError
    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(
            host_and_ca_chain,
            config=VerifyCertificatesConfig(
                ocsp_enabled=True,
                allow_private_ip=False,
            ),
        )

    reason = exc_info.value.reason
    assert isinstance(reason, OcspDownloadError)
    assert isinstance(reason.reason, NonGlobalAddressError)

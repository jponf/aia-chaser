import ssl

import pytest

from aia_chaser import AiaChaser, VerifyCertificatesConfig
from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    CrlRevokedError,
    OcspRevokedStatusError,
)

from .conftest import EXPIRED_URLS, REVOKED_CRL_URLS, REVOKED_OCSP_URLS, TEST_URLS


@pytest.mark.parametrize("url_string", TEST_URLS)
def test_aia_chase_url_ok(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_cert_chain_for_url(
        url_string=url_string,
        verify_config=VerifyCertificatesConfig(
            ocsp_enabled=True,
        ),
    )
    # on Windows microsoft.com certificate is trusted resulting
    # in a chain of length 1 ¯\_(ツ)_/¯
    assert len(chain) >= 1


@pytest.mark.parametrize(
    "url_string",
    [
        "www.siemens.com",
        "www.microsoft.com",
        "www.amazon.com",
        "www.google.com",
        "www.segre.com",
        "www.nytimes.com",
    ],
)
def test_aia_chase_url_no_scheme(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(ValueError):  # noqa: PT011
        chaser.fetch_ca_chain_for_url(url_string=url_string)


@pytest.mark.parametrize("url_string", EXPIRED_URLS)
def test_aia_chase_url_expired(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(CertificateChainError) as exc_info:
        chaser.fetch_ca_chain_for_url(url_string=url_string)
    assert type(exc_info.value.reason) is CertificateExpiredError


@pytest.mark.parametrize("url_string", EXPIRED_URLS)
def test_aia_chase_url_ignore_expired(url_string: str) -> None:
    # Create context that allows fetching expired certificates
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Load trusted CAs separately since CERT_NONE context won't have them
    from aia_chaser.utils.cert_utils import load_ssl_ca_certificates

    trusted_cas = load_ssl_ca_certificates()

    chaser = AiaChaser(context=context, trusted_cas=trusted_cas)
    chain = chaser.fetch_ca_chain_for_url(url_string=url_string, verify=False)
    assert len(chain) >= 1


@pytest.mark.parametrize("url_string", REVOKED_CRL_URLS)
def test_aia_chase_url_crl_revoked(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(CertificateChainError) as exc_info:
        chaser.fetch_ca_chain_for_url(
            url_string=url_string,
            verify_config=VerifyCertificatesConfig(
                crl_enabled=True,
            ),
        )
    assert type(exc_info.value.reason) is CrlRevokedError


@pytest.mark.parametrize("url_string", REVOKED_OCSP_URLS)
def test_aia_chase_url_ocsp_revoked(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(CertificateChainError) as exc_info:
        chaser.fetch_ca_chain_for_url(
            url_string=url_string,
            verify_config=VerifyCertificatesConfig(
                ocsp_enabled=True,
            ),
        )
    assert type(exc_info.value.reason) is OcspRevokedStatusError


@pytest.mark.parametrize("url_string", REVOKED_OCSP_URLS)
def test_aia_chase_url_ignore_ocsp_revoked(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_ca_chain_for_url(
        url_string=url_string,
        verify_config=VerifyCertificatesConfig(
            ocsp_enabled=False,
        ),
    )
    assert len(chain) >= 1

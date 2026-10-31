from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

import pytest

from aia_chaser import VerifyCertificatesConfig, verify_certificate_chain
from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    CrlRevokedError,
    OcspRevokedStatusError,
)

from .conftest import EXPIRED_URLS, REVOKED_CRL_URLS, REVOKED_OCSP_URLS, TEST_URLS


if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography import x509

    from aia_chaser import AiaChaser


def _verification_time_for_chain(chain: Sequence[x509.Certificate]) -> dt.datetime:
    """Return a time within the chain's shared validity window, preferring now."""
    valid_from = max(cert.not_valid_before_utc for cert in chain)
    valid_until = min(cert.not_valid_after_utc for cert in chain)
    assert valid_from <= valid_until
    now = dt.datetime.now(dt.timezone.utc)
    return max(valid_from, min(now, valid_until))


def test_trusted_certificates_is_read_only(chaser_certifi: AiaChaser) -> None:
    chaser_certificates = chaser_certifi.trusted_certificates
    with pytest.raises(TypeError):
        chaser_certificates[next(iter(chaser_certificates))] = None  # type: ignore[index]


@pytest.mark.parametrize("url_string", TEST_URLS)
def test_aia_chase_url_ok(url_string: str, chaser_certifi: AiaChaser) -> None:
    chain = chaser_certifi.fetch_cert_chain_for_url(
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
def test_aia_chase_url_no_scheme(url_string: str, chaser_certifi: AiaChaser) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        chaser_certifi.fetch_ca_chain_for_url(url_string=url_string)


@pytest.mark.parametrize("url_string", EXPIRED_URLS)
def test_aia_chase_url_expired(url_string: str, chaser_certifi: AiaChaser) -> None:
    with pytest.raises(CertificateChainError) as exc_info:
        chaser_certifi.fetch_ca_chain_for_url(url_string=url_string)
    assert type(exc_info.value.reason) is CertificateExpiredError


@pytest.mark.parametrize("url_string", EXPIRED_URLS)
def test_aia_chase_url_ignore_expired(
    url_string: str,
    chaser_certifi: AiaChaser,
) -> None:
    chain = chaser_certifi.fetch_ca_chain_for_url(url_string=url_string, verify=False)
    assert len(chain) >= 1


@pytest.mark.parametrize("url_string", REVOKED_CRL_URLS)
def test_aia_chase_url_crl_revoked(url_string: str, chaser_certifi: AiaChaser) -> None:
    with pytest.raises(CertificateChainError) as exc_info:
        chaser_certifi.fetch_ca_chain_for_url(
            url_string=url_string,
            verify_config=VerifyCertificatesConfig(
                crl_enabled=True,
            ),
        )
    assert type(exc_info.value.reason) is CrlRevokedError


@pytest.mark.parametrize("url_string", REVOKED_OCSP_URLS)
def test_aia_chase_url_ocsp_revoked(
    url_string: str,
    chaser_certifi: AiaChaser,
) -> None:
    chain = chaser_certifi.fetch_cert_chain_for_url(
        url_string=url_string,
        verify=False,
    )

    verification_time = _verification_time_for_chain(chain)

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificate_chain(
            certificates=chain,
            trusted=chaser_certifi.trusted_certificates,
            config=VerifyCertificatesConfig(
                ocsp_enabled=True,
                verification_time=verification_time,
            ),
        )
    assert type(exc_info.value.reason) is OcspRevokedStatusError


@pytest.mark.parametrize("url_string", REVOKED_OCSP_URLS)
def test_aia_chase_url_ignore_ocsp_revoked(
    url_string: str,
    chaser_certifi: AiaChaser,
) -> None:
    chain = chaser_certifi.fetch_cert_chain_for_url(
        url_string=url_string,
        verify=False,
    )

    verification_time = _verification_time_for_chain(chain)
    verify_certificate_chain(
        certificates=chain,
        trusted=chaser_certifi.trusted_certificates,
        config=VerifyCertificatesConfig(
            ocsp_enabled=False,
            verification_time=verification_time,
        ),
    )
    assert len(chain) >= 1

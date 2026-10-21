from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

import pytest

from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    CertificateTimeZoneError,
    RootCertificateNotFoundError,
)
from aia_chaser.verify import VerifyCertificatesConfig, verify_certificate_chain


if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography import x509


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

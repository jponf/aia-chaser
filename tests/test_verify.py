import datetime

import pytest

from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateTimeError,
    CertificateTimeZoneError,
    RootCertificateNotTrustedError,
)
from aia_chaser.verify import verify_certificates_chain


def test_verify_chain_of_2_ok(host_and_ca) -> None:
    verify_certificates_chain(host_and_ca)


def test_verify_chain_of_2_wrong_subject(host_and_ca) -> None:
    # By reversing the chain the issued's (host) issuer and
    # the issuer's subject will not match
    reversed_chain = reversed(host_and_ca)
    with pytest.raises(CertificateChainError):
        verify_certificates_chain(reversed_chain)


def test_verify_chain_of_2_wrong_validity_period(host_and_ca) -> None:
    verification_time = datetime.datetime.now(
        datetime.timezone.utc,
    ) - datetime.timedelta(days=1)

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificates_chain(
            host_and_ca,
            verification_time=verification_time,
        )
    assert type(exc_info.value.__cause__) is CertificateTimeError


def test_verify_chain_of_2_offset_naive_validation_time(host_and_ca) -> None:
    verification_time = datetime.datetime.now() - datetime.timedelta(days=1)

    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificates_chain(
            host_and_ca,
            verification_time=verification_time,
        )
    assert type(exc_info.value.__cause__) is CertificateTimeZoneError


def test_verify_chain_of_2_root_not_trusted(host_and_ca) -> None:
    with pytest.raises(CertificateChainError) as exc_info:
        verify_certificates_chain(host_and_ca, trusted={})
    assert type(exc_info.value.__cause__) is RootCertificateNotTrustedError


def test_verify_chain_of_2_root_trusted(host_and_ca) -> None:
    root_ca = host_and_ca[-1]
    verify_certificates_chain(
        host_and_ca,
        trusted={root_ca.subject.rfc4514_string(): root_ca},
    )

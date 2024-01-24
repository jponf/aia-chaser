import contextlib
import datetime
import itertools
from typing import Iterable, Mapping, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateTimeError,
    CertificateTimeZoneError,
    RootCertificateNotTrustedError,
)


def verify_certificates_chain(
    certificates: Iterable[x509.Certificate],
    verification_time: Optional[datetime.datetime] = None,
    trusted: Optional[Mapping[str, x509.Certificate]] = None,
) -> None:
    """Verifies the certificates in the chain.

    The verification checks that each certificate in the sequence
    is signed by the next one and that all are within their validity
    period.

    TODO: Verify OCSP revoked status.

    Args:
        certificates: Chain of certificates starting with the leaf and
            ending in the root CA certificate.
        verification_time: datetime value to validate the certificates
            validity period. If not given uses UTC time.
        trusted: Trusted certificates mapping from subject to certificate.
            If not provided root certificate verification will be skipped.

    Raise:
        CertificateChainError: If a verification error is detected on
            any of the certificates from the chain. Also, it will also
            be raised if trusted is given and it does not contain
            `certificates[-1]`.
    """
    verification_time = verification_time or _get_default_verification_time()
    with contextlib.suppress(StopIteration):
        certificates, ca_certificates = itertools.tee(certificates)
        root_cert = next(ca_certificates)

    chain_index = 0
    try:
        for issued, issuer in zip(certificates, ca_certificates):
            root_cert = issuer

            verify_certificate_validity_period(
                issued,
                verification_time=verification_time,
            )
            issued.verify_directly_issued_by(issuer)
            chain_index += 1

        _verify_root_certificate(
            root_cert.subject.rfc4514_string(),
            trusted=trusted,
            verification_time=verification_time,
        )
    except ValueError as err:
        raise CertificateChainError.from_index_and_reason(
            index=chain_index,
            reason=f"issued issuer name ({issued.issuer}) does not"
            f" match issuer subject ({issuer.subject})",
        ) from err
    except TypeError as err:
        raise CertificateChainError.from_index_and_reason(
            index=chain_index,
            reason=f"issuer does not provide a supported public key [{err}]",
        ) from err
    except (CertificateTimeZoneError, CertificateTimeError) as err:
        raise CertificateChainError.from_index_and_reason(
            index=chain_index,
            reason=str(err),
        ) from err
    except RootCertificateNotTrustedError as err:
        raise CertificateChainError.from_index_and_reason(
            index=chain_index,
            reason=str(err),
        ) from err
    except InvalidSignature as err:
        raise CertificateChainError.from_index_and_reason(
            index=chain_index,
            reason=f"issuer ({issuer.subject}) did not sign certificate"
            f" ({issued.subject})",
        ) from err


def _verify_root_certificate(
    subject: str,
    trusted: Optional[Mapping[str, x509.Certificate]],
    verification_time: Optional[datetime.datetime] = None,
) -> None:
    if trusted is not None:
        if subject not in trusted:
            raise RootCertificateNotTrustedError(
                f"root certificate with subject '{subject}' not in trusted database",
            )

        root_ca = trusted[subject]
        verify_certificate_validity_period(
            root_ca,
            verification_time=verification_time,
        )


def verify_certificate_validity_period(
    certificate: x509.Certificate,
    verification_time: Optional[datetime.datetime] = None,
) -> None:
    """Verify certificate validity period (not valid before/after).

    Args:
        certificate: Certificate to verify.
        verification_time: datetime value to use as reference when
            verifying the validity period. If not given uses UTC time.

    Raises:
        CertificateTimeError: If the certificate is outside its validity
            period.
        CertificateTimeZoneError: If `verification_time` is offset-naive.
    """
    verification_time = verification_time or _get_default_verification_time()

    if verification_time.tzinfo is None:
        raise CertificateTimeZoneError(
            "comparing validity period against offset-naive time is disallowed,"
            " set the offset with `datetime.replace(tzinfo=<timezone>)",
        )

    not_valid_before = _get_not_valid_before(certificate)
    not_valid_after = _get_not_valid_after(certificate)

    if (
        not _get_not_valid_before(certificate)
        <= verification_time
        <= _get_not_valid_after(certificate)
    ):
        raise CertificateTimeError(
            "certificate outside of validity period"
            f" [{not_valid_before}, {not_valid_after}]"
            f" using verification time {verification_time}",
        )


def _get_default_verification_time() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# Since version 42 not_valid_before and not_valid_after are deprecated
# in favor of the offset-aware alternatives not_valid_before_utc and
# not_valid_after_utc.
if hasattr(x509.Certificate, "not_valid_before_utc"):

    def _get_not_valid_before(cert: x509.Certificate) -> datetime.datetime:
        return cert.not_valid_before_utc

    def _get_not_valid_after(cert: x509.Certificate) -> datetime.datetime:
        return cert.not_valid_after_utc

else:

    def _get_not_valid_before(cert: x509.Certificate) -> datetime.datetime:
        return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    def _get_not_valid_after(cert: x509.Certificate) -> datetime.datetime:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

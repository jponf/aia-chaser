from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence

    from cryptography.x509.ocsp import OCSPResponseStatus


class AiaChaserError(Exception):
    """Base exception for aia_chaser errors."""


class MissingPeerCertificateError(AiaChaserError):
    """There is no certificate for the peer on the other end."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(f"could not get certificate for host {host} on port {port}")

        self.host = host
        self.port = port


class CertificateDownloadError(AiaChaserError):
    """Error downloading a certificate."""

    def __init__(
        self,
        message: str,
        url_string: str,
        content_type: str | None = None,
    ) -> None:
        super().__init__(message)
        self.url_string = url_string
        self.content_type = content_type


class CertificateParseError(AiaChaserError):
    """Error parsing a certificate."""

    def __init__(self, reasons: Sequence[str]) -> None:
        super().__init__("could not parse certificate")
        self.reasons = reasons


class NoValidAiaCaUrlError(AiaChaserError):
    """None of the AIA CA URLs is a valid http or https URL.

    Args:
        urls: URLs that were provided to fetch the CA.
    """

    def __init__(self, urls: Sequence[str]) -> None:
        super().__init__(
            f"at least one of the AIA CA urls ({urls}) must be an http or https url",
        )
        self.urls = urls


class AiaChaseExhaustedError(AiaChaserError):
    """Failed to retrieve the issuing CA after exhausting all AIA URLs.

    Arguments:
        errors: A collection of errors encountered while attempting to
            fetch the CA.

    Attributes:
        errors: A collection of errors encountered while attempting to
            fetch the CA.
    """

    def __init__(
        self,
        errors: Sequence[CertificateDownloadError | CertificateParseError],
    ) -> None:
        super().__init__("AIA chasing failed after exhausting all CA urls")
        self.errors = errors


class CertificateVerificationError(AiaChaserError):
    """Base exception for certificate verification errors."""


class CertificateIssuerNameError(CertificateVerificationError):
    """Certificate issuer name does not match issuer's subject.

    Args:
        cert_issuer: Certificate's issuer subject.
        issuer_subject: Issuer's subject.
    """

    def __init__(self, cert_issuer: str, issuer_subject: str) -> None:
        super().__init__(
            f"certificate's issuer name ({cert_issuer}) does not"
            f" match issuer's subject ({issuer_subject})",
        )
        self.cert_issuer = cert_issuer
        self.issuer_subject = issuer_subject


class CertificateKeyTypeError(CertificateVerificationError):
    """Unsupported key type used to sign a certificate.

    Args:
        reason: Message explaining the cause of the error.
    """

    def __init__(self, reason: str) -> None:
        msg = "certificate does not provide a supported public key"
        if reason:
            msg += f" [{reason}]"

        super().__init__(msg)


class CertificateSignatureError(CertificateVerificationError):
    """Issuer's certificate did not sign the certificate.

    Args:
        certificate: Certificate whose signature is being validated.
        issuer: Certificate that should have signed the `certificate`.
    """

    def __init__(self, certificate: str, issuer: str) -> None:
        super().__init__(f"issuer ({issuer}) did not sign certificate ({certificate})")
        self.certificate_name = certificate
        self.issuer_name = issuer


class CertificateIssuerNotTrustedError(CertificateVerificationError):
    """Issuer's certificate cannot be used to verify signature."""

    def __init__(self, issuer: str) -> None:
        super().__init__(
            f"issuer ({issuer}) not found among the trusted certificates",
        )
        self.issuer_name = issuer


class CertificateExpiredError(CertificateVerificationError):
    """Certificate outside its validity period.

    Args:
        not_valid_before: Certificate is not valid before this time.
        not_valid_after: Certificate is not valid after this time.
        verification_time: When the certificate was validated and
            validation failed because it's outside the validity period.
    """

    def __init__(
        self,
        not_valid_before: datetime.datetime,
        not_valid_after: datetime.datetime,
        verification_time: datetime.datetime,
    ) -> None:
        super().__init__(
            "certificate outside of validity period"
            f" [{not_valid_before}, {not_valid_after}]"
            f" using verification time {verification_time}",
        )
        self.not_valid_before = not_valid_after
        self.not_valid_after = not_valid_after
        self.verification_time = verification_time


class CertificateTimeZoneError(CertificateVerificationError):
    """Cannot compare offset-aware and offset-naive times."""

    def __init__(self, message: str | None = None) -> None:
        message = message or (
            "Using offset-naive time is disallowed set the offset with"
            " `datetime.replace(tzinfo=<timezone>) or equivalent"
        )
        super().__init__(message)


class RootCertificateNotFoundError(CertificateVerificationError):
    """Root certificate not in trusted database.

    Args:
        subject: Subject of the certificate not found among the
            trusted certificates.
    """

    def __init__(self, subject: str) -> None:
        super().__init__(
            f"root certificate with subject '{subject}' not in trusted database",
        )


class CertificateFingerprintError(CertificateVerificationError):
    """Certificate fingerprint does not match trusted fingerprint."""

    def __init__(self, fingerprint: bytes, trusted_fingerprint: bytes) -> None:
        super().__init__(
            "certificate fingerprint does not match fingerprint of"
            " certificate in trusted database",
        )
        self.fingerprint = fingerprint
        self.trusted_fingerprint = trusted_fingerprint


class OcspError(CertificateVerificationError):
    """Base exception for OCSP errors."""


class OcspRevokedStatusError(OcspError):
    """OCSP response indicated that certificate has been revoked."""

    def __init__(self, certificate: str) -> None:
        super().__init__(f"OCSP status for {certificate} is REVOKED")


class OcspUnknownStatusError(OcspError):
    """OCSP response indicates that certificate validity is unknown."""

    def __init__(self, certificate: str) -> None:
        super().__init__(f"OCSP status for {certificate} is UNKNOWN")


class OcspHttpError(OcspError):
    """OCSP failed due to an HTTP protocol error.

    Args:
        ocsp_url: OCSP endpoint url.
        http_status: HTTP status indicating the type of error.
    """

    def __init__(self, ocsp_url: str, http_status: int) -> None:
        super().__init__(
            f"HTTP failed with status code {http_status} when "
            f" requesting OCSP status to {ocsp_url}",
        )
        self.ocsp_url = ocsp_url
        self.http_status = http_status


class OcspResponseStatusError(OcspError):
    """OCSP response status is not successful.

    Args:
        status: OCSP response status.
    """

    def __init__(self, status: OCSPResponseStatus) -> None:
        super().__init__(f"OCSP response status was {status}")
        self.status = status


class OcspResponseUnsignedError(OcspError):
    """OCSP response is unsigned."""

    def __init__(self) -> None:
        super().__init__("OCSP response is unsigned this should not happen")


class OcspResponseSignatureError(OcspError):
    """OCSP responder certificate did not sign the response."""

    def __init__(self, responder: str) -> None:
        super().__init__(
            f"responder's certificate {responder} did not sign the OCSP response",
        )
        self.responder = responder


class OcspResponderCertificateError(OcspError):
    """OCSP responder certificate not issued or signed by issuer."""

    def __init__(
        self,
        reason: (
            CertificateIssuerNameError
            | CertificateIssuerNotTrustedError
            | CertificateSignatureError
        ),
    ) -> None:
        super().__init__(f"OCSP certificate error: {reason}")
        self.reason = reason


class CertificateChainError(AiaChaserError):
    """Error detected in a certificates chain of trust."""

    def __init__(
        self,
        index: int,
        reason: CertificateVerificationError | OcspError,
    ) -> None:
        super().__init__(f"certificate at index {index}: {reason}")
        self.reason = reason

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence


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


class CertificateChainError(AiaChaserError):
    """Error detected in a certificates chain of trust."""

    @classmethod
    def from_index_and_reason(cls, index: int, reason: str) -> CertificateChainError:
        """Create exception from given arguments.

        Args:
            index: Index of the offending/failing certificate within
                the chain.
            reason: Description of the error.

        Returns:
            A CertificateChainError with a message constructed from
            `index` and `reason`.
        """
        return CertificateChainError(f"certificate at index {index}: {reason}")


class CertificateTimeError(AiaChaserError):
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


class CertificateTimeZoneError(AiaChaserError):
    """Cannot compare offset-aware and offset-naive times."""

    def __init__(self, message: str | None = None) -> None:
        message = message or (
            "Using offset-naive time is disallowed set the offset with"
            " `datetime.replace(tzinfo=<timezone>) or equivalent"
        )
        super().__init__(message)


class RootCertificateNotTrustedError(AiaChaserError):
    """Root certificate not in trusted database."""

    def __init__(self, subject: str) -> None:
        super().__init__(
            f"root certificate with subject '{subject}' not in trusted database",
        )


class CertificateFingerprintError(AiaChaserError):
    """Certificate fingerprint does not match trusted fingerprint."""

    def __init__(self, fingerprint: bytes, trusted_fingerprint: bytes) -> None:
        super().__init__(
            "certificate fingerprint does not match fingerprint of"
            " certificate in trusted database",
        )
        self.fingerprint = fingerprint
        self.trusted_fingerprint = trusted_fingerprint

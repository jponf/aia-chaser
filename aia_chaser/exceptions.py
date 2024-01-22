from __future__ import annotations


class AiaChaserError(Exception):
    """Base exception for aia_chaser errors."""


class MissingPeerCertificateError(AiaChaserError):
    """There is no certificate for the peer on the other end."""


class CertificateDownloadError(AiaChaserError):
    """Error downloading a certificate."""


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
    """Certificate outside its validity period."""


class RootCertificateNotTrustedError(AiaChaserError):
    """Root certificate not in trusted database."""

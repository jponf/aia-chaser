from __future__ import annotations

import contextlib
import dataclasses
import datetime
import http
import itertools
import secrets
import warnings
from typing import TYPE_CHECKING
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp

from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    CertificateFingerprintError,
    CertificateIssuerNameError,
    CertificateIssuerNotTrustedError,
    CertificateKeyTypeError,
    CertificateSignatureError,
    CertificateTimeZoneError,
    CertificateVerificationError,
    OcspError,
    OcspHttpError,
    OcspResponderCertificateError,
    OcspResponseSignatureError,
    OcspResponseStatusError,
    OcspResponseUnsignedError,
    OcspRevokedStatusError,
    OcspUnknownStatusError,
    RootCertificateNotFoundError,
)
from aia_chaser.utils.cert_utils import (
    extract_aia_information,
    select_rsa_padding_for_signature_algorithm_oid,
)


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


def _get_default_verification_time() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclasses.dataclass
class VerifyCertificatesConfig:
    """Configuration to verify certificates.

    Attributes:
        fingerprint_hash_alg: Hash algorithm used to verify that the
            root certificate from the chain is the same as the one
            found in the trusted certificates. Defaults to `hashes.SHA256`.

        ocsp_enabled: Whether or not perform OCSP validation.
            Defaults to True.
        ocsp_hash_alg: Hash algorithm used to construct OCSP requests.
            Defaults to `hashes.SHA1`.
        ocsp_ignore_unknown: Whether to ignore OCSP's status UNKNOWN or
            consider it a verification error.
            Defaults to True.
        ocsp_verify_responder: Whether to verify responder certificate. See
            [`VerifyOcspConfig`][aia_chaser.verify.VerifyOcspConfig] for more
            details.


        verification_time: Timestamp used to verify certificate validity
            period. Defaults to `datetime.datetime.now(datetime.timezone.utc)`.
    """

    fingerprint_hash_alg: hashes.HashAlgorithm = dataclasses.field(
        default_factory=hashes.SHA256,
    )

    ocsp_enabled: bool = False
    ocsp_hash_alg: hashes.HashAlgorithm = dataclasses.field(
        default_factory=hashes.SHA1,
    )
    ocsp_ignore_unknown: bool = True
    ocsp_verify_responder: bool = True

    verification_time: datetime.datetime = dataclasses.field(
        default_factory=_get_default_verification_time,
    )


def verify_certificate_chain(
    certificates: Iterable[x509.Certificate],
    trusted: Mapping[x509.Name, x509.Certificate] | None = None,
    config: VerifyCertificatesConfig | None = None,
) -> None:
    """Verifies the integrity of the certificates chain.

    The verification checks that each certificate in the sequence
    is signed by the next one and that all are valid certificates.

    Args:
        certificates: Chain of certificates starting with the leaf and
            ending in the root CA certificate.
        trusted: Trusted certificates mapping from subject, formatted as
            rfc4514, to certificate. If not provided root certificate
            verification will be skipped.
        config: Configuration of the verification process.

    Raises:
        CertificateChainError: If a verification error is detected on
            any of the certificates from the chain. It will also
            be raised if trusted is given `certificate[-1]` is not
            contained in it or the fingerprint does not match.
    """
    config = config or VerifyCertificatesConfig()

    with contextlib.suppress(StopIteration):
        certificates, ca_certificates = itertools.tee(certificates)
        root_cert = next(ca_certificates)

    chain_index = 0
    try:
        for issued, issuer in zip(certificates, ca_certificates):
            root_cert = issuer

            verify_certificate_validity_period(
                issued,
                verification_time=config.verification_time,
            )
            verify_directly_issued_by(certificate=issued, issuer=issuer)
            if config.ocsp_enabled:
                verify_ocsp_status(
                    certificate=issued,
                    issuer=issuer,
                    config=VerifyOcspConfig(
                        hash_alg=config.ocsp_hash_alg,
                        ignore_unknown=config.ocsp_ignore_unknown,
                        verify_responder=config.ocsp_verify_responder,
                        trusted=trusted or {},
                    ),
                )

            chain_index += 1

        if trusted is not None:
            verify_root_certificate(
                root_cert,
                hash_alg=config.fingerprint_hash_alg,
                trusted=trusted,
                verification_time=config.verification_time,
            )
    except (CertificateVerificationError, OcspError) as err:
        raise CertificateChainError(index=chain_index, reason=err) from err


def verify_directly_issued_by(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
) -> None:
    """Verifies that a certificate was issued by the provided issuer.

    This function delegates to `x509.Certificate.verify_directly_issued_by`
    to check if the given certificate's issuer matches the provided issuer
    certificate and to validate the issuer's signature. If the check fails,
    specific exceptions are raised to indicate the type of failure.

    Args:
        certificate: The certificate to validate.
        issuer: The certificate of the issuer expected to have issued the
            given certificate.

    Raises:
        CertificateIssuerNameError: If the issuer's subject name does not match
            the certificate's issuer name.
        CertificateSignatureError: If the issuer's signature on the certificate
            is invalid.
    """
    try:
        certificate.verify_directly_issued_by(issuer)
    except TypeError as err:
        raise CertificateKeyTypeError(str(err)) from err
    except ValueError as err:
        raise CertificateIssuerNameError(
            cert_issuer=certificate.subject.rfc4514_string(),
            issuer_subject=issuer.subject.rfc4514_string(),
        ) from err
    except InvalidSignature as err:
        raise CertificateSignatureError(
            certificate=certificate.subject.rfc4514_string(),
            issuer=issuer.subject.rfc4514_string(),
        ) from err


def verify_root_certificate(
    root_cert: x509.Certificate,
    trusted: Mapping[x509.Name, x509.Certificate],
    verification_time: datetime.datetime | None = None,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> None:
    """Verifies the validity of the provided root certificate.

    Args:
        root_cert: Certificate to verify.
        verification_time: datetime value to validate the certificates
            validity period.
            Defaults to `datetime.datetime.now(datetime.timezone.utc)`.
        trusted: Trusted certificates mapping from subject (name) to
            certificate.
        hash_alg: Hashing algorithm used for operations like fingerprint
            comparison, etc. Defaults to SHA-256.

    Raises:
        RootCertificateNotFoundError: If the root certificate cannot
            be found in `trusted`.
        CertificateFingerprintError: If the root certificate fingerprint
            does not match the trusted certificate fingerprint.
    """
    verification_time = verification_time or _get_default_verification_time()
    hash_alg = hash_alg or hashes.SHA256()

    if root_cert.subject not in trusted:
        raise RootCertificateNotFoundError(root_cert.subject.rfc4514_string())

    # Match fingerprint
    trusted_root_ca = trusted[root_cert.subject]
    trusted_root_cert_fp = trusted_root_ca.fingerprint(hash_alg)
    root_cert_fp = root_cert.fingerprint(hash_alg)

    if trusted_root_cert_fp != root_cert_fp:
        raise CertificateFingerprintError(
            fingerprint=root_cert_fp,
            trusted_fingerprint=trusted_root_cert_fp,
        )

    # Verify validity period
    verify_certificate_validity_period(
        root_cert,
        verification_time=verification_time,
    )


def verify_certificate_validity_period(
    certificate: x509.Certificate,
    verification_time: datetime.datetime | None = None,
) -> None:
    """Verifies certificate validity period (not valid before/after).

    Args:
        certificate: Certificate to verify.
        verification_time: datetime value to use as reference when
            verifying the validity period. If not given uses UTC time.

    Raises:
        CertificateExpiredError: If the certificate is outside its validity
            period.
        CertificateTimeZoneError: If `verification_time` is offset-naive.
    """
    verification_time = verification_time or _get_default_verification_time()

    if verification_time.tzinfo is None:
        raise CertificateTimeZoneError

    not_valid_before = _get_not_valid_before(certificate)
    not_valid_after = _get_not_valid_after(certificate)

    if not not_valid_before <= verification_time <= not_valid_after:
        raise CertificateExpiredError(
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            verification_time=verification_time,
        )


######################
# Verify OCSP Status #
######################


@dataclasses.dataclass
class VerifyOcspConfig:
    """Configuration to verify certificates.

    Attributes:
        hash_alg: Hash algorithm used to construct OCSP requests.
            Defaults to `hashes.SHA1`.
        nonce_size: Size in bytes of the OCSP nonce.
        ignore_unknown: Whether to ignore OCSP's status UNKNOWN or
            consider it a verification error.
            Defaults to True.

        verify_responder: Whether to verify responder certificate. If enabled
            there are 3 possibilities:

                1 - Responder and Issuer are the same: Issuer is *trusted*
                    (verifying it should be done by the user using
                    `verify_certificate_chain`) and the response signature
                    is verified with the Issuer certificate.
                2 - Responder certificate is different but is signed by
                    Issuer: The same criteria applies, Issuer is *trusted*
                    and used to verify the responder certificate, which
                    in turn is used to verify the response.
                3 - Responder certificate is different and signed by another
                    certificate: Then a trusted set of certificates is
                    required to verify the certificate.

        trusted: Trusted certificates mapping from subject (name) to
            certificate. If not provided a responder certificate
            verification may fail.
    """

    hash_alg: hashes.HashAlgorithm = dataclasses.field(
        default_factory=hashes.SHA1,
    )
    nonce_size: int = 20
    ignore_unknown: bool = True
    verify_responder: bool = False

    trusted: Mapping[x509.Name, x509.Certificate] = dataclasses.field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:  # noqa: D105
        if self.nonce_size < 1:
            raise ValueError("`nonce_size` must be at least 1")  # noqa: EM101, TRY003


def verify_ocsp_status(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    config: VerifyOcspConfig | None = None,
) -> None:
    """Verifies the status of a certificate using Online Certificate Status Protocol.

    Args:
        certificate: The certificate whose revocation status needs to be
            verified.
        issuer: The issuer certificate that signed the target certificate.
        config: Configuration of the OCSP verification process.

    Raises:
        OcspRevokedStatusError:
            The certificate status is `REVOKED` in the OCSP response.
        OcspUnknownStatusError:
            The certificate status is `UNKNOWN` in the OCSP response
            and `ignore_unknown` is False.
        OcspHttpError:
            An HTTP error happened while requesting the OCSP status.
        OcspResponseStatusError:
            The OCSP response status is not `SUCCESSFUL`.
        OcspResponseUnsignedError:
            The OCSP response is not signed.
        OcspResponseSignatureError:
            The OCSP response is not signed by the responder certificate.
        CertificateKeyTypeError:
            The responder certificate key is not supported.

    Warnings:
        UserWarning:
            A warning is issued if a hash algorithm other than SHA-1 is
            used, as some OCSP servers may not support other hash algorithms
            and may fail with `UNAUTHORIZED` or `MALFORMED` responses.
    """
    config = config or VerifyOcspConfig()

    aia_info = extract_aia_information(certificate)
    nonce = secrets.token_bytes(config.nonce_size)

    if config.hash_alg.name.lower() != "sha1":
        warnings.warn(
            "Some OCSP servers may fail with UNAUTHORIZED or MALFORMED "
            " responses if request hash is different than SHA1",
            category=UserWarning,
            stacklevel=2,
        )

    if aia_info.ocsp_urls:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(certificate, issuer, config.hash_alg)
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        ocsp_request = builder.build()

        for ocsp_url in aia_info.ocsp_urls:
            last_status = _run_ocsp_request(
                ocsp_request=ocsp_request,
                ocsp_url=ocsp_url,
                issuer=issuer,
                config=config,
            )
            if last_status == ocsp.OCSPCertStatus.REVOKED:
                raise OcspRevokedStatusError(certificate.subject.rfc4514_string())
            if last_status == ocsp.OCSPCertStatus.UNKNOWN and not config.ignore_unknown:
                raise OcspUnknownStatusError(certificate.subject.rfc4514_string())


def _run_ocsp_request(
    ocsp_request: ocsp.OCSPRequest,
    ocsp_url: str,
    issuer: x509.Certificate,
    config: VerifyOcspConfig,
) -> ocsp.OCSPCertStatus:
    http_request = Request(  # noqa: S310
        url=ocsp_url,
        data=ocsp_request.public_bytes(serialization.Encoding.DER),
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )

    with urlopen(http_request) as response:  # noqa: S310
        if response.status != http.HTTPStatus.OK:
            raise OcspHttpError(ocsp_url=ocsp_url, http_status=response.status)
        ocsp_response_data = response.read()

    ocsp_resp = ocsp.load_der_ocsp_response(ocsp_response_data)
    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise OcspResponseStatusError(ocsp_resp.response_status)

    all_responses = list(ocsp_resp.responses)
    if len(all_responses) != 1:
        raise OcspError("exactly one response is expected")  # noqa: EM101, TRY003
    single_response = all_responses[0]

    # Verify response signature
    if ocsp_resp.signature_hash_algorithm is None:
        raise OcspResponseUnsignedError

    responder_cert = _get_ocsp_responder_certificate(
        ocsp_response=ocsp_resp,
        issuer=issuer,
    )
    try:
        _verify_ocsp_responder_certificate(
            responder_cert=responder_cert,
            issuer=issuer,
            config=config,
        )
    except (
        CertificateIssuerNameError,
        CertificateIssuerNotTrustedError,
        CertificateSignatureError,
    ) as err:
        raise OcspResponderCertificateError(err) from err

    responder_key = responder_cert.public_key()

    try:
        if isinstance(responder_key, rsa.RSAPublicKey):
            responder_key.verify(
                signature=ocsp_resp.signature,
                data=ocsp_resp.tbs_response_bytes,
                padding=select_rsa_padding_for_signature_algorithm_oid(
                    signature_alg_oid=ocsp_resp.signature_algorithm_oid,
                    signature_hash_alg=ocsp_resp.signature_hash_algorithm,
                ),
                algorithm=ocsp_resp.signature_hash_algorithm,
            )
        elif isinstance(responder_key, ec.EllipticCurvePublicKey):
            responder_key.verify(
                signature=ocsp_resp.signature,
                data=ocsp_resp.tbs_response_bytes,
                signature_algorithm=ec.ECDSA(
                    ocsp_resp.signature_hash_algorithm,
                ),
            )
        else:
            raise CertificateKeyTypeError(
                reason=f"unsupported key type {type(responder_key)}",
            )
    except InvalidSignature:
        raise OcspResponseSignatureError(
            responder_cert.subject.rfc4514_string(),
        ) from None

    # Check certificate status
    return single_response.certificate_status


def _get_ocsp_responder_certificate(
    ocsp_response: ocsp.OCSPResponse,
    issuer: x509.Certificate,
) -> x509.Certificate:
    # We only request OCSP of a single certificate so the response
    # should only contain one responder certificate, if any.
    if ocsp_response.certificates:
        return ocsp_response.certificates[0]

    # Fallback to issuer as responder
    return issuer


def _verify_ocsp_responder_certificate(
    responder_cert: x509.Certificate,
    issuer: x509.Certificate,
    config: VerifyOcspConfig,
) -> None:
    if config.verify_responder and responder_cert != issuer:
        responder_issuer = (
            issuer
            if responder_cert.issuer == issuer.subject
            else config.trusted.get(responder_cert.issuer)
        )
        if responder_issuer is not None:
            verify_directly_issued_by(
                certificate=responder_cert,
                issuer=responder_issuer,
            )
        else:
            raise CertificateIssuerNotTrustedError(
                issuer=responder_cert.issuer.rfc4514_string(),
            )


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

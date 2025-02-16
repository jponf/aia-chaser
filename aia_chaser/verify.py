from __future__ import annotations

import contextlib
import datetime
import http
import itertools
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp

from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateFingerprintError,
    CertificateTimeError,
    CertificateTimeZoneError,
    RootCertificateNotFoundError,
)
from aia_chaser.utils.cert_utils import (
    extract_aia_information,
    select_padding_from_signature_algorithm_oid,
)


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cryptography.hazmat.primitives.asymmetric.types import (
        CertificatePublicKeyTypes,
    )


def verify_certificates_chain(
    certificates: Iterable[x509.Certificate],
    verification_time: datetime.datetime | None = None,
    trusted: Mapping[str, x509.Certificate] | None = None,
    hash_alg: hashes.HashAlgorithm | None = None,
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
        trusted: Trusted certificates mapping from subject, formatted as
            rfc4514, to certificate. to certificate. If not provided root
            certificate verification will be skipped.
        hash_alg: Hashing algorithm used for operations like fingerprint
            comparison, etc. Defaults: to SHA-256.

    Raise:
        CertificateChainError: If a verification error is detected on
            any of the certificates from the chain. Also, it will also
            be raised if trusted is given and it does not contain
            `certificates[-1]`.
    """
    verification_time = verification_time or _get_default_verification_time()
    hash_alg = hash_alg or hashes.SHA256()

    with contextlib.suppress(StopIteration):
        certificates, ca_certificates = itertools.tee(certificates)
        root_cert = next(ca_certificates)

    chain_index = 0
    try:
        for issued, issuer in zip(certificates, ca_certificates):
            root_cert = issuer

            with open("issued.crt", "wb") as fh:
                fh.write(issued.public_bytes(serialization.Encoding.DER))
            with open("issuer.crt", "wb") as fh:
                fh.write(issuer.public_bytes(serialization.Encoding.DER))

            verify_certificate_validity_period(
                issued,
                verification_time=verification_time,
            )
            issued.verify_directly_issued_by(issuer)
            verify_ocsp_status(issued, issuer)  # , hash_alg)

            chain_index += 1

        if trusted is not None:
            verify_root_certificate(
                root_cert,
                hash_alg=hash_alg,
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
    except RootCertificateNotFoundError as err:
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


def verify_root_certificate(
    root_cert: x509.Certificate,
    trusted: Mapping[str, x509.Certificate],
    verification_time: datetime.datetime | None = None,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> None:
    """Verifies the validity of the provided root certificate.

    Args:
        root_cert: Certificate to verify.
        verification_time: datetime value to validate the certificates
            validity period. If not given uses UTC time.
        trusted: Trusted certificates mapping from subject, formatted as
            rfc4514, to certificate.
        hash_alg: Hashing algorithm used for operations like fingerprint
            comparison, etc. Defaults: to SHA-256.

    Raises:
        RootCertificateNotFoundError: If the root certificate cannot
            be found in `trusted`.
        CertificateFingerprintError: If the root certificate fingerprint
            does not match the trusted certificate fingerprint.
    """
    verification_time = verification_time or _get_default_verification_time()
    hash_alg = hash_alg or hashes.SHA256()

    root_cert_subject = root_cert.subject.rfc4514_string()
    if root_cert_subject not in trusted:
        raise RootCertificateNotFoundError(root_cert_subject)

    # Match fingerprint
    trusted_root_ca = trusted[root_cert_subject]
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


def verify_ocsp_status(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    # hash_alg: hashes.HashAlgorithm | None = None,
) -> ocsp.OCSPSingleResponse:
    aia_info = extract_aia_information(certificate)
    nonce = secrets.token_bytes(24)

    if aia_info.ocsp_urls:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(certificate, issuer, hashes.SHA1())
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        ocsp_request = builder.build()

        for ocsp_url in aia_info.ocsp_urls:
            _run_ocsp_request(
                ocsp_request=ocsp_request,
                ocsp_url=ocsp_url,
                issuer_key=issuer.public_key(),
            )


def _run_ocsp_request(
    ocsp_request: ocsp.OCSPRequest,
    ocsp_url: str,
    issuer_key: CertificatePublicKeyTypes,
) -> ocsp.OCSPCertStatus:
    http_request = Request(  # noqa: S310
        url=ocsp_url,
        data=ocsp_request.public_bytes(serialization.Encoding.DER),
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )

    with urlopen(http_request) as response:  # noqa: S310
        if response.status != http.HTTPStatus.OK:
            raise Exception("http status error")
        ocsp_response_data = response.read()

    ocsp_resp = ocsp.load_der_ocsp_response(ocsp_response_data)
    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise Exception(f"OCSP response was not successful {ocsp_resp.response_status}")

    all_responses = list(ocsp_resp.responses)
    if len(all_responses) != 1:
        raise ValueError("exactly one response is expected")
    single_response = all_responses[0]

    # Verify response signature
    padding_scheme = select_padding_from_signature_algorithm_oid(
        signature_alg_oid=ocsp_resp.signature_algorithm_oid,
        signature_hash_alg=ocsp_resp.signature_hash_algorithm,
    )

    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            issuer_key.verify(
                signature=ocsp_resp.signature,
                data=ocsp_resp.tbs_response_bytes,
                padding=padding_scheme,
                algorithm=ocsp_resp.signature_hash_algorithm,
            )
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(
                signature=ocsp_resp.signature,
                data=ocsp_resp.tbs_response_bytes,
                signature_algorithm=ec.ECDSA(ocsp_resp.signature_hash_algorithm),
            )
        else:
            raise Exception("Unsupported public key type")
    except InvalidSignature as err:
        raise Exception(f"OCSP signature {err}")

    # Check certificate status
    return single_response


def verify_certificate_validity_period(
    certificate: x509.Certificate,
    verification_time: datetime.datetime | None = None,
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
        raise CertificateTimeZoneError

    not_valid_before = _get_not_valid_before(certificate)
    not_valid_after = _get_not_valid_after(certificate)

    if not not_valid_before <= verification_time <= not_valid_after:
        raise CertificateTimeError(
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            verification_time=verification_time,
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

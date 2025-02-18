from __future__ import annotations

import ssl
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding


if TYPE_CHECKING:
    from cryptography.hazmat.primitives import hashes


def certificates_to_der(certificates: list[x509.Certificate]) -> bytes:
    """DER representation of the given certificates."""
    return b"".join(cert.public_bytes(Encoding.DER) for cert in certificates)


def certificates_to_pem(certificates: list[x509.Certificate]) -> str:
    """PEM representation of the given certificates."""
    return "\n".join(
        cert.public_bytes(Encoding.PEM).decode("ascii") for cert in certificates
    )


def force_load_default_verify_certificates(context: ssl.SSLContext) -> None:
    """Forcefully load default verify certificates into the SSL context.

    Certificates in CA path directory are not loaded unless they
    have been used at leas one by the SSL context.

    This function loads all files located CA path, except those
    that are considered hidden files (start with a '.').

    Args:
        context: The SSL context to load the verify certificates into.
    """
    # Expected way to load default certificates
    context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)

    # Forcefully load files in CA path (this solution may not work on Windows
    ssl_defaults = ssl.get_default_verify_paths()

    if ssl_defaults.capath is not None:
        ca_files = filter(
            lambda ca_file: ca_file.is_file() and not ca_file.name.startswith("."),
            Path(ssl_defaults.capath).iterdir(),
        )
        # Note: We found that some ssl installations have files that
        # are not cert, i.e., homebrew's openssl has a .keepme. For now
        # we ignore files that start with '.' but a try except might
        # be necessary ¯\_(ツ)_/¯
        for ca_file in ca_files:
            context.load_verify_locations(ca_file)


class AiaInformation(NamedTuple):
    """Authority Information Access (AIA) values."""

    ca_issuers: list[str]
    ocsp_urls: list[str]


def extract_aia_information(
    certificate: x509.Certificate,
) -> AiaInformation:
    """Extract authority information access (AIA) from a certificate.

    Args:
        certificate: Certificate from which extract AIA information.

    Returns:
        The extracted CA issues and OCSP servers in an `AiaInformation`
        instance.

    Note:
        If the certificate does not have the AIA extension this function
        does not fail, it fallbacks to returning empty sequences of data.
    """
    try:
        aia_extension = cast(
            x509.Extension[x509.AuthorityInformationAccess],
            certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            ),
        )
    except x509.ExtensionNotFound:
        return AiaInformation([], [])

    ca_issuers = [
        aia_entry.access_location.value
        for aia_entry in aia_extension.value
        if aia_entry.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS
    ]
    ocsp_urls = [
        aia_entry.access_location.value
        for aia_entry in aia_extension.value
        if aia_entry.access_method == x509.AuthorityInformationAccessOID.OCSP
    ]

    return AiaInformation(ca_issuers=ca_issuers, ocsp_urls=ocsp_urls)


_PADDING_PKCS1V15_OIDS = (
    x509.SignatureAlgorithmOID.RSA_WITH_MD5,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA1,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA224,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA256,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA384,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA3_224,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA3_256,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA3_384,
    x509.SignatureAlgorithmOID.RSA_WITH_SHA3_512,
)


def select_rsa_padding_for_signature_algorithm_oid(
    signature_alg_oid: x509.ObjectIdentifier,
    signature_hash_alg: hashes.HashAlgorithm | None,
) -> padding.AsymmetricPadding:
    """Select padding for a given signature algorithm OID."""
    if signature_alg_oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
        if signature_hash_alg is None:
            msg = "RSASSA-PSS signature requires a hash algorithm"
            raise ValueError(msg)

        return padding.PSS(
            mgf=padding.MGF1(signature_hash_alg),
            salt_length=padding.PSS.MAX_LENGTH,
        )
    if signature_alg_oid in _PADDING_PKCS1V15_OIDS:
        return padding.PKCS1v15()

    msg = f"unknown padding for signature algorithm oid {signature_alg_oid}"
    raise ValueError(msg)

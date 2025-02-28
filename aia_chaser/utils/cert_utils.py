from __future__ import annotations

import collections
import contextlib
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from cryptography.hazmat.primitives import hashes


def certificates_to_der(certificates: list[x509.Certificate]) -> bytes:
    """DER representation of the given certificates.

    Returns:
        A bytes object with the DER content of `certificates`.
    """
    return b"".join(cert.public_bytes(Encoding.DER) for cert in certificates)


def certificates_to_pem(certificates: list[x509.Certificate]) -> str:
    """PEM representation of the given certificates.

    Returns:
        A string with the PEM content of `certificates`.
    """
    return "\n".join(
        cert.public_bytes(Encoding.PEM).decode("ascii") for cert in certificates
    )


def load_ssl_ca_certificates(
    context: ssl.SSLContext | None = None,
    *,
    force_load: bool = True,
) -> list[x509.Certificate]:
    """Load CA certificates available to Python's `ssl`.

    Args:
        context: The SSL context used to get the default certificates.
            If not provided a default context is created with
            `ssl.SSLContext()`.
        force_load: Forcefully load default certificates into the SSL
            context. Certificates in CA path directory are not loaded
            unless they have been used at leas one by the SSL context.

            For more information see
            [`force_load_default_verify_certificates`][aia_chaser.utils.cert_utils.force_load_default_verify_certificates].

    Returns:
        A list with the CA certificates from `context`.
    """
    context = context or ssl.SSLContext()
    context = ssl.SSLContext()
    if force_load:
        force_load_default_verify_certificates(context)

    # Load trusted certificates
    trusted_der = context.get_ca_certs(True)  # noqa: FBT003
    return list(map(x509.load_der_x509_certificate, trusted_der))


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
        # Note: We found that some ssl installations have files that
        #   are not cert, i.e., homebrew's openssl has a .keepme. For now
        # we ignore files that start with '.' but a try except might
        # be necessary ¯\_(ツ)_/¯
        ca_files = (
            ca_file
            for ca_file in Path(ssl_defaults.capath).iterdir()
            if ca_file.is_file() and not ca_file.name.startswith(".")
        )

        for ca_file in ca_files:
            with contextlib.suppress(ssl.SSLError):
                context.load_verify_locations(ca_file)


def find_leaf_certificates(
    certificates: Sequence[x509.Certificate],
) -> list[x509.Certificate]:
    """Finds leaf certificates.

    A certificate is considered a leaf certificate if its subject
    is not found as the issuer of another certificate from the list.

    Returns:
        List with the certificates that are not issuers of any of the
            other provided certificates.
    """
    graph = collections.defaultdict(list)
    for cert in certificates:
        graph[cert.issuer].append(cert.subject)

    return [
        cert
        for cert in certificates
        if cert.subject not in graph or not graph[cert.subject]
    ]


def build_certificate_chain(
    leaf_cert: x509.Certificate,
    certs_map: Mapping[x509.Name, x509.Certificate],
) -> list[x509.Certificate]:
    """Builds a certificate chain from the `leaf_cert` to the root CA.

    Args:
        leaf_cert: Leaf certificate of the chain.
        certs_map: Mapping from `x509.Certificate.subject` to `x509.Certificate`.

    Returns:
        A certificate chain starting at `leaf_cert` and ending in root CA.

    Raises:
        KeyError: An issuer is not found in `certs_map`.
    """
    chain = [leaf_cert]

    while chain[-1].subject != chain[-1].issuer:
        chain.append(certs_map[chain[-1].issuer])

    return chain


def build_certificate_chains(
    certificates: Sequence[x509.Certificate],
) -> list[list[x509.Certificate]]:
    """Builds all certificate chains found in `certificates`.

    First it looks for all leaf certificates using
    [`find_leaf_certificates`][aia_chaser.utils.cert_utils.find_leaf_certificates]
    and then builds the chains starting at each leaf using
    [`build_certificate_chain`][aia_chaser.utils.cert_utils.build_certificate_chain].

    Returns:
        All certificate chains found in `certificates` each starting at
            its corresponding leaf certificate.
    """
    leaves = find_leaf_certificates(certificates)
    certs_map = {cert.subject: cert for cert in certificates}

    return [
        build_certificate_chain(
            leaf_cert=leaf,
            certs_map=certs_map,
        )
        for leaf in leaves
    ]


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
        The extracted CA issues and OCSP servers.

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

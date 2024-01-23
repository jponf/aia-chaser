import contextlib
import functools
import socket
import ssl
import warnings
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Tuple, cast
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from aia_chaser.constants import (
    DEFAULT_URLOPEN_TIMEOUT,
    DOWNLOAD_CACHE_SIZE,
    X509_CERTIFICATE_MIME,
    HttpHeader,
)
from aia_chaser.exceptions import (
    CertificateDownloadError,
    MissingPeerCertificateError,
    RootCertificateNotTrustedError,
)
from aia_chaser.utils.url import extract_host_port_from_url
from aia_chaser.verify import verify_certificates_chain


__all__ = ["AiaChaser"]


class CertificatesChain(List[x509.Certificate]):
    """Specialized list for x509 certificates."""

    def to_der(self) -> bytes:
        """DER representation of the certificates chain."""
        return b"".join(cert.public_bytes(Encoding.DER) for cert in self)

    def to_pem(self) -> str:
        """PEM representation of the certificates chain."""
        return "\n".join(
            cert.public_bytes(Encoding.PEM).decode("ascii") for cert in self
        )


class AiaChaser(object):
    """Authority Information Access (AIA) Chaser.

    AIA is part of the X509 standard in RFC 5280. It's objective
    is pointing the client towards an endpoint from which the
    signing certificate can be obtained even if the server does
    not provide the intermediate certificates as part of the
    TLS handshake.

    The chaser object can be later used to generate SSL context
    to access specific hosts after all the intermediate certificates
    have been resolved.

    Args:
        context: Context used internally to request the host's certificate
            during AIA chasing operations. Its loaded CA certificates at
            the time of crating the `AiaChaser` are considered the trusted
            root CAs. If not given a new SSLContext is created with the
            default certificates.
    """

    def __init__(self, context: Optional[ssl.SSLContext] = None) -> None:
        self._context = context or ssl.SSLContext()
        if not context:
            _load_default_certificates(self._context)

        # Load trusted certificates
        trusted_der = list(self._context.get_ca_certs(True))
        trusted_cert = list(map(x509.load_der_x509_certificate, trusted_der))

        self._trusted = {
            ca_cert.subject.rfc4514_string(): ca_cert for ca_cert in trusted_cert
        }

    def aia_chase(self, host: str, port: int = 443) -> Iterator[x509.Certificate]:
        """Generates a certificate chain from host to root certificate.

        Args:
            host: Host to generate the certificate chain for.
            port: Port on host to connect and retrieve the initial
                certificate.

        Yields:
            The certificates from the certificate chain, starting at host.
        """
        cert = self.fetch_host_cert(host=host, port=port)
        while True:
            cert_info = _extract_aia_info(cert)

            # Already trusted & self-signed
            #
            # Running until the end of some chains end up in "ValiCert Class 2
            # Policy Validation Authority", which are not in the system's
            # trusted database:
            # https://security.stackexchange.com/questions/65508/what-is-the-deal-with-valicert-ssl-root-certificates
            #
            # This may happen with other certificate chains thereby we stop
            # the chasing once we find a certificate that we already trust.
            if cert_info.subject in self._trusted:
                yield self._trusted[cert_info.subject]
                break
            if cert_info.subject == cert_info.issuer:
                if cert_info.issuer not in self._trusted:
                    raise RootCertificateNotTrustedError(
                        f"root certificate {cert_info.issuer} not in "
                        "trusted database",
                    )
                yield self._trusted[cert_info.issuer]
                break

            # Yield and continue AIA chasing
            yield cert

            # No more intermediate CAs, issuer must be trusted
            if not cert_info.aia_ca_issuers:
                if cert_info.issuer not in self._trusted:
                    raise RootCertificateNotTrustedError(
                        f"root certificate {cert_info.issuer} not in "
                        "trusted database",
                    )
                yield self._trusted[cert_info.issuer]
                break

            ca_url = cert_info.aia_ca_issuers[0]
            cert = _download_certificate(ca_url)

    def fetch_host_cert(self, host: str, port: int = 443) -> x509.Certificate:
        """Get the host, port pair certificate.

        Args:
            host: Host to retrieve the certificate for.
            port: Port on host to connect and retrieve the certificate.

        Returns:
            The certificate of the (host, port) pair.
        """
        with contextlib.ExitStack() as ctx:
            sock = ctx.enter_context(socket.create_connection((host, port)))
            s_sock = ctx.enter_context(
                self._context.wrap_socket(
                    sock,
                    server_hostname=host,
                ),
            )

            # Get initial, possibly incomplete, chain from peer once the
            # functionality is supported by ssl module
            # https://www.openssl.org/docs/man1.0.2/man3/SSL_get_peer_cert_chain.html
            der_cert = s_sock.getpeercert(True)
            if der_cert is not None:
                return x509.load_der_x509_certificate(der_cert)

        raise MissingPeerCertificateError(
            f"could not get certificate for host {host} on port {port}",
        )

    def fetch_ca_chain_for_host(
        self,
        host: str,
        port: int = 443,
    ) -> CertificatesChain:
        """Get the CA certification chain excluding the leaf node.

        Args:
            host: Host (leaf node) to get the CA certification chain for.
            port: Port on host to connect and retrieve the initial
                certificate.

        Returns:
            List of CA certificates that verify host's certificate.
        """
        certificates = list(self.aia_chase(host, port))[1:]
        verify_certificates_chain(
            certificates=certificates,
            trusted=self._trusted,
        )
        return CertificatesChain(certificates)

    def fetch_ca_chain_for_url(
        self,
        url_string: str,
    ) -> CertificatesChain:
        """Get the CA certification chain excluding the leaf node.

        Same as `get_ca_chain_for_host` but the host name is obtained
        from `url_string`.

        Args:
            url_string: URL for which to get the CA certification chain.

        Returns:
            List of CA certificates that verify the URL's host certificate.
        """
        host, port = extract_host_port_from_url(url_string)
        return self.fetch_ca_chain_for_host(host=host, port=port)

    def make_ssl_context_for_host(
        self,
        host: str,
        port: int = 443,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificates chain for host."""
        context = ssl.create_default_context(purpose=purpose)
        self.add_host_ca_chain_to_context(context, host, port)
        return context

    def make_ssl_context_for_url(
        self,
        url_string: str,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificates chain for URL."""
        context = ssl.create_default_context(purpose=purpose)
        self.add_url_ca_chain_to_context(context, url_string=url_string)
        return context

    def add_host_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        host: str,
        port: int = 443,
    ) -> None:
        """Add host CA chain to SSL context."""
        certificates = self.fetch_ca_chain_for_host(host, port)
        context.load_verify_locations(cadata=certificates.to_der())

    def add_url_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        url_string: str,
    ) -> None:
        """Add CA chain to URL's host to SSL context."""
        certificates = self.fetch_ca_chain_for_url(url_string)
        context.load_verify_locations(cadata=certificates.to_der())


@functools.lru_cache(maxsize=DOWNLOAD_CACHE_SIZE)
def _download_certificate(url_string: str) -> x509.Certificate:
    if url_string.startswith("https:"):
        warnings.warn(
            "Trying to download an intermediate CA certificate using HTTPS",
            category=UserWarning,
            stacklevel=2,
        )
    elif not url_string.startswith("http:"):
        raise CertificateDownloadError("URL scheme must be http or https")

    with urlopen(  # noqa: S310
        url_string,
        timeout=DEFAULT_URLOPEN_TIMEOUT,
    ) as response:
        if response.status != 200:
            raise CertificateDownloadError(f"could not download {url_string}")

        content_type = response.headers.get(HttpHeader.CONTENT_TYPE, "")
        if content_type in X509_CERTIFICATE_MIME:
            return _try_parse_certificate(response.read())

    raise CertificateDownloadError(
        f"unknown Content-Type '{content_type}' for {url_string}",
    )


def _try_parse_certificate(data: bytes) -> x509.Certificate:
    parse_fns = [x509.load_der_x509_certificate, x509.load_pem_x509_certificate]
    exceptions = []
    for parse_fn in parse_fns:
        try:
            return parse_fn(data)
        except Exception as err:
            exceptions.append(err)

    raise CertificateDownloadError(*exceptions)


class _CertificateAiaInfo(NamedTuple):
    """Simpler format to work with  certificate info."""

    subject: str
    issuer: str
    aia_ca_issuers: List[str]
    aia_ocsp_servers: List[str]


def _extract_aia_information(
    x509_certificate: x509.Certificate,
) -> Tuple[List[str], List[str]]:
    try:
        aia_extension = cast(
            x509.Extension[x509.AuthorityInformationAccess],
            x509_certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            ),
        )
    except x509.ExtensionNotFound:
        return [], []

    ca_issuers = [
        aia_entry.access_location.value
        for aia_entry in aia_extension.value
        if aia_entry.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS
    ]
    ocsp_servers = [
        aia_entry.access_location.value
        for aia_entry in aia_extension.value
        if aia_entry.access_method == x509.AuthorityInformationAccessOID.OCSP
    ]

    return ca_issuers, ocsp_servers


def _extract_aia_info(x509_certificate: x509.Certificate) -> _CertificateAiaInfo:
    ca_issuers, ocsp_servers = _extract_aia_information(x509_certificate)
    return _CertificateAiaInfo(
        subject=x509_certificate.subject.rfc4514_string(),
        issuer=x509_certificate.issuer.rfc4514_string(),
        aia_ca_issuers=ca_issuers,
        aia_ocsp_servers=ocsp_servers,
    )


def _load_default_certificates(context: ssl.SSLContext) -> None:
    # Expected way to load default certificates
    context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)

    # Note:
    # Certificates in a capath directory aren't loaded unless they have
    # been used at least once.
    #
    # To avoid an empty list of trusted certificates when a cafile does
    # not exist and also to avoid missing certificates that only exist
    # in capath, let's forcefully load them (this solution may not work
    # on Windows):
    ssl_defaults = ssl.get_default_verify_paths()
    if ssl_defaults.capath is not None:
        ca_files = filter(
            lambda ca_file: ca_file.is_file(),
            Path(ssl_defaults.capath).iterdir(),
        )
        for ca_file in ca_files:
            context.load_verify_locations(ca_file)

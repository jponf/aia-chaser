from __future__ import annotations

import contextlib
import functools
import http
import socket
import ssl
import warnings
from typing import TYPE_CHECKING, NamedTuple
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from aia_chaser.constants import DEFAULT_URLOPEN_TIMEOUT, DOWNLOAD_CACHE_SIZE
from aia_chaser.exceptions import (
    AiaChaseExhaustedError,
    CertificateDownloadError,
    CertificateParseError,
    MissingPeerCertificateError,
    NoValidAiaCaUrlError,
    RootCertificateNotFoundError,
)
from aia_chaser.utils.cert_utils import (
    certificates_to_der,
    extract_aia_information,
    load_ssl_ca_certificates,
)
from aia_chaser.utils.url import extract_host_port_from_url
from aia_chaser.verify import VerifyCertificatesConfig, verify_certificate_chain


if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


__all__ = ["AiaChaser"]


class AiaChaser:
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
        trusted_ca: Additional trusted CA certificates.
    """

    def __init__(
        self,
        context: ssl.SSLContext | None = None,
        trusted_cas: Sequence[x509.Certificate] | None = None,
    ) -> None:
        trusted_cas = trusted_cas or []

        self._context = context or ssl.SSLContext()

        # Load trusted certificates
        ssl_trusted_cert = load_ssl_ca_certificates(
            self._context,
            force_load=context is None,
        )

        self._trusted = {ca_cert.subject: ca_cert for ca_cert in ssl_trusted_cert}
        for cert in trusted_cas:
            self.add_trusted_cert(cert)  # self._context and self._trusted must exist

    def add_trusted_cert(self, cert: x509.Certificate) -> None:
        """Trust the provided certificate.

        If the certificate subject already exists in the trusted mapping
        it will not be overwritten.

        Args:
            cert: Certificate to trust.
        """
        if cert.subject not in self._trusted:
            self._context.load_verify_locations(
                cadata=cert.public_bytes(Encoding.DER),
            )
            self._trusted[cert.subject] = cert

    def aia_chase_cert(
        self,
        certificate: x509.Certificate,
    ) -> Iterator[x509.Certificate]:
        """Chase AIA CA information from the provided certificate.

        Args:
            certificate: Start AIA chasing from this certificate.

        Yields:
            The certificates from the certificate chain of
                `certificate`. The first is the provided
                certificate and the last is the root or a
                trusted CA.
        """
        cert = certificate
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
                    raise RootCertificateNotFoundError(
                        subject=cert_info.issuer.rfc4514_string(),
                    )
                yield self._trusted[cert_info.issuer]
                break

            # Yield and continue AIA chasing
            yield cert

            # No more intermediate CAs, issuer must be trusted
            if not cert_info.aia_ca_issuers:
                if cert_info.issuer not in self._trusted:
                    raise RootCertificateNotFoundError(
                        subject=cert_info.issuer.rfc4514_string(),
                    )
                yield self._trusted[cert_info.issuer]
                break

            cert = _try_download_certificate(cert_info.aia_ca_issuers)

    def aia_chase(
        self,
        host: str,
        port: int = 443,
    ) -> Iterator[x509.Certificate]:
        """Chase AIA CA information starting from the `host`'s certificate.

        Args:
            host: Host to get the initial certificate.
            port: Port on host to connect and retrieve the initial
                certificate.

        Yields:
            The certificates from the certificate chain of the
                host's certificate. The first is the host's
                certificate and the last is the root or a
                trusted CA.
        """
        cert = self.fetch_host_cert(host=host, port=port)
        yield from self.aia_chase_cert(certificate=cert)

    def fetch_host_cert(self, host: str, port: int = 443) -> x509.Certificate:
        """Get the host, port pair certificate.

        Args:
            host: Host to retrieve the certificate for.
            port: Port on host to connect and retrieve the certificate.

        Returns:
            The certificate of the (host, port) pair.

        Raises:
            MissingPeerCertificateError: If it is not possible to retrieve
                the certificate of the `host`.
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
            der_cert = s_sock.getpeercert(True)  # noqa: FBT003
            if der_cert is not None:
                return x509.load_der_x509_certificate(der_cert)

        raise MissingPeerCertificateError(host=host, port=port)

    def fetch_cert_chain_for_host(
        self,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the certificate chain for a given host.

        Retrieves the certificate chain for a specified host and port.
        Optionally verifies the chain against a trusted certificate store.

        Args:
            host: The hostname to fetch the certificate chain for.
            port: The port to connect to. Defaults to 443.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration is used.
            verify: Whether to verify the certificate chain. Defaults to True.

        Returns:
            The fetched certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the `host`.
        """
        certificates = list(self.aia_chase(host, port))
        if verify:
            verify_certificate_chain(
                certificates=certificates,
                trusted=self._trusted,
                config=verify_config or VerifyCertificatesConfig(),
            )
        return certificates

    def fetch_ca_chain_for_host(
        self,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the CA certificate chain for a given host.

        Same as
        [`fetch_cert_chain_for_host`][aia_chaser.AiaChaser.fetch_cert_chain_for_host]
        excluding the host's certificate.

        Args:
            host: The hostname to fetch the CA certificate chain for.
            port: The port to connect to. Defaults to 443.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration is used.
            verify: Whether to verify the CA certificate chain. Defaults to True.

        Returns:
            The fetched CA certificate chain (host excluded), optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the `host`.
        """
        return self.fetch_cert_chain_for_host(
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )[:1]

    def fetch_cert_chain_for_url(
        self,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the certificate chain for a given host.

        Same as `fetch_cert_chain_for_host` but the host name and port
        are obtained from the `url_string`

        Args:
            url_string: URL to fetch the certificate chain for.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration is used.
            verify: Whether to verify the certificate chain. Defaults to True.

        Returns:
            The fetched certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the host.
        """
        host, port = extract_host_port_from_url(url_string)
        return self.fetch_cert_chain_for_host(
            host=host,
            port=port,
            verify_config=verify_config,
            verify=verify,
        )

    def fetch_ca_chain_for_url(
        self,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the CA certificate chain for a given host.

        Same as `fetch_cert_chain_for_url` excluding the host's
        certificate.

        Args:
            url_string: URL to fetch the CA certificate chain for.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration is used.
            verify: Whether to verify the CA certificate chain. Defaults to True.

        Returns:
            The fetched CA certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the host.
        """
        return self.fetch_cert_chain_for_url(
            url_string=url_string,
            verify_config=verify_config,
            verify=verify,
        )[:1]

    def make_ssl_context_for_host(
        self,
        host: str,
        port: int = 443,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificate chain for host.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        context = ssl.create_default_context(purpose=purpose)
        self.add_host_ca_chain_to_context(
            context,
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )
        return context

    def make_ssl_context_for_url(
        self,
        url_string: str,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificate chain for URL.

        See Also:
            fetch_ca_chain_for_url: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        context = ssl.create_default_context(purpose=purpose)
        self.add_url_ca_chain_to_context(
            context,
            url_string=url_string,
            verify_config=verify_config,
            verify=verify,
        )
        return context

    def add_host_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> None:
        """Add host CA chain to SSL context.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        certificates = self.fetch_ca_chain_for_host(
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )
        context.load_verify_locations(cadata=certificates_to_der(certificates))

    def add_url_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> None:
        """Add CA chain to URL's host to SSL context.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        certificates = self.fetch_ca_chain_for_url(
            url_string,
            verify_config=verify_config,
            verify=verify,
        )
        context.load_verify_locations(cadata=certificates_to_der(certificates))


def _try_download_certificate(urls: Sequence[str]) -> x509.Certificate:
    http_urls = [url for url in urls if url.lower().startswith(("http:", "https:"))]
    if not http_urls:
        raise NoValidAiaCaUrlError(urls=urls)

    errors = []
    for http_url in http_urls:
        try:
            return _download_certificate(http_url)
        except (  # noqa: PERF203
            CertificateDownloadError,
            CertificateParseError,
        ) as err:
            errors.append(err)

    raise AiaChaseExhaustedError(errors=errors)


@functools.lru_cache(maxsize=DOWNLOAD_CACHE_SIZE)
def _download_certificate(url_string: str) -> x509.Certificate:
    if url_string.startswith("https:"):
        warnings.warn(
            "Trying to download an intermediate CA certificate using HTTPS",
            category=UserWarning,
            stacklevel=2,
        )
    elif not url_string.startswith("http:"):
        raise CertificateDownloadError(
            message="URL scheme must be http or https",
            url_string=url_string,
        )

    with urlopen(  # noqa: S310
        url_string,
        timeout=DEFAULT_URLOPEN_TIMEOUT,
    ) as response:
        if response.status != http.HTTPStatus.OK:
            raise CertificateDownloadError(
                message=f"could not download {url_string}",
                url_string=url_string,
            )

        try:
            return _try_parse_certificate(response.read())
        except CertificateParseError as err:
            raise CertificateDownloadError(
                message=str(err),
                url_string=url_string,
            ) from None


def _try_parse_certificate(data: bytes) -> x509.Certificate:
    parse_fns = [x509.load_der_x509_certificate, x509.load_pem_x509_certificate]
    exceptions = []
    for parse_fn in parse_fns:
        try:
            return parse_fn(data)
        except (ValueError, TypeError) as err:  # noqa: PERF203
            exceptions.append(err)

    raise CertificateParseError(reasons=[str(err) for err in exceptions])


class _CertificateAiaInfo(NamedTuple):
    """Simpler format to work with  certificate info."""

    subject: x509.Name
    issuer: x509.Name
    aia_ca_issuers: list[str]
    aia_ocsp_urls: list[str]


def _extract_aia_info(x509_certificate: x509.Certificate) -> _CertificateAiaInfo:
    aia_info = extract_aia_information(x509_certificate)
    return _CertificateAiaInfo(
        subject=x509_certificate.subject,
        issuer=x509_certificate.issuer,
        aia_ca_issuers=aia_info.ca_issuers,
        aia_ocsp_urls=aia_info.ocsp_urls,
    )

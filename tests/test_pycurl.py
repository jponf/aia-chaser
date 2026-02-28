"""Tests for pycurl library integration."""

import tempfile
from http import HTTPStatus

import pycurl
import pytest

from aia_chaser import AiaChaser
from aia_chaser.utils.cert_utils import certificates_to_pem

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_pycurl_with_pem_file(url_string: str) -> None:
    chaser = AiaChaser()
    ca_chain = chaser.fetch_ca_chain_for_url(url_string)

    with tempfile.NamedTemporaryFile("wt", suffix=".pem") as pem_file:
        pem_file.write(certificates_to_pem(ca_chain))
        pem_file.flush()

        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url_string)
        curl.setopt(pycurl.CAINFO, pem_file.name)
        curl.setopt(pycurl.FOLLOWLOCATION, True)  # noqa: FBT003
        curl.setopt(pycurl.USERAGENT, "aia-chaser-test/1.0")
        curl.setopt(pycurl.WRITEFUNCTION, lambda _: None)  # Discard response body
        curl.perform()

        status_code = curl.getinfo(pycurl.RESPONSE_CODE)
        curl.close()

    assert status_code == HTTPStatus.OK

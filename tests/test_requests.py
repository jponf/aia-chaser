"""Tests for requests library integration."""

import tempfile
from http import HTTPStatus

import pytest
import requests

from aia_chaser import AiaChaser
from aia_chaser.utils.cert_utils import certificates_to_pem

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_requests_with_pem_file(url_string: str) -> None:
    chaser = AiaChaser()
    ca_chain = chaser.fetch_ca_chain_for_url(url_string)

    with tempfile.NamedTemporaryFile(
        "wt",
        suffix=".pem",
        delete=False,
    ) as pem_file:
        pem_file.write(certificates_to_pem(ca_chain))
        pem_file.flush()
        response = requests.get(url_string, verify=pem_file.name, timeout=30)

    assert response.status_code == HTTPStatus.OK

"""Tests for requests library integration."""

from http import HTTPStatus

import pytest
import requests

from aia_chaser import AiaChaser
from aia_chaser.utils.cert_utils import temp_pem_file

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_requests_with_pem_file(url_string: str) -> None:
    chaser = AiaChaser()
    ca_chain = chaser.fetch_ca_chain_for_url(url_string)

    with temp_pem_file(ca_chain) as pem_path:
        response = requests.get(url_string, verify=str(pem_path), timeout=30)

    assert response.status_code == HTTPStatus.OK

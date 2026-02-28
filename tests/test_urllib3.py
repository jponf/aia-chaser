"""Tests for urllib3 library integration."""

from http import HTTPStatus

import pytest
import urllib3

from aia_chaser import AiaChaser

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_urllib3_with_ssl_context(url_string: str) -> None:
    chaser = AiaChaser()
    context = chaser.make_ssl_context_for_url(url_string)

    with urllib3.PoolManager(ssl_context=context) as pool:
        response = pool.request("GET", url_string)

    assert response.status == HTTPStatus.OK

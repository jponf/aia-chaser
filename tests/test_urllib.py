"""Tests for urllib (standard library) integration."""

from http import HTTPStatus
from urllib.request import urlopen

import pytest

from aia_chaser import AiaChaser

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_urlopen_with_ssl_context(url_string: str) -> None:
    chaser = AiaChaser()
    context = chaser.make_ssl_context_for_url(url_string)
    response = urlopen(url_string, context=context)  # noqa: S310

    assert response.status == HTTPStatus.OK

"""Tests for httpx library integration."""

from http import HTTPStatus

import httpx
import pytest

from aia_chaser import AiaChaser

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_httpx_sync_with_ssl_context(url_string: str) -> None:
    chaser = AiaChaser()
    context = chaser.make_ssl_context_for_url(url_string)

    with httpx.Client(verify=context, follow_redirects=True) as client:
        response = client.get(url_string)

    assert response.status_code == HTTPStatus.OK


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
@pytest.mark.asyncio
async def test_httpx_async_with_ssl_context(url_string: str) -> None:
    chaser = AiaChaser()
    context = chaser.make_ssl_context_for_url(url_string)

    async with httpx.AsyncClient(verify=context, follow_redirects=True) as client:
        response = await client.get(url_string)

    assert response.status_code == HTTPStatus.OK

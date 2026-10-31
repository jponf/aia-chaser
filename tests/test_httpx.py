"""Tests for httpx library integration."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING

import httpx
import pytest

from .conftest import TEST_URLS_SUBSET


if TYPE_CHECKING:
    from aia_chaser import AiaChaser


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_httpx_sync_with_ssl_context(
    url_string: str,
    chaser_certifi: AiaChaser,
) -> None:
    context = chaser_certifi.make_ssl_context_for_url(url_string)

    with httpx.Client(verify=context, follow_redirects=True) as client:
        response = client.get(url_string)

    assert response.status_code == HTTPStatus.OK


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
@pytest.mark.asyncio
async def test_httpx_async_with_ssl_context(
    url_string: str,
    chaser_certifi: AiaChaser,
) -> None:
    context = chaser_certifi.make_ssl_context_for_url(url_string)

    async with httpx.AsyncClient(verify=context, follow_redirects=True) as client:
        response = await client.get(url_string)

    assert response.status_code == HTTPStatus.OK

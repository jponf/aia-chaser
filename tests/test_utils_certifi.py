"""Tests for the optional certifi SSL context utility."""

from __future__ import annotations

import ssl
import sys

import pytest

from aia_chaser.utils.certifi import create_certifi_context


def test_create_certifi_context_for_chaser() -> None:
    """Should create an unverified SSL context from certifi's CA bundle."""
    context = create_certifi_context(for_chaser=True)

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
    assert context.get_ca_certs()


def test_create_certifi_context() -> None:
    """Should create a default SSL context from certifi's CA bundle."""
    context = create_certifi_context(for_chaser=False)
    default_context = ssl.create_default_context()

    assert context.check_hostname == default_context.check_hostname
    assert context.verify_mode == default_context.verify_mode
    assert context.get_ca_certs()


def test_create_certifi_context_without_certifi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Should explain how to install the extra when certifi is unavailable."""
    monkeypatch.setitem(sys.modules, "certifi", None)

    with pytest.raises(ImportError, match=r"aia-chaser\[certifi\]"):
        create_certifi_context()

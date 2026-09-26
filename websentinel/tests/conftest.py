"""
tests/conftest.py
====================
Shared test doubles so the test suite never makes real network calls
and never targets a real website. FakeResponse/FakeSession mimic just
the parts of requests.Response / requests.Session that WebSentinel's
check modules actually read.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


class FakeRawHeaders:
    """Mimics urllib3's HTTPHeaderDict.get_all() for Set-Cookie handling."""

    def __init__(self, set_cookie_values=None):
        self._set_cookie_values = set_cookie_values or []

    def get_all(self, name):
        if name == "Set-Cookie":
            return self._set_cookie_values
        return []


class FakeRaw:
    def __init__(self, set_cookie_values=None):
        self.headers = FakeRawHeaders(set_cookie_values)


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, headers=None, status_code=200, url="https://example.com/",
                 text="", set_cookie_values=None, history=None):
        self.headers = headers or {}
        self.status_code = status_code
        self.url = url
        self.text = text
        self.raw = FakeRaw(set_cookie_values)
        self.history = history or []


class FakeSession:
    """
    Minimal stand-in for requests.Session. Returns `response` for every
    .get()/.request() call by default, or looks up a per-URL response from
    `responses_by_url` if provided.
    """

    def __init__(self, response: FakeResponse = None, responses_by_url: dict = None):
        self._response = response
        self._responses_by_url = responses_by_url or {}

    def get(self, url, headers=None, timeout=None, allow_redirects=True, **kwargs):
        if url in self._responses_by_url:
            return self._responses_by_url[url]
        if self._response is not None:
            return self._response
        return FakeResponse(status_code=404, url=url)

    def request(self, method, url, timeout=None, **kwargs):
        return self.get(url, timeout=timeout)


@pytest.fixture
def fake_response():
    return FakeResponse


@pytest.fixture
def fake_session():
    return FakeSession

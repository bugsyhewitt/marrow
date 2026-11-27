"""Tests for HTTP prober (all mocked)."""
from __future__ import annotations

import io
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from marrow.payloads import ProtoPayload, prototype_pollution_payloads
from marrow.prober import probe_url


def _mock_response(status: int = 200, body: str = "") -> MagicMock:
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = body.encode()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


def test_empty_payloads_returns_empty():
    results = probe_url("http://example.com", [])
    assert results == []


def test_result_has_required_keys():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    mock_resp = _mock_response(200, "")
    with patch("urllib.request.urlopen", return_value=mock_resp):
        results = probe_url("http://example.com", [payload])
    assert len(results) == 1
    assert "payload" in results[0]
    assert "response_code" in results[0]


def test_get_method_issues_get_request():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    mock_resp = _mock_response(200, "")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        probe_url("http://example.com", [payload], method="GET")
    req = mock_open.call_args[0][0]
    assert req.get_method() == "GET"


def test_post_method_issues_post_request():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    mock_resp = _mock_response(200, "")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        probe_url("http://example.com", [payload], method="POST")
    req = mock_open.call_args[0][0]
    assert req.get_method() == "POST"


def test_connection_error_handled_gracefully():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
        results = probe_url("http://example.com", [payload])
    assert len(results) == 1
    assert results[0]["error"] is not None
    assert results[0]["response_code"] is None


def test_indicators_non_empty_when_probe_key_in_body():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    mock_resp = _mock_response(200, "polluted found in response")
    with patch("urllib.request.urlopen", return_value=mock_resp):
        results = probe_url("http://example.com", [payload], probe_key="polluted")
    assert results[0]["indicators"], "Expected indicator when probe_key in body"


def test_200_response_code_recorded():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    mock_resp = _mock_response(200, "")
    with patch("urllib.request.urlopen", return_value=mock_resp):
        results = probe_url("http://example.com", [payload])
    assert results[0]["response_code"] == 200


def test_http_error_response_code_recorded():
    payload = ProtoPayload("proto-bracket", "__proto__[polluted]", "1", "test")
    exc = urllib.error.HTTPError(
        url="http://example.com",
        code=403,
        msg="Forbidden",
        hdrs=MagicMock(),
        fp=io.BytesIO(b""),
    )
    with patch("urllib.request.urlopen", side_effect=exc):
        results = probe_url("http://example.com", [payload])
    assert results[0]["response_code"] == 403


def test_multiple_payloads_all_probed():
    payloads = prototype_pollution_payloads()
    mock_resp = _mock_response(200, "")
    with patch("urllib.request.urlopen", return_value=mock_resp):
        results = probe_url("http://example.com", payloads)
    assert len(results) == len(payloads)

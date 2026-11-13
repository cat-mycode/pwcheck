import urllib.error
import urllib.request

import pytest

from pwcheck.breach import (
    BreachCheckError,
    count_breaches,
    parse_range_response,
    sha1_prefix_suffix,
)

# SHA-1 of "password" is a well-known test vector.
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PASSWORD_SUFFIX = PASSWORD_SHA1[5:]


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_prefix_and_suffix_split():
    prefix, suffix = sha1_prefix_suffix("password")
    assert prefix == "5BAA6"
    assert prefix + suffix == PASSWORD_SHA1


def test_parse_finds_suffix_and_returns_count():
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{PASSWORD_SUFFIX}:12345\r\nFFFF:2\r\n"
    assert parse_range_response(body, PASSWORD_SUFFIX) == 12345


def test_parse_is_case_insensitive():
    body = f"{PASSWORD_SUFFIX}:7\n"
    assert parse_range_response(body, PASSWORD_SUFFIX.lower()) == 7


def test_parse_returns_zero_when_absent():
    assert parse_range_response("ABCDEF:3\nFEDCBA:9\n", PASSWORD_SUFFIX) == 0


def test_padding_entries_with_zero_count_read_as_not_found():
    assert parse_range_response(f"{PASSWORD_SUFFIX}:0\n", PASSWORD_SUFFIX) == 0


def test_parse_ignores_malformed_lines():
    body = f"garbage\n\n:\n{PASSWORD_SUFFIX}:notanumber\n"
    assert parse_range_response(body, PASSWORD_SUFFIX) == 0


def test_only_the_prefix_is_ever_sent():
    seen = []

    def fake_fetch(prefix):
        seen.append(prefix)
        return f"{PASSWORD_SUFFIX}:42\n"

    assert count_breaches("password", fetch=fake_fetch) == 42
    assert seen == ["5BAA6"]


def test_fetch_errors_propagate():
    def failing_fetch(prefix):
        raise BreachCheckError("boom")

    with pytest.raises(BreachCheckError):
        count_breaches("password", fetch=failing_fetch)


def test_http_request_shape(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(f"{PASSWORD_SUFFIX}:5\n".encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert count_breaches("password", timeout=3) == 5

    request = captured["request"]
    headers = {key.lower(): value for key, value in request.header_items()}
    assert request.full_url == "https://api.pwnedpasswords.com/range/5BAA6"
    assert headers["add-padding"] == "true"
    assert "user-agent" in headers
    assert captured["timeout"] == 3


def test_network_failure_becomes_breach_check_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(BreachCheckError):
        count_breaches("password")

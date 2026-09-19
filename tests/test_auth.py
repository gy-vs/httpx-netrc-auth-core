"""
Unit tests for auth classes.

Integration tests also exist in tests/client/test_auth.py
"""
import netrc
import os
import typing
from urllib.request import parse_keqv_list

import pytest

import httpx


def test_basic_auth():
    auth = httpx.BasicAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should include a basic auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert request.headers["Authorization"].startswith("Basic")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_200():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 200 response is returned, then no other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401_nonce_counting():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers
    )
    first_request = flow.send(response)
    assert first_request.headers["Authorization"].startswith("Digest")

    # Each subsequent request contains the digest header by default...
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    second_request = next(flow)
    assert second_request.headers["Authorization"].startswith("Digest")

    # ... and the client nonce count (nc) is increased
    first_nc = parse_keqv_list(first_request.headers["Authorization"].split(", "))["nc"]
    second_nc = parse_keqv_list(second_request.headers["Authorization"].split(", "))[
        "nc"
    ]
    assert int(first_nc, 16) + 1 == int(second_nc, 16)

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def write_netrc(tmp_path: typing.Any, content: str) -> str:
    path = tmp_path / ".netrc"
    path.write_text(content)
    os.chmod(path, 0o600)
    return str(path)


def netrc_auth_flow_request(auth: httpx.NetRCAuth, url: str) -> httpx.Request:
    request = httpx.Request("GET", url)
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)
    return request


def test_netrc_auth(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://example.org")
    assert request.headers["Authorization"] == (
        "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_matching_is_case_insensitive_on_the_request_host(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://EXAMPLE.ORG")
    assert request.headers["Authorization"] == (
        "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_matching_ignores_the_request_port(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://example.org:8443")
    assert request.headers["Authorization"] == (
        "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_default_entry(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "default\nlogin example-username\npassword example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://other.org")
    assert request.headers["Authorization"] == (
        "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_machine_entry_has_priority_over_default_entry(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\nlogin machine-login\npassword machine-password\n"
        "default\nlogin default-login\npassword default-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://example.org")
    assert (
        request.headers["Authorization"]
        == "Basic bWFjaGluZS1sb2dpbjptYWNoaW5lLXBhc3N3b3Jk"
    )

    request = netrc_auth_flow_request(auth, "https://other.org")
    assert (
        request.headers["Authorization"]
        == "Basic ZGVmYXVsdC1sb2dpbjpkZWZhdWx0LXBhc3N3b3Jk"
    )


def test_netrc_auth_account_field_is_ignored(tmp_path):
    # The 'account' field is parsed following Python netrc semantics,
    # but is not used by basic auth.
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "account example-account\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://example.org")
    assert request.headers["Authorization"] == (
        "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_no_matching_entry_leaves_request_unauthenticated(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://other.org")
    assert "Authorization" not in request.headers


def test_netrc_auth_missing_password_leaves_request_unauthenticated(tmp_path):
    # A 'password' keyword with no value gives an empty password,
    # following Python netrc semantics.
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\nlogin example-username\npassword",
    )
    auth = httpx.NetRCAuth(netrc_file)

    request = netrc_auth_flow_request(auth, "https://example.org")
    assert "Authorization" not in request.headers


def test_netrc_auth_missing_file():
    with pytest.raises(FileNotFoundError):
        httpx.NetRCAuth("does-not-exist.netrc")


def test_netrc_auth_malformed_file(tmp_path):
    netrc_file = write_netrc(tmp_path, "this is not a valid netrc file")
    with pytest.raises(netrc.NetrcParseError):
        httpx.NetRCAuth(netrc_file)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
def test_netrc_auth_insecure_file_permissions(tmp_path):
    path = tmp_path / ".netrc"
    path.write_text(
        "machine example.org\nlogin example-username\npassword example-password\n"
    )
    os.chmod(path, 0o644)

    with pytest.raises(netrc.NetrcParseError):
        httpx.NetRCAuth(str(path))


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
def test_netrc_auth_file_owned_by_another_user(tmp_path, monkeypatch):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\nlogin example-username\npassword example-password\n",
    )
    # Simulate a netrc file that is owned by a different user.
    monkeypatch.setattr(os, "getuid", lambda: 12345)

    with pytest.raises(netrc.NetrcParseError):
        httpx.NetRCAuth(netrc_file)


def test_netrc_auth_repr_does_not_leak_password(tmp_path):
    netrc_file = write_netrc(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(netrc_file)
    assert repr(auth) == f"NetRCAuth(file={netrc_file!r})"
    assert "example-username" not in repr(auth)
    assert "example-password" not in repr(auth)

    auth = httpx.NetRCAuth()
    assert repr(auth) == "NetRCAuth(file='<default>')"

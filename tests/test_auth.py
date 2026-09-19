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


def write_netrc_file(tmp_path: typing.Any, content: str) -> str:
    netrc_file = tmp_path / "netrc"
    netrc_file.write_text(content)
    # The netrc file must only be accessible to the current user.
    netrc_file.chmod(0o600)
    return str(netrc_file)


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


def test_netrc_auth(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)
    assert not auth.uses_default_file

    request = httpx.Request("GET", "http://example.org")

    # The request should include a basic auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)

    # The netrc file is only loaded once, and is cached for further requests.
    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


@pytest.mark.anyio
async def test_netrc_auth_async(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    request = httpx.Request("GET", "http://example.org")

    # The request should include a basic auth header.
    flow = auth.async_auth_flow(request)
    request = await flow.__anext__()
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopAsyncIteration):
        await flow.asend(response)


def test_netrc_auth_host_case_insensitive(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    # Hostnames are matched case-insensitively.
    request = httpx.Request("GET", "http://EXAMPLE.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_with_port(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    # Any port in the URL is ignored when matching the hostname.
    request = httpx.Request("GET", "http://example.org:8080")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_default_entry(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n"
        "default\n"
        "login default-username\n"
        "password default-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    # A 'machine' entry takes precedence over the 'default' entry.
    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )

    # Hosts without a 'machine' entry use the 'default' entry.
    request = httpx.Request("GET", "http://other.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZGVmYXVsdC11c2VybmFtZTpkZWZhdWx0LXBhc3N3b3Jk"
    )


def test_netrc_auth_with_account(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "account example-account\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    # The 'account' value is valid netrc, but is not used for basic auth.
    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_no_matching_entry(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine other.org\nlogin example-username\npassword example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    # No matching 'machine' or 'default' entry, so the request is
    # sent without any authentication.
    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_netrc_auth_default_file_from_environment(tmp_path, monkeypatch):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    monkeypatch.setenv("NETRC", netrc_file)
    auth = httpx.NetRCAuth()
    assert auth.uses_default_file

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert (
        request.headers["Authorization"]
        == "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    )


def test_netrc_auth_default_file_not_found(tmp_path, monkeypatch):
    monkeypatch.setenv("NETRC", str(tmp_path / "does-not-exist"))
    monkeypatch.setenv("HOME", str(tmp_path))
    auth = httpx.NetRCAuth()

    # No netrc file exists in any of the default locations,
    # so the request is sent without any authentication.
    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers


def test_netrc_auth_file_not_found(tmp_path):
    auth = httpx.NetRCAuth(file=str(tmp_path / "does-not-exist"))

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    with pytest.raises(FileNotFoundError):
        next(flow)


def test_netrc_auth_malformed_file(tmp_path):
    netrc_file = write_netrc_file(tmp_path, "this is not a valid netrc file")
    auth = httpx.NetRCAuth(file=netrc_file)

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    with pytest.raises(netrc.NetrcParseError):
        next(flow)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
def test_netrc_auth_file_not_owned_by_user(tmp_path, monkeypatch):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    # Simulate a netrc file that is owned by a different user.
    monkeypatch.setattr(os, "getuid", lambda: 12321)
    auth = httpx.NetRCAuth(file=netrc_file)

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    with pytest.raises(netrc.NetrcParseError):
        next(flow)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
def test_netrc_auth_file_insecure_permissions(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    # The netrc file must not be accessible to the group or other users.
    os.chmod(netrc_file, 0o644)
    auth = httpx.NetRCAuth(file=netrc_file)

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    with pytest.raises(netrc.NetrcParseError):
        next(flow)


def test_netrc_auth_repr_does_not_leak_password(tmp_path):
    netrc_file = write_netrc_file(
        tmp_path,
        "machine example.org\n"
        "login example-username\n"
        "password example-password\n",
    )
    auth = httpx.NetRCAuth(file=netrc_file)

    request = httpx.Request("GET", "http://example.org")
    flow = auth.sync_auth_flow(request)
    next(flow)

    assert repr(auth) == f"NetRCAuth(file={netrc_file!r})"
    assert "example-username" not in repr(auth)
    assert "example-password" not in repr(auth)

    auth = httpx.NetRCAuth()
    assert repr(auth) == "NetRCAuth()"

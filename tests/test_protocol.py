import asyncio
import ipaddress
import time
from types import SimpleNamespace

import pytest
from starlette.datastructures import Headers
from starlette.responses import Response

import opus_auth

KEY = "test-key-0123456789"
NOW = 1758000000.0

# Every cookie already in a browser was written exactly this way, so these
# vectors never change.
ISSUED = {
    ("filip", 3): "1760592000.ZmlsaXA.3.6878f6a9ac1c096cde5fd8ec4048efabd99a0d17f662c2e321554ba1cb8d2adb",
    ("đurđa šimić", 1): "1760592000.xJF1csSRYSDFoWltacSH.1.23a6bfb7eb7659ec383b55fc0dfff193d1ed0c39c21e2b1374b45e84c1f54799",
    ("jana", 12): "1760592000.amFuYQ.12.952f2f0cfa6ae599923bc1ef22fde5dbab3f6bf84872fb01f65b8fca8d217b83",
}
PLAYER_CAR = "2073360000.ZmlsaXA.3.7.6b20a0ecc60a79fcf15a2d725cd299b12313cda998b61fc4ab5ace7a3e82deac"
PLAYER_PROFILE = "2073360000.ZmlsaXA.cad724c10b34ed46f3655ec2361ac7ffd473aa2d82ff489d1201eaa6efadef7e"
DECADE = 3650 * 24 * 3600

SET_ON_DOMAIN = ("opus_session=1760592000.ZmlsaXA.3.6878f6a9ac1c096cde5fd8ec4048efabd99a0d17f662c2e321554ba1cb8d2adb; "
                 "Domain=example.com; HttpOnly; Max-Age=2592000; Path=/; SameSite=lax; Secure")
SET_ON_LAN = ("opus_session=1760592000.ZmlsaXA.3.6878f6a9ac1c096cde5fd8ec4048efabd99a0d17f662c2e321554ba1cb8d2adb; "
              "HttpOnly; Max-Age=2592000; Path=/; SameSite=lax")
DELETED_ON_DOMAIN = ('opus_session=""; Domain=example.com; expires=Tue, 16 Sep 2025 05:20:00 GMT; '
                     "HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure")
DELETED_ON_LAN = 'opus_session=""; expires=Tue, 16 Sep 2025 05:20:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax'


@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)


def request(headers: dict, host: str | None = "10.0.0.1", method: str = "GET"):
    return SimpleNamespace(headers=Headers(headers), method=method,
                           client=SimpleNamespace(host=host) if host else None)


def test_wire_words():
    assert opus_auth.SESSION_COOKIE == "opus_session"
    assert opus_auth.SESSION_MAX_AGE == 2592000
    assert opus_auth.TOKEN_HEADER == "X-OPUS-Token"
    assert opus_auth.ROLES == ("admin", "user", "guest")


@pytest.mark.parametrize(("who", "version"), list(ISSUED))
def test_issue_matches_deployed(frozen, who, version):
    assert opus_auth.issue(KEY, who, version) == ISSUED[(who, version)]


@pytest.mark.parametrize(("who", "version"), list(ISSUED))
def test_session_user_reads_deployed(frozen, who, version):
    assert opus_auth.session_user(KEY, ISSUED[(who, version)]) == (who, version)


def test_other_purposes_seal_the_same_way(frozen):
    car = opus_auth.signing_key(KEY, "opus-player-car")
    profile = opus_auth.signing_key(KEY, "opus-player-session")
    assert opus_auth.seal(car, DECADE, opus_auth.encode_name("filip"), "3", "7") == PLAYER_CAR
    assert opus_auth.seal(profile, DECADE, opus_auth.encode_name("filip")) == PLAYER_PROFILE
    assert opus_auth.unseal(car, PLAYER_CAR, 3) == ["ZmlsaXA", "3", "7"]
    assert opus_auth.unseal(profile, PLAYER_CAR, 3) is None


@pytest.mark.parametrize("cookie", [
    None,
    "",
    "garbage",
    ISSUED[("filip", 3)][:-1] + "0",
    ISSUED[("filip", 3)].replace(".3.", ".4.", 1),
    ISSUED[("filip", 3)] + ".extra",
    "1760592000.ZmlsaXA.x.6878f6a9ac1c096cde5fd8ec4048efabd99a0d17f662c2e321554ba1cb8d2adb",
    "²760592000.ZmlsaXA.3.6878f6a9ac1c096cde5fd8ec4048efabd99a0d17f662c2e321554ba1cb8d2adb",
    "1760592000.ZmlsaXA.3.ščć",
])
def test_session_user_refuses(frozen, cookie):
    assert opus_auth.session_user(KEY, cookie) is None


def test_session_user_refuses_another_key(frozen):
    assert opus_auth.session_user("another-key", ISSUED[("filip", 3)]) is None


def test_session_user_refuses_expired(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1760592001.0)
    assert opus_auth.session_user(KEY, ISSUED[("filip", 3)]) is None


def test_same_token():
    assert opus_auth.same_token("abc", "abc")
    assert not opus_auth.same_token("abc", "abd")
    assert not opus_auth.same_token("", "")
    assert not opus_auth.same_token(None, "abc")
    assert not opus_auth.same_token("abc", "")
    assert not opus_auth.same_token("ščć", "abc")


def test_new_token_shape():
    token = opus_auth.new_token()
    assert len(token) == 43 and token != opus_auth.new_token()


def test_client_address_believes_headers_only_from_trusted_peers(monkeypatch):
    monkeypatch.setattr(opus_auth, "_local_networks", lambda: (ipaddress.ip_network("172.18.0.0/16"),))
    proxied = {"cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"}
    assert opus_auth.client_address(request(proxied, host="172.18.0.5")) == "1.2.3.4"
    assert opus_auth.client_address(request({"x-forwarded-for": " 5.6.7.8, 9.9.9.9"}, host="172.18.0.5")) == "5.6.7.8"
    assert opus_auth.client_address(request(proxied, host="192.168.1.50")) == "192.168.1.50"
    assert opus_auth.client_address(request(proxied, host="192.168.1.102"), relayed=True) == "1.2.3.4"
    assert opus_auth.client_address(request({}, host="10.0.0.1")) == "10.0.0.1"
    assert opus_auth.client_address(request({}, host=None)) == ""


def test_gateway_is_not_a_trusted_peer(monkeypatch):
    monkeypatch.setattr(opus_auth, "_local_networks", lambda: (ipaddress.ip_network("172.18.0.0/16"),))
    monkeypatch.setattr(opus_auth, "_gateways", lambda: frozenset({ipaddress.ip_address("172.18.0.1")}))
    proxied = {"cf-connecting-ip": "1.2.3.4"}
    assert opus_auth.client_address(request(proxied, host="172.18.0.1")) == "172.18.0.1"
    assert opus_auth.client_address(request(proxied, host="172.18.0.5")) == "1.2.3.4"


def test_a_passkey_door_only_behind_the_module_s_own_web_server(monkeypatch):
    monkeypatch.setattr(opus_auth, "_local_networks", lambda: (ipaddress.ip_network("172.18.0.0/16"),))
    monkeypatch.setattr(opus_auth, "_gateways", lambda: frozenset({ipaddress.ip_address("172.18.0.1")}))
    reached = {"x-forwarded-host": "Library.Example.com", "host": "backend:8095"}
    door = opus_auth.passkey_door
    assert door("example.com", request(reached, host="172.18.0.5")) == (
        "example.com", "https://library.example.com")
    assert door("example.com", request(reached, host="172.18.0.1")) is None
    assert door("example.com", request(reached, host="192.168.1.50")) is None
    assert door("example.com", request({"host": "backend:8095"}, host="172.18.0.5")) is None
    assert door("", request(reached, host="172.18.0.5")) is None
    lan = {"x-forwarded-host": "192.168.1.103:5280", "host": "backend:8095"}
    assert door("example.com", request(lan, host="172.18.0.5")) is None


@pytest.mark.parametrize(("address", "bucket"), [
    ("192.168.1.50", "192.168.1.50"),
    ("2a02:810:1:2:aaaa:bbbb:cccc:dddd", "2a02:810:1:2::/64"),
    ("2a02:810:1:2::1", "2a02:810:1:2::/64"),
    ("::ffff:10.0.0.1", "10.0.0.1"),
    ("not an address", "not an address"),
])
def test_address_bucket(address, bucket):
    assert opus_auth.address_bucket(address) == bucket


def test_quiet_access_log_drops_queries_once():
    import logging
    opus_auth.quiet_access_log()
    opus_auth.quiet_access_log()
    access = logging.getLogger("uvicorn.access")
    assert sum(isinstance(f, opus_auth._WithoutQuery) for f in access.filters) == 1
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "%s %s", ("GET", "/api/art?t=secret"), None)
    access.filters[-1].filter(record)
    assert record.args == ("GET", "/api/art")


def test_local_networks_include_loopback():
    assert any(ipaddress.ip_address("127.0.0.1") in n for n in opus_auth._local_networks())


@pytest.mark.parametrize(("method", "headers", "allowed"), [
    ("GET", {"sec-fetch-site": "cross-site"}, True),
    ("POST", {"sec-fetch-site": "same-origin"}, True),
    ("POST", {"sec-fetch-site": "none"}, True),
    ("POST", {"sec-fetch-site": "same-site"}, False),
    ("PUT", {"sec-fetch-site": "cross-site"}, False),
    ("POST", {"origin": "https://library.example.com", "x-forwarded-host": "library.example.com"}, True),
    ("DELETE", {"origin": "https://dida.example.com", "x-forwarded-host": "library.example.com"}, False),
    ("POST", {"origin": "http://192.168.1.103:5280", "host": "192.168.1.103:5280"}, True),
    ("POST", {}, True),
])
def test_same_origin(method, headers, allowed):
    assert opus_auth.same_origin(request(headers, method=method)) is allowed


@pytest.mark.parametrize(("path", "inside"), [
    ("/api/photos/vault", True),
    ("/api/photos/vault/files/3", True),
    ("/api/photos/vaultX", False),
    ("/api/photos/vaults", False),
    ("/api/music", True),
])
def test_under(path, inside):
    assert opus_auth.under(path, ("/api/photos/vault", "/api/music/")) is inside


@pytest.mark.parametrize(("configured", "headers", "domain"), [
    ("", {"host": "opus.example.com"}, None),
    (".Example.com", {"x-forwarded-host": "library.example.com", "host": "backend:8095"},
     "example.com"),
    ("example.com", {"host": "example.com:443"}, "example.com"),
    ("example.com", {"host": "backend:8095"}, None),
    ("example.com", {"host": "192.168.1.103:8095"}, None),
    ("example.com", {"host": "notboskovic.biz"}, None),
    ("example.com", {"x-forwarded-host": "opus.example.com, proxy"}, "example.com"),
])
def test_cookie_domain(configured, headers, domain):
    assert opus_auth.cookie_domain(configured, request(headers)) == domain


@pytest.mark.parametrize(("host", "written", "deleted"), [
    ("library.example.com", SET_ON_DOMAIN, DELETED_ON_DOMAIN),
    ("192.168.1.103:8095", SET_ON_LAN, DELETED_ON_LAN),
])
def test_cookie_headers_match_deployed(frozen, host, written, deleted):
    asked = request({"x-forwarded-host": host})
    response = Response()
    opus_auth.set_cookie(response, asked, ".Example.com", opus_auth.SESSION_COOKIE,
                         opus_auth.issue(KEY, "filip", 3), opus_auth.SESSION_MAX_AGE)
    assert response.headers.getlist("set-cookie") == [written]
    response = Response()
    opus_auth.delete_cookie(response, asked, ".Example.com", opus_auth.SESSION_COOKIE)
    assert response.headers.getlist("set-cookie") == [deleted]


def _answer(inner, scope_type="http"):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    asyncio.run(opus_auth.secured(inner)({"type": scope_type}, receive, send))
    return sent


def test_secured_adds_headers_and_keeps_the_routes_own():
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 500,
                    "headers": [(b"Content-Security-Policy", b"frame-ancestors https://x")]})
        await send({"type": "http.response.body", "body": b"boom"})

    start, body = _answer(inner)
    headers = start["headers"]
    assert (b"x-content-type-options", b"nosniff") in headers
    assert (b"referrer-policy", b"same-origin") in headers
    assert [v for k, v in headers if k.lower() == b"content-security-policy"] == [b"frame-ancestors https://x"]
    assert body == {"type": "http.response.body", "body": b"boom"}


def test_secured_passes_other_scopes_through():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    assert _answer(inner, "lifespan") == []
    assert seen == ["lifespan"]

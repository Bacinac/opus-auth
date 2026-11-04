"""What the three OPUS modules must agree on byte for byte: the shared session
cookie, the header a module's token rides in, the words for a person's standing,
and how a signed credential is made and read.

Policy is not here. Which paths a module opens, and to whom, stays with that
module; this package only says what a credential looks like."""

import base64
import functools
import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
import struct
import time

SESSION_COOKIE = "opus_session"
SESSION_MAX_AGE = 30 * 24 * 3600
SESSION_PURPOSE = "opus-session"

TOKEN_HEADER = "X-OPUS-Token"
# The person a module asks on behalf of. Only ever narrows: the module's token
# still decides what may be reached, and the person's standing can only take
# away from that.
FOR_HEADER = "X-OPUS-For"

SESSION_KEY_MIN = 32

ADMIN, USER, GUEST = "admin", "user", "guest"
ROLES = (ADMIN, USER, GUEST)


def signing_key(session_key: str, purpose: str = SESSION_PURPOSE) -> bytes:
    return hashlib.sha256(f"{purpose}:{session_key}".encode()).digest()


def _mac(key: bytes, body: str) -> str:
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def _number(field: str) -> bool:
    return field.isascii() and field.isdigit()


def seal(key: bytes, max_age: int, *fields: str) -> str:
    body = ".".join((str(int(time.time()) + max_age), *fields))
    return f"{body}.{_mac(key, body)}"


def unseal(key: bytes, credential: str | None, count: int) -> list[str] | None:
    """The fields after the expiry, once the signature and the expiry both hold."""
    body, _, mac = (credential or "").rpartition(".")
    parts = body.split(".")
    if not mac or len(parts) != count + 1:
        return None
    if not _number(parts[0]) or int(parts[0]) < time.time():
        return None
    if not hmac.compare_digest(mac.encode(), _mac(key, body).encode()):
        return None
    return parts[1:]


def encode_name(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode()).decode().rstrip("=")


def decode_name(field: str) -> str | None:
    try:
        return base64.urlsafe_b64decode(field + "=" * (-len(field) % 4)).decode()
    except ValueError:
        return None


def issue(session_key: str, name: str, version: int) -> str:
    return seal(signing_key(session_key), SESSION_MAX_AGE, encode_name(name), str(version))


def session_user(session_key: str, cookie: str | None) -> tuple[str, int] | None:
    """Who the shared cookie credibly says this is, and under which version of
    their secret."""
    said = unseal(signing_key(session_key), cookie, 2)
    if said is None or not _number(said[1]):
        return None
    name = decode_name(said[0])
    return None if name is None else (name, int(said[1]))


def same_token(given: str | None, known: str | None) -> bool:
    """An unset token on either side recognises nothing."""
    if not given or not known:
        return False
    return hmac.compare_digest(given.encode(), known.encode())


def new_token() -> str:
    return secrets.token_urlsafe(32)


def _routes() -> list[list[str]]:
    try:
        with open("/proc/net/route") as routes:
            return [line.split() for line in list(routes)[1:]]
    except OSError:
        return []


def _dotted(field: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(field, 16)))


@functools.cache
def _local_networks() -> tuple:
    networks = [ipaddress.ip_network("127.0.0.0/8")]
    for fields in _routes():
        try:
            if int(fields[7], 16):
                networks.append(ipaddress.ip_network(
                    f"{_dotted(fields[1])}/{_dotted(fields[7])}", strict=False))
        except (IndexError, ValueError):
            continue
    return tuple(networks)


@functools.cache
def _gateways() -> frozenset:
    """The container network's gateway is where the engine's own port forwarding
    hands over connections from outside, so an address there is anybody."""
    found = set()
    for fields in _routes():
        try:
            if int(fields[2], 16):
                found.add(ipaddress.ip_address(_dotted(fields[2])))
        except (IndexError, ValueError):
            continue
    return frozenset(found)


def _local(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip not in _gateways() and any(ip in network for network in _local_networks())


def address_bucket(address: str) -> str:
    """What counts as one caller when attempts are counted: an IPv6 host is handed
    a whole /64, and every address in it is the same somebody."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class _WithoutQuery(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(a.partition("?")[0] if isinstance(a, str) and a.startswith("/")
                                else a for a in record.args)
        return True


def quiet_access_log() -> None:
    """The server's own log keeps a path and drops its query, which is where a
    ticket or a token rides when a client cannot send a header."""
    for name in ("uvicorn.access", "uvicorn.error"):
        server_log = logging.getLogger(name)
        if not any(isinstance(f, _WithoutQuery) for f in server_log.filters):
            server_log.addFilter(_WithoutQuery())


def client_address(request, relayed: bool = False) -> str:
    """Who is knocking. The forwarding headers are believed only from this
    module's own web server, which sits on the container network and has already
    decided what to pass on, or from a module that proved itself with the token;
    from anywhere else they are whatever the caller chose to write."""
    peer = request.client.host if request.client else ""
    if relayed or _local(peer):
        said = (request.headers.get("cf-connecting-ip")
                or request.headers.get("x-forwarded-for", "").partition(",")[0]).strip()
        if said:
            return said
    return peer


def same_origin(request) -> bool:
    """Whether a browser sent this from one of this module's own pages. Every
    module shares one cookie across the parent domain, and SameSite treats every
    sibling subdomain as the same site, so the browser's own report of where a
    request came from is what separates a form on this page from one elsewhere.
    A caller that is not a browser sends neither header and is judged by its
    credential alone."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is None:
        return True
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = host.partition(",")[0].strip().lower()
    return origin.lower().split("://", 1)[-1].rstrip("/") == host


def passkey_door(configured_domain: str, request) -> tuple[str, str] | None:
    """The domain a passkey here belongs to and the address its signature has to
    name for this door to take it, or None where this door takes none.

    The address is known only from this module's own web server, which writes
    the host it was reached on; a caller at the port directly could write any
    host at all, including a sibling site's that collected the signature."""
    peer = request.client.host if request.client else ""
    if not _local(peer):
        return None
    host = request.headers.get("x-forwarded-host", "").partition(",")[0].strip().lower()
    domain = cookie_domain(configured_domain, request)
    return (domain, f"https://{host}") if host and domain else None


SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"content-security-policy", b"frame-ancestors 'self'"),
)


def secured(inner):
    """An ASGI application that answers like `inner`, with the headers a browser
    needs to refuse sniffing, framing and leaking the address. Wrapped around the
    whole stack, so an error page and a stream carry them too; a header the
    route set itself is left as it is."""
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)

        async def sending(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                message = {**message, "headers": headers + [
                    header for header in SECURITY_HEADERS if header[0] not in present]}
            await send(message)

        await inner(scope, receive, sending)

    return app


def under(path: str, prefixes: tuple[str, ...]) -> bool:
    """A path inside one of these, segment for segment: /api/photos/vault covers
    /api/photos/vault/files but not /api/photos/vaults."""
    for prefix in prefixes:
        root = prefix.rstrip("/")
        if path == root or path.startswith(root + "/"):
            return True
    return False


def cookie_domain(configured: str, request) -> str | None:
    """The shared domain, only when the browser actually arrived on it: a cookie
    scoped to a domain the address does not belong to is discarded without a
    word. Behind a UI proxy the Host header is the internal service, so the
    forwarded one leads."""
    configured = configured.strip().lstrip(".").lower()
    if not configured:
        return None
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = host.partition(",")[0].strip().partition(":")[0].lower()
    return configured if host == configured or host.endswith(f".{configured}") else None


def set_cookie(response, request, configured_domain: str, name: str, value: str,
               max_age: int) -> None:
    # the shared domain is only reached through the tunnel, which is https; a LAN
    # address is plain http, where a Secure cookie would not be kept
    domain = cookie_domain(configured_domain, request)
    response.set_cookie(name, value, max_age=max_age, path="/", domain=domain,
                        secure=domain is not None, httponly=True, samesite="lax")


def delete_cookie(response, request, configured_domain: str, name: str) -> None:
    # written with a domain, it is only removed with the same one
    domain = cookie_domain(configured_domain, request)
    response.delete_cookie(name, path="/", domain=domain, secure=domain is not None,
                           httponly=True, samesite="lax")

"""Asking Library, which keeps the roster: who exists and under which version of
their secret, and whether a typed credential is right.

Unreachable is not open. What was last known is kept through a blip, but it is
never marked fresh, and a credential that cannot be checked raises rather than
reading as a wrong password."""

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from opus_auth import TOKEN_HEADER

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Person:
    name: str
    version: int
    role: str
    display: str
    # the people whose photographs a guest sees; empty is none of them
    circle: tuple[int, ...] = ()
    # which face in the photographs this account is, where it is one
    person_id: int | None = None


class AuthorityUnavailable(Exception):
    """Library could not say whether a credential is right, which is not the
    same as saying it is wrong."""


class TooManyAttempts(Exception):
    def __init__(self, retry_after: str):
        super().__init__("too many failed attempts")
        self.retry_after = retry_after


class Authority:
    # long enough that the roster is not fetched per request, short enough that
    # somebody removed is out within the minute
    TTL = 60.0
    # A temporary outage must not turn a revoked credential into a permanent
    # one. Existing sessions survive a short Library blip, then fail closed.
    MAX_STALE = 5 * 60.0
    # a cookie the copy does not recognise is on every request of a page, and
    # each of them asking again is a storm
    PAUSE = 2.0

    def __init__(self, url: str, token: str,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.url = url.rstrip("/")
        self.token = token
        self._transport = transport
        self._people: dict[str, Person] = {}
        self._fetched = 0.0
        self._tried = 0.0
        self._fetches = 0
        self._refused: set[tuple[str, int]] = set()
        self._asking = asyncio.Lock()
        self._complaint: str | None = None

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=10, transport=self._transport)

    def forget(self) -> None:
        """The copy is known to be behind, so the next question goes to Library."""
        self._fetched = self._tried = 0.0

    def _due(self, force: bool, now: float) -> bool:
        if now - self._tried < self.PAUSE:
            return False
        return force or now - self._fetched >= self.TTL

    def _complain(self, said: str) -> None:
        # once per change of reason: a roster that cannot be had turns every
        # request into a refusal, and a line per request buries the one that matters
        if said != self._complaint:
            self._complaint = said
            log.warning("roster unavailable from %s (%s); nobody new is recognised "
                        "until this clears", self.url, said)

    async def people(self, force: bool = False) -> dict[str, Person]:
        """Everyone who may be let in, by name. Somebody switched off is not on it."""
        if not self._due(force, time.monotonic()):
            return self._people
        async with self._asking:
            now = time.monotonic()
            if not self._due(force, now):
                return self._people
            self._tried = now
            try:
                async with self._http() as http:
                    resp = await http.get(f"{self.url}/api/auth/people",
                                          headers={TOKEN_HEADER: self.token})
                resp.raise_for_status()
                people = {p["name"]: Person(p["name"], int(p["version"]), p["role"], p["display"],
                                         tuple(int(i) for i in p.get("circle") or ()),
                                         p.get("person_id"))
                          for p in resp.json()["people"] if not p["disabled"]}
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as why:
                self._complain(f"{type(why).__name__}: {why}")
                return self._people
            if self._complaint is not None:
                self._complaint = None
                log.info("roster available again from %s", self.url)
            self._people, self._fetched = people, now
            self._fetches += 1
            self._refused.clear()
            return people

    async def current(self, name: str, version: int) -> Person | None:
        """The person a signed credential names, while the roster still carries
        them at that version.

        A password changed a moment ago looks exactly like a stale cookie until
        the copy catches up, so a mismatch asks again before refusing. Once a
        fresh copy has refused it, it stays refused until the copy next changes."""
        fetches = self._fetches
        person = (await self.people()).get(name)
        if (person is not None and person.version == version
                and time.monotonic() - self._fetched <= self.MAX_STALE):
            return person
        if (name, version) in self._refused:
            return None
        person = (await self.people(force=True)).get(name)
        if (person is not None and person.version == version
                and time.monotonic() - self._fetched <= self.MAX_STALE):
            return person
        if self._fetches != fetches:
            self._refused.add((name, version))
        return None

    async def _ask(self, path: str, body: dict | None, address: str | None = None) -> httpx.Response:
        url = f"{self.url}{path}"
        headers = {TOKEN_HEADER: self.token}
        if address is not None:
            headers["X-Forwarded-For"] = address
        try:
            async with self._http() as http:
                resp = await http.post(url, json=body, headers=headers)
        except httpx.HTTPError as why:
            log.warning("%s failed: %s", url, type(why).__name__)
            raise AuthorityUnavailable(
                f"the library could not be reached ({type(why).__name__})") from why
        if resp.status_code == 429:
            raise TooManyAttempts(resp.headers.get("retry-after", "60"))
        if resp.status_code != 200:
            log.warning("%s answered %s", url, resp.status_code)
            raise AuthorityUnavailable(f"the library answered {resp.status_code}")
        return resp

    def _verdict(self, resp: httpx.Response) -> Person | None:
        try:
            said = resp.json()
            if not said["ok"]:
                return None
            person = Person(said["name"], int(said["version"]), said["role"], said["display"])
        except (KeyError, TypeError, ValueError) as why:
            raise AuthorityUnavailable("the library answered something that is not a verdict") from why
        self.forget()
        return person

    async def verify(self, username: str, password: str, address: str) -> Person | None:
        """The person this credential proves, or None. Asked on behalf of the
        address the person is knocking from, which is what Library counts
        failures against."""
        return self._verdict(await self._ask(
            "/api/auth/verify", {"username": username, "password": password}, address))

    async def passkey_options(self) -> dict:
        """What the browser is asked to sign. Handed out by Library, because the
        answer is checked there and the question has to be remembered where it is
        checked."""
        resp = await self._ask("/api/auth/passkey/options", None)
        try:
            options = resp.json()
        except ValueError as why:
            raise AuthorityUnavailable("the library answered something that is not a challenge") from why
        if not isinstance(options, dict):
            raise AuthorityUnavailable("the library answered something that is not a challenge")
        return options

    async def passkey(self, credential: dict, origin: str, address: str) -> Person | None:
        """The person whose passkey signed this, or None. The origin is this
        module's own door, which the signature has to name."""
        return self._verdict(await self._ask(
            "/api/auth/passkey/verify", {"credential": credential, "origin": origin}, address))

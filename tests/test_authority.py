import asyncio
import json
import logging

import httpx
import pytest

from opus_auth import authority as module
from opus_auth.authority import Authority, AuthorityUnavailable, Person, TooManyAttempts

TOKEN = "module-token"

# What Library's accounts.shown() answers, field for field.
FILIP = {"name": "filip", "display": "Filip", "role": "user", "disabled": False,
       "version": 3, "person_id": 12, "circle": []}
BOSS = {"name": "boss", "display": "boss", "role": "admin", "disabled": False,
        "version": 1, "person_id": None, "circle": []}
GONE = {"name": "kata", "display": "Kata", "role": "user", "disabled": True,
        "version": 5, "person_id": None, "circle": []}
COUSIN = {"name": "ante", "display": "Ante", "role": "guest", "disabled": False,
          "version": 2, "person_id": 40, "circle": [40, 41]}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    kept = Clock()
    monkeypatch.setattr(module, "time", kept)
    return kept


class Library:
    def __init__(self):
        self.people = [FILIP, BOSS, GONE]
        self.asked: list[httpx.Request] = []
        self.answer = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.asked.append(request)
        if self.answer is not None:
            return self.answer(request)
        if request.url.path == "/api/auth/people":
            return httpx.Response(200, json={"people": self.people})
        raise AssertionError(request.url)

    def authority(self) -> Authority:
        return Authority("http://library:8095/", TOKEN, transport=httpx.MockTransport(self))


def run(coroutine):
    return asyncio.run(coroutine)


def test_people_payload(clock):
    library = Library()
    people = run(library.authority().people())
    assert people == {"filip": Person("filip", 3, "user", "Filip", person_id=12),
                      "boss": Person("boss", 1, "admin", "boss")}
    (asked,) = library.asked
    assert asked.method == "GET"
    assert str(asked.url) == "http://library:8095/api/auth/people"
    assert asked.headers["X-OPUS-Token"] == TOKEN


def test_a_guest_carries_the_people_whose_photographs_they_see(clock):
    library = Library()
    library.people = [FILIP, COUSIN]
    people = run(library.authority().people())
    assert people["ante"] == Person("ante", 2, "guest", "Ante", (40, 41), 40)
    assert people["filip"].circle == ()


def test_people_asked_once_for_a_crowd(clock):
    library = Library()
    authority = library.authority()

    async def crowd():
        return await asyncio.gather(*(authority.people() for _ in range(20)))

    run(crowd())
    assert len(library.asked) == 1


def test_people_kept_for_the_ttl_and_forced_at_most_every_pause(clock):
    library = Library()
    authority = library.authority()
    run(authority.people())
    clock.now += 1
    run(authority.people())
    run(authority.people(force=True))
    assert len(library.asked) == 1
    clock.now += Authority.PAUSE
    run(authority.people(force=True))
    assert len(library.asked) == 2
    clock.now += Authority.TTL
    run(authority.people())
    assert len(library.asked) == 3


def test_forget_asks_again_at_once(clock):
    library = Library()
    authority = library.authority()
    run(authority.people())
    authority.forget()
    run(authority.people())
    assert len(library.asked) == 2


def test_current_follows_a_password_changed_a_moment_ago(clock):
    library = Library()
    authority = library.authority()
    run(authority.people())
    library.people = [FILIP | {"version": 4}, BOSS]
    clock.now += Authority.PAUSE
    assert run(authority.current("filip", 4)) == Person("filip", 4, "user", "Filip", person_id=12)
    assert run(authority.current("filip", 3)) is None


def test_current_refuses_a_stale_cookie_without_asking_again(clock):
    library = Library()
    authority = library.authority()
    assert run(authority.current("filip", 2)) is None
    asked = len(library.asked)
    for _ in range(25):
        clock.now += Authority.PAUSE
        assert run(authority.current("filip", 2)) is None
    assert len(library.asked) == asked
    clock.now += Authority.TTL
    for _ in range(25):
        clock.now += Authority.PAUSE
        assert run(authority.current("filip", 2)) is None
    assert len(library.asked) == asked + 1


def test_current_does_not_refuse_on_a_copy_it_could_not_refresh(clock):
    library = Library()
    authority = library.authority()
    run(authority.people())
    library.people = [FILIP | {"version": 4}, BOSS]
    clock.now += 0.5
    assert run(authority.current("filip", 4)) is None
    clock.now += Authority.PAUSE
    assert run(authority.current("filip", 4)) == Person("filip", 4, "user", "Filip", person_id=12)


def test_switched_off_and_removed_are_nobody(clock):
    library = Library()
    authority = library.authority()
    assert run(authority.current("kata", 5)) is None
    assert run(authority.current("stranger", 1)) is None


@pytest.mark.parametrize("failure", [
    lambda request: httpx.Response(401, json={"detail": "authentication required"}),
    lambda request: httpx.Response(200, text="not json"),
    lambda request: httpx.Response(200, json={"people": [{"name": "filip"}]}),
    lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused", request=request)),
])
def test_unavailable_keeps_what_was_known_and_says_so_once(clock, caplog, failure):
    library = Library()
    authority = library.authority()
    run(authority.people())
    library.answer = failure
    caplog.set_level(logging.WARNING, logger=module.__name__)
    for _ in range(3):
        clock.now += Authority.TTL
        assert set(run(authority.people())) == {"filip", "boss"}
    assert len(caplog.records) == 1


def test_a_positive_session_expires_after_a_bounded_authority_outage(clock):
    library = Library()
    authority = library.authority()
    assert run(authority.current("filip", 3)) == Person("filip", 3, "user", "Filip", person_id=12)
    library.answer = lambda request: httpx.Response(503)

    clock.now += Authority.TTL
    assert run(authority.current("filip", 3)) == Person("filip", 3, "user", "Filip", person_id=12)
    clock.now += Authority.MAX_STALE
    assert run(authority.current("filip", 3)) is None


def test_nothing_known_while_unavailable_from_the_start(clock):
    library = Library()
    library.answer = lambda request: httpx.Response(503)
    assert run(library.authority().people()) == {}


def verdict(status: int, body=None, headers=None):
    def answer(request: httpx.Request) -> httpx.Response:
        if isinstance(body, str):
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(status, json=body, headers=headers)
    return answer


def test_verify_payload_and_answer(clock):
    library = Library()
    library.answer = verdict(200, {"ok": True, **FILIP})
    authority = library.authority()
    assert run(authority.verify("Filip", "secret words", "1.2.3.4")) == Person("filip", 3, "user", "Filip")
    (asked,) = library.asked
    assert asked.method == "POST"
    assert str(asked.url) == "http://library:8095/api/auth/verify"
    assert json.loads(asked.content) == {"username": "Filip", "password": "secret words"}
    assert asked.headers["X-OPUS-Token"] == TOKEN
    assert asked.headers["X-Forwarded-For"] == "1.2.3.4"


def test_verify_success_forgets_the_copy(clock):
    library = Library()
    authority = library.authority()
    run(authority.people())
    library.answer = verdict(200, {"ok": True, **FILIP})
    run(authority.verify("filip", "secret words", "1.2.3.4"))
    library.answer = None
    run(authority.people())
    assert [r.url.path for r in library.asked] == ["/api/auth/people", "/api/auth/verify",
                                                   "/api/auth/people"]


def test_verify_wrong_credential_is_none(clock):
    library = Library()
    library.answer = verdict(200, {"ok": False})
    assert run(library.authority().verify("filip", "wrong", "1.2.3.4")) is None


def test_verify_too_many_attempts(clock):
    library = Library()
    library.answer = verdict(429, {"detail": "too many failed attempts"}, {"Retry-After": "42"})
    with pytest.raises(TooManyAttempts) as raised:
        run(library.authority().verify("filip", "wrong", "1.2.3.4"))
    assert raised.value.retry_after == "42"


@pytest.mark.parametrize("answer", [
    verdict(403, {"detail": "only a module may ask this"}),
    verdict(500, "boom"),
    verdict(200, "not json"),
    verdict(200, [1, 2]),
    verdict(200, {"ok": True, "name": "filip"}),
    lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused", request=request)),
])
def test_verify_unavailable(clock, answer):
    library = Library()
    library.answer = answer
    with pytest.raises(AuthorityUnavailable):
        run(library.authority().verify("filip", "secret words", "1.2.3.4"))


CREDENTIAL = {"id": "a2V5", "rawId": "a2V5", "type": "public-key",
              "response": {"clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA"}}


def test_passkey_options_are_library_s(clock):
    library = Library()
    library.answer = verdict(200, {"challenge": "c2lnbg", "rpId": "example.com"})
    assert run(library.authority().passkey_options()) == {"challenge": "c2lnbg", "rpId": "example.com"}
    (asked,) = library.asked
    assert (asked.method, str(asked.url)) == ("POST", "http://library:8095/api/auth/passkey/options")
    assert asked.headers["X-OPUS-Token"] == TOKEN


@pytest.mark.parametrize("answer", [verdict(404, {"detail": "no shared domain"}),
                                    verdict(200, "not json"), verdict(200, [1])])
def test_passkey_options_unavailable(clock, answer):
    library = Library()
    library.answer = answer
    with pytest.raises(AuthorityUnavailable):
        run(library.authority().passkey_options())


def test_passkey_names_the_door_and_the_caller(clock):
    library = Library()
    library.answer = verdict(200, {"ok": True, **FILIP})
    said = run(library.authority().passkey(CREDENTIAL, "https://opus.example.com", "1.2.3.4"))
    assert said == Person("filip", 3, "user", "Filip")
    (asked,) = library.asked
    assert str(asked.url) == "http://library:8095/api/auth/passkey/verify"
    assert json.loads(asked.content) == {"credential": CREDENTIAL, "origin": "https://opus.example.com"}
    assert asked.headers["X-Forwarded-For"] == "1.2.3.4"


def test_passkey_refused_is_none(clock):
    library = Library()
    library.answer = verdict(200, {"ok": False})
    assert run(library.authority().passkey(CREDENTIAL, "https://opus.example.com", "1.2.3.4")) is None

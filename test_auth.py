"""Offline tests for the login and the daily ceiling: auth.py and the sign-in rules in web_app.py.

Run with:  python test_auth.py

Plain asserts. The web tests start the real server on 127.0.0.1 in demo mode and talk to it locally:
no network calls, no API keys, no extra packages.
"""
import http.client
import json
import sys
import threading

import auth
import checker
import lookup
import verdict
import web_app

PASSWORD = "correct horse battery"
USERS = {"manager": auth.hash_password(PASSWORD)}
PUBLIC = "demo.example.com"


class FakeClock:
    """A clock the tests can move forward."""

    def __init__(self):
        """Start at an arbitrary time."""
        self.now = 1_000_000.0

    def __call__(self):
        """Return the current fake time in seconds."""
        return self.now


def refuse_real_call(*args, **kwargs):
    """Stand-in for anything that could go online or read a key: fail loudly if a test reaches it."""
    raise AssertionError("a test tried to make a real API call or read a real key")


REAL = {"lookup_ip": lookup.lookup_ip, "get_verdict": verdict.get_verdict, "lookup_ip_details": lookup.lookup_ip_details,
        "get_client": verdict.get_client}


def block_real_calls():
    """Make any real API function fail loudly, so a test can only pass using fakes."""
    lookup.lookup_ip = refuse_real_call
    lookup.lookup_ip_details = refuse_real_call
    verdict.get_verdict = refuse_real_call
    verdict.get_client = refuse_real_call


class Site:
    """A real web server in demo mode on a free local port, run in a background thread for one test."""

    def __init__(self, public=False, users=USERS, live=False, daily_limit=700):
        """Start serving. public=True makes it answer to PUBLIC like a hosted copy (still listening only on 127.0.0.1)."""
        self.server = web_app.build_server(live, 0, PUBLIC if public else None, users, daily_limit, bind_address="127.0.0.1")
        self.port = self.server.server_port
        self.host = PUBLIC if public else f"127.0.0.1:{self.port}"
        self.origin = f"https://{PUBLIC}" if public else f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, cookie=None, host=None, origin=None, forwarded=None):
        """Send one request and return (status, headers, text)."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or self.host}
        if origin is not False:
            headers["Origin"] = origin or self.origin
        if cookie:
            headers["Cookie"] = cookie
        if forwarded:
            headers["X-Forwarded-For"] = forwarded
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        connection.request(method, path, payload, headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8")
        result = (response.status, response, text)
        connection.close()
        return result

    def sign_in(self, password=PASSWORD, forwarded=None):
        """Sign in as the manager and return the session cookie, or None if it was refused."""
        status, response, _ = self.request("POST", "/login", {"username": "manager", "password": password}, forwarded=forwarded)
        cookie = response.getheader("Set-Cookie")
        return cookie.split(";")[0] if status == 200 and cookie else None

    def stop(self):
        """Stop serving and close the port."""
        self.server.shutdown()
        self.server.server_close()


def with_site(**options):
    """Decorator: run a test with a started Site passed in, and always stop it afterwards."""
    def decorate(test):
        """Wrap test so it gets its own Site."""
        def wrapper():
            """Start a Site, run the test, stop the Site."""
            site = Site(**options)
            try:
                test(site)
            finally:
                site.stop()
        wrapper.__name__ = test.__name__
        return wrapper
    return decorate


# ---------------------------------------------------------------- auth.py


def test_password_hashing():
    """A password verifies against its own hash only, hashes are salted, and a damaged hash never verifies."""
    stored = auth.hash_password("s3cret!")
    assert auth.verify_password("s3cret!", stored)
    assert not auth.verify_password("s3cret", stored) and not auth.verify_password("", stored)
    assert auth.hash_password("s3cret!") != stored, "each hash gets its own random salt"
    assert "s3cret" not in stored
    for broken in ["", "nothex:nothex", "aa", "aa:bb:cc"]:
        assert not auth.verify_password("s3cret!", broken), broken


def test_parse_users():
    """IOC_USERS parses into names and hashes, ignores blanks, and rejects anything malformed."""
    one, two = auth.hash_password("a"), auth.hash_password("b")
    users = auth.parse_users(f"manager={one}, me-office={two},")
    assert users == {"manager": one, "me-office": two}
    assert auth.parse_users("") == {} and auth.parse_users(None) == {}
    for bad in ["manager", "Manager=aa:bb", "man ager=aa:bb", "=aa:bb", "manager=aabb", "manager=zz:yy", "manager=aa:", "manager=:bb"]:
        try:
            auth.parse_users(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted a bad entry: {bad!r}")


def test_login_and_sessions():
    """A right password gives a token that works until it expires or the user signs out."""
    clock = FakeClock()
    gate = auth.Auth(USERS, clock=clock)
    token, problem = gate.login("manager", PASSWORD, "1.2.3.4")
    assert token and problem is None
    assert gate.user_for(token) == "manager"
    assert gate.user_for("made-up") is None and gate.user_for(None) is None

    clock.now += auth.SESSION_SECONDS - 1
    assert gate.user_for(token) == "manager", "still valid just before 12 hours"
    clock.now += 2
    assert gate.user_for(token) is None, "expired after 12 hours"

    token, _ = gate.login("manager", PASSWORD, "1.2.3.4")
    gate.logout(token)
    assert gate.user_for(token) is None


def test_wrong_logins_are_refused_alike():
    """Unknown names, wrong passwords and non-text values are all refused with the same message."""
    gate = auth.Auth(USERS, clock=FakeClock())
    messages = set()
    for username, password in [("manager", "wrong"), ("nobody", PASSWORD), (None, PASSWORD), ("manager", None), ("manager", 12345), (["manager"], {})]:
        token, problem = gate.login(username, password, "9.9.9.9")
        assert token is None
        messages.add(problem)
        gate.failures.clear()
    assert messages == {"wrong username or password"}, messages


def test_lockout_after_five_failures():
    """Five wrong passwords lock an address out, even for the right password, until 15 minutes have passed."""
    clock = FakeClock()
    gate = auth.Auth(USERS, clock=clock)
    for _ in range(auth.MAX_FAILURES):
        assert gate.login("manager", "wrong", "5.5.5.5")[0] is None
    token, problem = gate.login("manager", PASSWORD, "5.5.5.5")
    assert token is None and problem.startswith("too many wrong passwords"), problem
    assert gate.login("manager", PASSWORD, "6.6.6.6")[0], "other addresses are not affected"

    clock.now += auth.LOCKOUT_SECONDS + 1
    assert gate.login("manager", PASSWORD, "5.5.5.5")[0], "the lockout ends"


def test_success_resets_the_failure_count():
    """A correct login clears earlier mistakes, so four slips then a success then four slips is not a lockout."""
    gate = auth.Auth(USERS, clock=FakeClock())
    for _ in range(4):
        gate.login("manager", "wrong", "7.7.7.7")
    assert gate.login("manager", PASSWORD, "7.7.7.7")[0]
    for _ in range(4):
        gate.login("manager", "wrong", "7.7.7.7")
    assert gate.login("manager", PASSWORD, "7.7.7.7")[0]


# ---------------------------------------------------------------- ceiling


def test_daily_ceiling():
    """The ceiling allows exactly its limit of lookups, refuses the rest without calling out, and resets on a new UTC day."""
    day = ["2026-11-08"]
    ceiling = auth.DailyCeiling(3, today=lambda: day[0])
    calls = []
    guarded = ceiling.limited(lambda ip: calls.append(ip) or {"ip": ip, "error": None})
    results = [guarded(f"8.8.8.{n}") for n in range(5)]
    assert [r["error"] for r in results] == [None, None, None, auth.LIMIT_MESSAGE, auth.LIMIT_MESSAGE]
    assert len(calls) == 3, "the refused lookups never reached the function"
    assert ceiling.left() == 0

    day[0] = "2026-11-09"
    assert ceiling.left() == 3
    assert guarded("8.8.8.9")["error"] is None


def test_ceiling_stops_a_check_part_way():
    """With 2 lookups left, a 4-IP check looks up 2, marks the other 2 as failed, and never asks Gemini about them."""
    looked_up, judged = [], []
    lookup.lookup_ip = lambda ip: looked_up.append(ip) or {
        "ip": ip, "score": 90, "country": "ZZ", "isp": "x", "reports": 5, "last_reported": None, "whitelisted": False, "error": None}
    verdict.get_verdict = lambda result: judged.append(result["ip"]) or {"verdict": "malicious", "severity": "high", "reason": "fake", "error": None}
    verdict.get_client = lambda: None  # check_payload asks for the Gemini client first, to stop early if its key is missing
    ceiling = auth.DailyCeiling(2)

    report = web_app.run_check("8.8.8.1 8.8.8.2 8.8.8.3 8.8.8.4", live=True, ceiling=ceiling)
    errors = [r["error"] for r in report["results"]]
    assert errors.count(None) == 2 and errors.count(f"lookup failed: {auth.LIMIT_MESSAGE}") == 2, errors
    assert looked_up == ["8.8.8.1", "8.8.8.2"] and judged == ["8.8.8.1", "8.8.8.2"], (looked_up, judged)


# ---------------------------------------------------------------- the web server


@with_site()
def test_signed_out_visitors_see_only_the_sign_in_page(site):
    """Without a login, / is the sign-in page, and the app, the data and the checks are refused."""
    status, _, page = site.request("GET", "/")
    assert status == 200 and "Sign in" in page and "/login.js" in page and "/app.js" not in page
    for path in ["/status", "/app.js"]:
        assert site.request("GET", path)[0] == 401, path
    assert site.request("POST", "/check", {"text": "8.8.8.8"})[0] == 401
    assert site.request("POST", "/insight", {"ip": "8.8.8.8", "token": "x"})[0] == 401
    for path in ["/style.css", "/login.js", "/favicon.svg"]:
        assert site.request("GET", path)[0] == 200, path


@with_site()
def test_login_cookie_and_signed_in_use(site):
    """A good login sets a script-proof, same-site cookie; with it the app, status and a demo check work; sign-out ends it."""
    status, response, _ = site.request("POST", "/login", {"username": "manager", "password": PASSWORD})
    cookie_header = response.getheader("Set-Cookie")
    assert status == 200
    assert "HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header and "Path=/" in cookie_header
    assert "Secure" not in cookie_header, "a local copy has no HTTPS, so no Secure flag"
    cookie = cookie_header.split(";")[0]

    status, _, page = site.request("GET", "/", cookie=cookie)
    assert status == 200 and "/app.js" in page and "Sign in" not in page.split("<title>")[1].split("</title>")[0]
    status, _, text = site.request("GET", "/status", cookie=cookie)
    info = json.loads(text)
    assert status == 200 and info["user"] == "manager" and info["mode"] == "demo" and info["lookups_left"] is None
    status, _, text = site.request("POST", "/check", {"text": "185.220.101.5 and 8.8.8.8"}, cookie=cookie)
    assert status == 200 and len(json.loads(text)["results"]) == 2

    status, response, _ = site.request("POST", "/logout", cookie=cookie)
    assert status == 200 and "Max-Age=0" in response.getheader("Set-Cookie")
    assert site.request("GET", "/status", cookie=cookie)[0] == 401, "the old cookie no longer works"


@with_site()
def test_login_refusals_and_lockout(site):
    """Wrong logins get 401 and never a cookie, odd bodies get 400, and the sixth try is locked out with 429."""
    status, response, text = site.request("POST", "/login", {"username": "manager", "password": "nope"})
    assert status == 401 and response.getheader("Set-Cookie") is None
    assert "wrong username or password" in text
    assert site.request("POST", "/login", {"username": 5})[0] == 401
    assert site.request("POST", "/login", ["manager"])[0] == 400
    assert site.request("POST", "/login", None)[0] == 415, "no JSON content type"
    site.server.auth.failures.clear()

    for _ in range(auth.MAX_FAILURES):
        assert site.request("POST", "/login", {"username": "manager", "password": "nope"})[0] == 401
    status, response, _ = site.request("POST", "/login", {"username": "manager", "password": PASSWORD})
    assert status == 429 and response.getheader("Set-Cookie") is None


@with_site()
def test_host_and_origin_checks_still_apply(site):
    """Another host name or another website's Origin is refused, signed in or not."""
    cookie = site.sign_in()
    assert cookie
    assert site.request("GET", "/", host="evil.example")[0] == 403
    assert site.request("POST", "/login", {"username": "manager", "password": PASSWORD}, origin="http://evil.example")[0] == 403
    assert site.request("POST", "/check", {"text": "8.8.8.8"}, cookie=cookie, origin="http://evil.example")[0] == 403
    assert site.request("POST", "/logout", cookie=cookie, origin="http://evil.example")[0] == 403
    assert site.request("POST", "/check", {"text": "8.8.8.8"}, cookie=cookie)[0] == 200


@with_site(public=True)
def test_public_copy_uses_https_settings(site):
    """A hosted copy answers only to its own name, sets Secure cookies and HSTS, locks out by the proxy's address, and has a health check."""
    status, response, _ = site.request("POST", "/login", {"username": "manager", "password": PASSWORD}, forwarded="203.0.113.9")
    assert status == 200 and "Secure" in response.getheader("Set-Cookie")
    assert "max-age" in (response.getheader("Strict-Transport-Security") or "")
    assert site.request("GET", "/", host=f"127.0.0.1:{site.port}")[0] == 403, "the raw address is not an allowed host"
    status, _, text = site.request("GET", "/healthz", host="internal-check")
    assert status == 200 and text == "ok"

    # The proxy appends the visitor's address as the LAST entry. Earlier entries are whatever the visitor sent, so they must not count.
    for n in range(auth.MAX_FAILURES):
        site.request("POST", "/login", {"username": "manager", "password": "x"}, forwarded=f"192.0.2.{n}, 198.51.100.1")
    assert site.request("POST", "/login", {"username": "manager", "password": PASSWORD}, forwarded="192.0.2.99, 198.51.100.1")[0] == 429, "faking the first entry does not escape the lockout"
    assert site.request("POST", "/login", {"username": "manager", "password": PASSWORD}, forwarded="198.51.100.77")[0] == 200, "a different visitor is fine"


@with_site(public=True, live=True, daily_limit=0)
def test_live_site_stops_at_the_ceiling(site):
    """When the daily ceiling is used up, a signed-in check or insight gets a 429 and nothing is looked up."""
    cookie = site.sign_in()
    status, _, text = site.request("POST", "/check", {"text": "8.8.8.8"}, cookie=cookie)
    assert status == 429 and "daily limit" in json.loads(text)["error"]
    token = json.loads(site.request("GET", "/status", cookie=cookie)[2])["insight_token"]
    status, _, _ = site.request("POST", "/insight", {"ip": "8.8.8.8", "token": token}, cookie=cookie)
    assert status == 429
    assert json.loads(site.request("GET", "/status", cookie=cookie)[2])["lookups_left"] == 0


def test_server_refuses_unsafe_setups():
    """A public host without logins, or with a path or port in its name, does not start; local use needs no login."""
    for options in [dict(public_host=PUBLIC, users={}), dict(public_host="a/b", users=USERS), dict(public_host="a.com:8000", users=USERS)]:
        try:
            web_app.build_server(False, 0, bind_address="127.0.0.1", **options)
        except SystemExit:
            continue
        raise AssertionError(f"started with {options}")
    local = web_app.build_server(False, 0, bind_address="127.0.0.1")
    try:
        assert local.auth is None and local.ceiling is None and not local.public
    finally:
        local.server_close()


TESTS = [
    test_password_hashing,
    test_parse_users,
    test_login_and_sessions,
    test_wrong_logins_are_refused_alike,
    test_lockout_after_five_failures,
    test_success_resets_the_failure_count,
    test_daily_ceiling,
    test_ceiling_stops_a_check_part_way,
    test_signed_out_visitors_see_only_the_sign_in_page,
    test_login_cookie_and_signed_in_use,
    test_login_refusals_and_lockout,
    test_host_and_origin_checks_still_apply,
    test_public_copy_uses_https_settings,
    test_live_site_stops_at_the_ceiling,
    test_server_refuses_unsafe_setups,
]


def run_all():
    """Run every test, print PASS, FAIL or ERROR for each, and return how many did not pass."""
    failures = 0
    for test in TESTS:
        lookup.lookup_ip, lookup.lookup_ip_details = REAL["lookup_ip"], REAL["lookup_ip_details"]
        verdict.get_verdict, verdict.get_client = REAL["get_verdict"], REAL["get_client"]
        block_real_calls()
        try:
            test()
        except AssertionError as err:
            failures += 1
            print(f"FAIL   {test.__name__}: {err}")
        except Exception as err:
            failures += 1
            print(f"ERROR  {test.__name__}: {type(err).__name__}: {err}")
        else:
            print(f"PASS   {test.__name__}")
    print(f"{len(TESTS) - failures} of {len(TESTS)} tests passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)

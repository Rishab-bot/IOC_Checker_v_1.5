"""Login and a daily ceiling for the hosted IOC Checker. Standard library only.

- Passwords are stored only as scrypt hashes. make_user.py creates one.
- Sessions live in memory: a restart signs everyone out.
- Too many wrong passwords from one address locks that address out for a while.
- DailyCeiling stops live lookups once the site has used its share of the AbuseIPDB day.
"""
import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import datetime, timezone

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
SESSION_SECONDS = 12 * 60 * 60  # a login lasts 12 hours
MAX_FAILURES = 5  # wrong passwords from one address before it is locked out
LOCKOUT_SECONDS = 15 * 60
USERNAME_PATTERN = re.compile(r"^[a-z0-9_-]{1,32}$")
LIMIT_MESSAGE = "site daily limit reached"


def hash_password(password, salt=None):
    """Return 'salt:hash' (both hex) for password. A new random salt is made when none is given."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password, stored):
    """True if password matches a stored 'salt:hash'. The comparison takes the same time either way."""
    try:
        salt_hex, hash_hex = stored.split(":")
        expected = bytes.fromhex(hash_hex)
        actual = bytes.fromhex(hash_password(password, bytes.fromhex(salt_hex)).split(":")[1])
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


def parse_users(text):
    """Turn 'name=salt:hash,name2=salt:hash' into {name: 'salt:hash'}. Raises ValueError for anything malformed."""
    users = {}
    for entry in (text or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, separator, stored = entry.partition("=")
        if not separator or not USERNAME_PATTERN.match(name):
            raise ValueError(f"bad user entry (names use a-z, 0-9, _ and -): {name[:20]!r}")
        salt_hex, colon, hash_hex = stored.partition(":")
        try:
            bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        except ValueError:
            raise ValueError(f"user {name!r} does not have a valid hash") from None
        if not colon or not salt_hex or not hash_hex:
            raise ValueError(f"user {name!r} does not have a valid hash")
        users[name] = stored
    return users


class Auth:
    """Checks logins, hands out session tokens, and locks out addresses that keep failing."""

    def __init__(self, users, clock=time.time):
        """users is {name: 'salt:hash'}. clock returns the current time in seconds (replaced in tests)."""
        self.users = users
        self.clock = clock
        self.sessions = {}  # token -> (username, expires)
        self.failures = {}  # client address -> (failure count, time of the last failure)
        self.lock = threading.Lock()
        self.decoy = hash_password("not a real password")  # keeps unknown names as slow as real ones

    def locked_for(self, client):
        """Seconds left on client's lockout, or 0 if it can try."""
        with self.lock:
            count, last = self.failures.get(client, (0, 0))
            remaining = last + LOCKOUT_SECONDS - self.clock()
            if count >= MAX_FAILURES and remaining > 0:
                return int(remaining) + 1
            if count >= MAX_FAILURES:
                del self.failures[client]
            return 0

    def login(self, username, password, client):
        """Return (token, None) on success, or (None, message) when the login is refused."""
        wait = self.locked_for(client)
        if wait:
            return None, f"too many wrong passwords; try again in {max(1, wait // 60)} minutes"

        stored = self.users.get(username) if isinstance(username, str) else None
        ok = verify_password(password if isinstance(password, str) else "", stored or self.decoy)
        if not (ok and stored):
            with self.lock:
                count, _ = self.failures.get(client, (0, 0))
                self.failures[client] = (count + 1, self.clock())
            return None, "wrong username or password"

        with self.lock:
            self.failures.pop(client, None)
            now = self.clock()
            self.sessions = {t: s for t, s in self.sessions.items() if s[1] > now}
            token = secrets.token_urlsafe(32)
            self.sessions[token] = (username, now + SESSION_SECONDS)
        return token, None

    def user_for(self, token):
        """Return the username for a live session token, or None."""
        if not isinstance(token, str):
            return None
        with self.lock:
            session = self.sessions.get(token)
            if session and session[1] > self.clock():
                return session[0]
            self.sessions.pop(token, None)
            return None

    def logout(self, token):
        """End the session for token, if there is one."""
        with self.lock:
            self.sessions.pop(token, None)


class DailyCeiling:
    """Counts live AbuseIPDB lookups per UTC day (AbuseIPDB's day) and refuses once the ceiling is reached."""

    def __init__(self, limit, today=None):
        """limit is the most lookups per day. today returns the current day label (replaced in tests)."""
        self.limit = limit
        self.today = today or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        self.day = self.today()
        self.used = 0
        self.lock = threading.Lock()

    def roll_over(self):
        """Start a new count when the UTC day has changed. Call with the lock held."""
        if self.today() != self.day:
            self.day, self.used = self.today(), 0

    def take(self):
        """Use one lookup. False, and nothing used, if the ceiling has been reached."""
        with self.lock:
            self.roll_over()
            if self.used >= self.limit:
                return False
            self.used += 1
            return True

    def left(self):
        """Lookups still available today."""
        with self.lock:
            self.roll_over()
            return max(0, self.limit - self.used)

    def limited(self, function):
        """Wrap a lookup function so it returns an error result, without calling the API, once the ceiling is reached."""
        def wrapper(ip):
            """Call function(ip) if a lookup is left today."""
            if not self.take():
                return {"ip": ip, "error": LIMIT_MESSAGE}
            return function(ip)
        return wrapper

"""Breached-password lookup using the Have I Been Pwned range API.

The lookup uses k-anonymity: the password is hashed locally with SHA-1 and only
the first five hex characters of the hash are sent. The API returns every known
hash suffix that shares that prefix, and the comparison happens on this machine.
The password and its full hash never leave the process.

API docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
import urllib.request
from collections.abc import Callable

API_URL = "https://api.pwnedpasswords.com/range/"
DEFAULT_TIMEOUT = 10.0
USER_AGENT = "pwcheck (https://github.com/YOUR-USERNAME/pwcheck)"
PREFIX_LENGTH = 5


class BreachCheckError(RuntimeError):
    """Raised when the breach lookup could not be completed."""


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    """Return the (5-char prefix, remaining suffix) of the password's uppercase SHA-1."""
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def parse_range_response(body: str, suffix: str) -> int:
    """Find ``suffix`` in a range response and return its breach count (0 if absent).

    Each line looks like ``SUFFIX:COUNT``. When padding is requested the API adds
    fake entries with a count of 0, which naturally read as "not found".
    """
    wanted = suffix.upper()
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == wanted:
            try:
                return max(int(count), 0)
            except ValueError:
                return 0
    return 0


def _fetch_range(prefix: str, timeout: float) -> str:
    request = urllib.request.Request(
        API_URL + prefix,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except (OSError, ValueError) as exc:
        raise BreachCheckError(f"could not reach the Pwned Passwords API: {exc}") from exc


def count_breaches(
    password: str,
    *,
    fetch: Callable[[str], str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> int:
    """Return how many times the password appears in known breaches (0 if never).

    ``fetch`` takes the 5-character hash prefix and returns the raw range response.
    It exists so tests can run without network access; it only ever receives the prefix.
    """
    prefix, suffix = sha1_prefix_suffix(password)
    body = fetch(prefix) if fetch is not None else _fetch_range(prefix, timeout)
    return parse_range_response(body, suffix)

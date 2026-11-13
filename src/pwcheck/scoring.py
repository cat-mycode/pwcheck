"""Password strength scoring.

The score is a heuristic built on an *estimated* entropy figure: the size of the
character pool a password draws from, multiplied by its effective length, minus
penalties for patterns attackers try first (repeats, alphabet/keyboard runs,
years, repeated chunks). Passwords on the built-in common list are capped hard.

It is a quick sanity check, not a guarantee. See the README for limitations.
"""

import math
import re
from dataclasses import asdict, dataclass, field

from .common import COMMON_PASSWORDS

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
SCORE_CAP_SHORT = 30
ENTROPY_CAP_COMMON = 10.0

_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
_POOL_SIZES = {"lower": 26, "upper": 26, "digit": 10, "symbol": 33, "other": 100}
_LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_LEET = str.maketrans(
    {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"}
)
_REPEAT_RE = re.compile(r"(.)\1{2,}", re.IGNORECASE | re.DOTALL)
_BLOCK_RE = re.compile(r"(.{2,4}?)\1+", re.IGNORECASE | re.DOTALL)
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
_EDGE_RE = re.compile(r"^[^a-z]+|[^a-z]+$")


@dataclass(frozen=True)
class StrengthResult:
    """The outcome of scoring one password. Never contains the password itself."""

    score: int
    label: str
    entropy_bits: float
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["entropy_bits"] = round(self.entropy_bits, 1)
        return data


def character_classes(password: str) -> set[str]:
    """Return which character classes the password uses."""
    classes: set[str] = set()
    for char in password:
        if char in _LOWER:
            classes.add("lower")
        elif char in _UPPER:
            classes.add("upper")
        elif char in _DIGITS:
            classes.add("digit")
        elif ord(char) < 128:
            classes.add("symbol")
        else:
            classes.add("other")
    return classes


def find_sequences(password: str, min_length: int = 3) -> list[str]:
    """Find runs that follow alphabet, digit or keyboard-row order (either direction)."""
    lowered = password.lower()
    intervals: list[tuple[int, int]] = []
    for source in _SEQUENCES:
        for sequence in (source, source[::-1]):
            for start in range(len(lowered) - min_length + 1):
                if lowered[start : start + min_length] in sequence:
                    intervals.append((start, start + min_length))
    intervals.sort()
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [password[start:end] for start, end in merged]


def find_repeats(password: str) -> list[str]:
    """Find runs of three or more identical characters."""
    return [match.group(0) for match in _REPEAT_RE.finditer(password)]


def _repeated_blocks(password: str) -> list[tuple[str, str]]:
    """Find repeated multi-character chunks such as 'abab' or '123123'."""
    found = []
    for match in _BLOCK_RE.finditer(password):
        block = match.group(1)
        if len({char.lower() for char in block}) > 1:
            found.append((match.group(0), block))
    return found


def is_common_password(password: str) -> bool:
    """True if the password (or a trivial variation) is on the built-in common list."""
    lowered = password.lower()
    leeted = lowered.translate(_LEET)
    core = _EDGE_RE.sub("", lowered)  # strip leading/trailing digits and symbols first...
    candidates = {
        lowered,
        leeted,
        core,
        core.translate(_LEET),  # ...then undo leetspeak, so "P@ssw0rd2019" -> "password"
        _EDGE_RE.sub("", leeted),
    }
    candidates.discard("")
    return not candidates.isdisjoint(COMMON_PASSWORDS)


def _pattern_penalty(password: str) -> int:
    penalty = sum(len(run) - 1 for run in find_sequences(password))
    penalty += sum(len(run) - 1 for run in find_repeats(password))
    penalty += sum(len(text) - len(block) for text, block in _repeated_blocks(password))
    penalty += 2 * len(_YEAR_RE.findall(password))
    return penalty


def estimate_entropy(password: str) -> float:
    """Estimate entropy in bits: effective length x log2(character pool size)."""
    if not password:
        return 0.0
    pool = sum(_POOL_SIZES[name] for name in character_classes(password))
    effective_length = max(1, len(password) - _pattern_penalty(password))
    return effective_length * math.log2(pool)


def label_for_score(score: int) -> str:
    if score < 20:
        return "Very weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very strong"


def evaluate(password: str) -> StrengthResult:
    """Score a password from 0 to 100 and explain what drags it down."""
    if not password:
        return StrengthResult(
            score=0,
            label="Very weak",
            entropy_bits=0.0,
            issues=["Password is empty."],
            suggestions=["Enter a password to check."],
        )

    issues: list[str] = []
    suggestions: list[str] = []
    length = len(password)
    bits = estimate_entropy(password)

    if is_common_password(password):
        bits = min(bits, ENTROPY_CAP_COMMON)
        issues.append("Matches a very common password (or a trivial variation of one).")
        suggestions.append("Avoid common words and predictable swaps like '@' for 'a'.")

    score = min(100, round(bits))

    if length < MIN_LENGTH:
        score = min(score, SCORE_CAP_SHORT)
        issues.append(f"Too short ({length} characters; at least {MIN_LENGTH} recommended).")
    if length < RECOMMENDED_LENGTH:
        suggestions.append(
            f"Use at least {RECOMMENDED_LENGTH} characters; length matters more than complexity."
        )
    if find_sequences(password):
        issues.append("Contains predictable sequences (such as abc, 123 or qwerty).")
    if find_repeats(password) or _repeated_blocks(password):
        issues.append("Contains repeated characters or repeated chunks.")
    if _YEAR_RE.search(password):
        issues.append("Contains something that looks like a year.")
    if len(character_classes(password)) < 3 and length < 16:
        suggestions.append("Mix in more character types (lowercase, uppercase, digits, symbols).")
    if score < 60:
        suggestions.append(
            "Try a random passphrase of four or more unrelated words, "
            "or let a password manager generate one."
        )

    return StrengthResult(
        score=score,
        label=label_for_score(score),
        entropy_bits=bits,
        issues=issues,
        suggestions=suggestions,
    )

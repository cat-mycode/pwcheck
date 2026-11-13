"""Command-line interface for pwcheck."""

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from . import __version__
from .breach import DEFAULT_TIMEOUT, BreachCheckError, count_breaches
from .scoring import StrengthResult, evaluate

EXIT_OK = 0
EXIT_WEAK = 1
EXIT_ERROR = 2
PASS_THRESHOLD = 60

_COLORS = {
    "Very weak": "31",
    "Weak": "31",
    "Fair": "33",
    "Strong": "32",
    "Very strong": "32",
}


@dataclass(frozen=True)
class BreachOutcome:
    status: str  # "found", "clean", "skipped" or "error"
    count: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "checked": self.status in ("found", "clean"),
            "found": {"found": True, "clean": False}.get(self.status),
            "count": self.count,
            "error": self.error,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Check password strength and whether it appears in known data breaches.",
        epilog=(
            "The password is never taken as an argument (it would leak into shell history "
            "and process lists). It is read from a hidden prompt, or from stdin with --stdin. "
            "Exit codes: 0 = strong and not breached, 1 = weak or breached, 2 = usage error."
        ),
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from the first line of standard input instead of prompting",
    )
    parser.add_argument(
        "--no-breach",
        action="store_true",
        help="skip the online breach check and run fully offline",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="network timeout in seconds for the breach check (default: %(default)s)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_password(use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("Password to check (input hidden): ")


def lookup_breaches(password: str, skip: bool, timeout: float) -> BreachOutcome:
    if skip:
        return BreachOutcome("skipped")
    try:
        count = count_breaches(password, timeout=timeout)
    except BreachCheckError as exc:
        return BreachOutcome("error", error=str(exc))
    return BreachOutcome("found" if count else "clean", count=count)


def _use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _describe_breach(breach: BreachOutcome, color: bool) -> str:
    if breach.status == "found":
        text = f"FOUND in {breach.count:,} known breach records. Do not use this password."
        return _paint(text, "31", color)
    if breach.status == "clean":
        return _paint("Not found in known breaches.", "32", color)
    if breach.status == "error":
        return f"Check failed ({breach.error}). Result unknown."
    return "Not checked (offline mode)."


def render_report(result: StrengthResult, breach: BreachOutcome, color: bool = False) -> str:
    label = _paint(result.label, _COLORS[result.label], color)
    lines = [
        f"Strength : {label} ({result.score}/100) {_bar(result.score)}",
        f"Entropy  : ~{result.entropy_bits:.1f} bits (estimate)",
        f"Breaches : {_describe_breach(breach, color)}",
    ]
    if result.issues:
        lines += ["", "Issues:"] + [f"  - {issue}" for issue in result.issues]
    if result.suggestions:
        lines += ["", "Suggestions:"] + [f"  - {tip}" for tip in result.suggestions]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        password = read_password(args.stdin)
    except (EOFError, KeyboardInterrupt):
        password = ""
    if not password:
        print("No password provided.", file=sys.stderr)
        return EXIT_ERROR

    result = evaluate(password)
    breach = lookup_breaches(password, skip=args.no_breach, timeout=args.timeout)

    if args.json:
        payload = result.to_dict()
        payload["breach"] = breach.to_dict()
        print(json.dumps(payload, indent=2))
    else:
        print(render_report(result, breach, color=_use_color(sys.stdout)))

    failed = breach.status == "found" or result.score < PASS_THRESHOLD
    return EXIT_WEAK if failed else EXIT_OK

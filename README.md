# pwcheck

[![CI](https://github.com/cat-mycode/pwcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/cat-mycode/pwcheck/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small, dependency-free command-line tool that tells you how strong a password is **and** whether it has appeared in a known data breach, without ever sending the password anywhere.

- **Strength scoring** from 0 to 100 with plain-English reasons and suggestions
- **Breach lookup** against [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity (only 5 characters of a SHA-1 hash leave your machine)
- **Safe by design**: the password is never a command-line argument, never printed, never logged
- **Script-friendly**: `--json` output and meaningful exit codes
- **Zero runtime dependencies**: standard library only

## Install

```bash
git clone https://github.com/cat-mycode/pwcheck.git
cd pwcheck
pip install .
```

Or run it without installing: `python -m pwcheck` (from the `src` directory).

## Usage

```bash
pwcheck                      # hidden prompt, then strength + breach check
pwcheck --no-breach          # fully offline, no network calls
pwcheck --json               # machine-readable output
echo 'my-password' | pwcheck --stdin   # read from stdin (for scripts/password managers)
```

Example (offline mode, a random 16-character password):

```text
Strength : Very strong (100/100) [####################]
Entropy  : ~105.1 bits (estimate)
Breaches : Not checked (offline mode).
```

Example (a common password with a leetspeak swap and a year):

```text
Strength : Very weak (10/100) [##------------------]
Entropy  : ~10.0 bits (estimate)
Breaches : Not checked (offline mode).

Issues:
  - Matches a very common password (or a trivial variation of one).
  - Contains something that looks like a year.

Suggestions:
  - Avoid common words and predictable swaps like '@' for 'a'.
  - Try a random passphrase of four or more unrelated words, or let a password manager generate one.
```

When the breach check is on and the password is found, the `Breaches` line reads
`FOUND in N known breach records. Do not use this password.` and the exit code is `1`.
If the lookup fails (for example, you're offline), the tool says so and falls back to the strength score alone.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Score is 60 or higher **and** the password was not found in a breach |
| `1`  | Score is below 60, **or** the password was found in a breach |
| `2`  | Usage error (no password given, bad option) |

### JSON output

```json
{
  "score": 10,
  "label": "Very weak",
  "entropy_bits": 10.0,
  "issues": ["Matches a very common password (or a trivial variation of one)."],
  "suggestions": ["Avoid common words and predictable swaps like '@' for 'a'."],
  "breach": { "checked": false, "found": null, "count": null, "error": null }
}
```

The password itself is never included in any output.

## How the breach check stays private

This uses the Pwned Passwords **range API**, which is designed so the service never learns what you looked up:

1. The password is hashed locally with SHA-1, e.g. `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
2. Only the first 5 characters (`5BAA6`) are sent to `api.pwnedpasswords.com/range/5BAA6`.
3. The API replies with every known hash *suffix* that shares that prefix, along with breach counts.
4. pwcheck looks for your suffix in that list **locally**.

Requests also send `Add-Padding: true`, so response sizes don't hint at which bucket you queried. SHA-1 is used here only because the API requires it, not for any security purpose.

## How the score works

The score is the estimated entropy in bits (capped at 100), computed as:

```text
effective_length x log2(size of the character pool used)
```

- The pool grows with each character class present: lowercase (26), uppercase (26), digits (10), symbols (33), other Unicode (100).
- `effective_length` is the real length minus penalties for patterns attackers try first: runs like `abc`, `321` or `qwerty`, repeated characters, repeated chunks like `abab`, and years.
- Passwords on a built-in common-password list (including leetspeak and trailing-digit variants such as `P@ssw0rd2019`) are capped at 10.
- Anything shorter than 8 characters is capped at 30.

| Score | Label |
| ----- | ----- |
| 0-19  | Very weak |
| 20-39 | Weak |
| 40-59 | Fair |
| 60-79 | Strong |
| 80-100 | Very strong |

## Limitations

pwcheck is a quick sanity check, not a guarantee. Be aware that:

- The entropy figure is **character-based**. A passphrase made of dictionary words is overrated, because the tool doesn't model word lists the way full estimators such as [zxcvbn](https://github.com/dropbox/zxcvbn) do.
- The built-in common-password list is deliberately small. The breach lookup covers the long tail, which is why it's on by default.
- A password that isn't in any breach can still be weak, and a strong score says nothing about how the site you use it on stores it.
- The best protection is a unique, randomly generated password per site, kept in a password manager, plus multi-factor authentication.

## Development

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

pytest                           # run the tests (no network needed)
ruff check .                     # lint
```

The tests never touch the network: the breach module accepts an injectable `fetch` function, and one test asserts that only the 5-character prefix is ever passed to it.

### Project layout

```text
src/pwcheck/
  scoring.py   # entropy estimate, pattern detection, score + feedback
  breach.py    # SHA-1 split, HIBP range lookup, response parsing
  common.py    # built-in list of very common passwords
  cli.py       # argparse CLI, report rendering, exit codes
tests/         # pytest suite
.github/workflows/ci.yml
```

## Ideas for contributions

- Word-list aware scoring (dictionary words, names, keyboard walks)
- A secure password / passphrase generator subcommand
- Batch mode for checking a file of hashes
- Packaging for PyPI

## License

[MIT](LICENSE)

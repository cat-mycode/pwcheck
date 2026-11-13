import io
import json

import pytest

from pwcheck import __version__, cli
from pwcheck.breach import BreachCheckError

STRONG = "t7#Qv!9mLx2@Wz8$"


def run(monkeypatch, capsys, argv, stdin_text):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_strong_password_offline_exits_zero(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["--stdin", "--no-breach"], STRONG + "\n")
    assert code == 0
    assert "Very strong" in out
    assert "Not checked" in out
    assert STRONG not in out


def test_weak_password_exits_one(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["--stdin", "--no-breach"], "password\n")
    assert code == 1
    assert "Very weak" in out
    assert "Issues:" in out


def test_json_output_has_no_password(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["--stdin", "--no-breach", "--json"], STRONG + "\n")
    data = json.loads(out)
    assert code == 0
    assert data["score"] == 100
    assert data["breach"]["checked"] is False
    assert data["breach"]["found"] is None
    assert STRONG not in out


def test_breached_password_fails_even_if_strong(monkeypatch, capsys):
    monkeypatch.setattr(cli, "count_breaches", lambda password, timeout: 7)
    code, out, _ = run(monkeypatch, capsys, ["--stdin"], STRONG + "\n")
    assert code == 1
    assert "FOUND in 7" in out


def test_clean_password_passes_breach_check(monkeypatch, capsys):
    monkeypatch.setattr(cli, "count_breaches", lambda password, timeout: 0)
    code, out, _ = run(monkeypatch, capsys, ["--stdin", "--json"], STRONG + "\n")
    data = json.loads(out)
    assert code == 0
    assert data["breach"] == {"checked": True, "found": False, "count": 0, "error": None}


def test_breach_lookup_failure_is_reported_not_fatal(monkeypatch, capsys):
    def offline(password, timeout):
        raise BreachCheckError("offline")

    monkeypatch.setattr(cli, "count_breaches", offline)
    code, out, _ = run(monkeypatch, capsys, ["--stdin"], STRONG + "\n")
    assert code == 0
    assert "Check failed (offline)" in out


def test_empty_input_is_a_usage_error(monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys, ["--stdin"], "")
    assert code == 2
    assert "No password provided" in err


def test_password_cannot_be_passed_as_an_argument(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunter2"])
    assert exc.value.code == 2


def test_timeout_must_be_positive():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--stdin", "--timeout", "0"])
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out

import pytest

from pwcheck.scoring import (
    estimate_entropy,
    evaluate,
    find_repeats,
    find_sequences,
    is_common_password,
    label_for_score,
)

STRONG = "t7#Qv!9mLx2@Wz8$"


def test_empty_password_scores_zero():
    result = evaluate("")
    assert result.score == 0
    assert result.label == "Very weak"
    assert result.issues


@pytest.mark.parametrize(
    "password",
    [
        "password",
        "123456",
        "P@ssw0rd",
        "p4ssw0rd",
        "Password1!",
        "QWERTY",
        "letmein123",
        "P@ssw0rd2019",  # leetspeak + trailing year
        "Passw0rd!2024",
        "@dmin",
    ],
)
def test_common_passwords_are_flagged_and_capped(password):
    assert is_common_password(password)
    result = evaluate(password)
    assert result.score <= 10
    assert result.label == "Very weak"


def test_unique_password_is_not_common():
    assert not is_common_password("Zq9!vLm2#x")


def test_short_passwords_are_capped_and_explained():
    result = evaluate("aZ9$kP!")
    assert result.score <= 30
    assert any("short" in issue.lower() for issue in result.issues)


def test_long_random_password_is_very_strong():
    result = evaluate(STRONG)
    assert result.label == "Very strong"
    assert result.score == 100
    assert not result.issues


def test_long_passphrase_scores_well():
    assert evaluate("correct horse battery staple").score >= 80


def test_unicode_passwords_do_not_crash():
    result = evaluate("pässwörd-ünïcode-ключ")
    assert 0 <= result.score <= 100


def test_year_is_reported():
    result = evaluate("Xk$Lm2019")
    assert any("year" in issue.lower() for issue in result.issues)


def test_sequences_are_found_in_both_directions_and_on_the_keyboard():
    assert find_sequences("abc123xyz") == ["abc", "123", "xyz"]
    assert find_sequences("cba") == ["cba"]
    assert find_sequences("QWERTY") == ["QWERTY"]


def test_no_false_sequences():
    assert find_sequences("x7!kq") == []


def test_repeats():
    assert find_repeats("xaaay") == ["aaa"]
    assert find_repeats("abab") == []


def test_patterns_reduce_entropy():
    assert estimate_entropy("aaaaaaaaaa") < estimate_entropy("kqzvwpmxrt")
    assert estimate_entropy("abababababab") < estimate_entropy("kqzvwpmxrtyh")


def test_more_length_means_more_entropy():
    assert estimate_entropy("kqzvwpmxrt") < estimate_entropy("kqzvwpmxrtbjdf")


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (0, "Very weak"),
        (19, "Very weak"),
        (20, "Weak"),
        (39, "Weak"),
        (40, "Fair"),
        (59, "Fair"),
        (60, "Strong"),
        (79, "Strong"),
        (80, "Very strong"),
        (100, "Very strong"),
    ],
)
def test_label_boundaries(score, label):
    assert label_for_score(score) == label


def test_report_never_contains_the_password():
    password = "Zq9!Zq9!abc2020"
    assert password not in str(evaluate(password))

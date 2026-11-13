"""A small built-in list of very common passwords.

This list is intentionally short. It catches the worst offenders instantly and
offline; the breach lookup in ``breach.py`` covers the long tail.
"""

COMMON_PASSWORDS: frozenset[str] = frozenset(
    """
    password password1 password12 password123 passw0rd passpass pass pass123
    123456 1234567 12345678 123456789 1234567890 12345 1234 111111 000000
    123123 654321 666666 121212 112233 987654321 123321 7777777 555555
    qwerty qwerty123 qwertyuiop qwe123 qazwsx zaq12wsx 1qaz2wsx 1q2w3e 1q2w3e4r
    asdfgh asdfghjkl zxcvbnm abc123 abcd1234 abcdef
    letmein welcome welcome1 login admin admin123 administrator root toor
    master dragon monkey football baseball basketball soccer hockey
    iloveyou princess sunshine shadow superman batman trustno1 whatever
    freedom michael jessica ashley charlie jordan hunter buster thomas
    tigger robert daniel andrew joshua matthew george summer winter spring
    autumn secret test test123 guest default changeme hello hello123 access
    flower starwars pokemon mustang ferrari harley ranger cheese cookie
    chocolate computer internet killer love lovely google facebook naruto
    liverpool arsenal chelsea barcelona football1 baseball1 samsung
    """.split()
)

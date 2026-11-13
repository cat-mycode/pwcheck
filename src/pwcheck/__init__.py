"""pwcheck: password strength checking with a privacy-preserving breach lookup."""

from .breach import BreachCheckError, count_breaches
from .scoring import StrengthResult, evaluate

__version__ = "0.1.0"

__all__ = [
    "BreachCheckError",
    "StrengthResult",
    "__version__",
    "count_breaches",
    "evaluate",
]

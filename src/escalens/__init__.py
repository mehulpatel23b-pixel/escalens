"""escalens - offline AWS IAM privilege-escalation auditor."""

from .engine import AnalysisResult, Finding, PolicyRef, Principal, analyze, evaluate_principal
from .loader import LoaderError, load_path
from .rules import BY_ID, CATALOG, Rule

__version__ = "1.0.0"
__all__ = [
    "AnalysisResult",
    "BY_ID",
    "CATALOG",
    "Finding",
    "LoaderError",
    "PolicyRef",
    "Principal",
    "Rule",
    "analyze",
    "evaluate_principal",
    "load_path",
    "__version__",
]

"""GitGrave Engine defensive GitHub exposure scanner."""

from .scanner import (
    AuditStep,
    HeuristicFinding,
    SecretFinding,
    SecurityAuditTracker,
    SinkTrace,
    scan_target,
    scout_target,
    write_report_package,
)
from .secrets import resolve_github_token

__all__ = [
    "AuditStep",
    "HeuristicFinding",
    "SecretFinding",
    "SecurityAuditTracker",
    "SinkTrace",
    "resolve_github_token",
    "scan_target",
    "scout_target",
    "write_report_package",
]
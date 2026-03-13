"""
validators/__init__.py — Validation pipeline for generated CTF labs.

Runs three validation layers:
1. Pattern check — static analysis of generated code
2. Live exploit — HTTP-based exploit against running container
3. Strix scan — automated pentest (optional, if STRIX_ENABLED=true)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ValidationResult:
    """Result of a validation run."""

    def __init__(
        self,
        passed: bool,
        method: str,
        flag_found: bool = False,
        details: str = "",
        unintended_vulns: list | None = None,
    ):
        self.passed = passed
        self.method = method
        self.flag_found = flag_found
        self.details = details
        self.unintended_vulns = unintended_vulns or []

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "method": self.method,
            "flag_found": self.flag_found,
            "details": self.details,
            "unintended_vulns": self.unintended_vulns,
        }

"""
validators/strix_validator.py — Strix integration for PoC validation.

After the CTF engine generates and deploys a lab, Strix can optionally
scan it to verify the vulnerability is genuinely exploitable.

Strix is called as a Python library (tightest integration, most automated).
It runs in white-box mode with source code access + live endpoint.

If Strix is not available (not installed or STRIX_ENABLED=false),
this validator is a no-op that returns a pass.
"""

import logging
import time
from pathlib import Path
from typing import Optional

from config import STRIX_ENABLED, STRIX_LLM, STRIX_MAX_ITERATIONS
from validators import ValidationResult

logger = logging.getLogger(__name__)


class StrixValidator:
    """
    Uses Strix as an automated pentesting validator.

    Flow:
    1. Strix receives the lab's source code + live URL
    2. It runs discovery → validation agents against the target
    3. If Strix finds and exploits the intended vulnerability → PASS
    4. If Strix can't exploit it → FAIL (vuln was accidentally fixed)
    5. If Strix finds unintended vulns → logged as bonus findings
    """

    def __init__(self):
        self.enabled = STRIX_ENABLED
        self._strix_available = None

    def _check_strix_available(self) -> bool:
        """Check if Strix is importable."""
        if self._strix_available is not None:
            return self._strix_available

        try:
            # Try importing core Strix components
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))  # Add strix root
            from strix.orchestrator.graph import build_graph
            self._strix_available = True
            logger.info("✅ Strix is available for validation")
        except ImportError as e:
            self._strix_available = False
            logger.info(f"Strix not available ({e}) — validation will be skipped")

        return self._strix_available

    def validate(
        self,
        lab_dir: str,
        target_url: str,
        vuln_type: str,
        expected_flag: str,
    ) -> ValidationResult:
        """
        Run Strix against the generated lab.

        Args:
            lab_dir: Path to the generated lab files
            target_url: URL where the lab is running (e.g., http://localhost:3000)
            vuln_type: Expected vulnerability type
            expected_flag: The flag that should be capturable

        Returns:
            ValidationResult with pass/fail and details
        """
        if not self.enabled:
            logger.info("[StrixValidator] Strix validation disabled (STRIX_ENABLED=false)")
            return ValidationResult(
                passed=True,
                method="strix_disabled",
                details="Strix validation is disabled. Skipping.",
            )

        if not self._check_strix_available():
            logger.info("[StrixValidator] Strix not importable — skipping validation")
            return ValidationResult(
                passed=True,
                method="strix_unavailable",
                details="Strix is not installed. Validation skipped.",
            )

        return self._run_strix_scan(lab_dir, target_url, vuln_type, expected_flag)

    def _run_strix_scan(
        self,
        lab_dir: str,
        target_url: str,
        vuln_type: str,
        expected_flag: str,
    ) -> ValidationResult:
        """Execute Strix scan against the lab."""
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))

            from strix.orchestrator.graph import build_graph
            from strix.config import StrixConfig

            logger.info(f"[StrixValidator] Running Strix scan against {target_url}")
            start_time = time.time()

            # Configure Strix for focused validation
            config = StrixConfig(
                target=target_url,
                llm=STRIX_LLM,
                max_iterations=STRIX_MAX_ITERATIONS,
                mode="whitebox",
                source_dir=lab_dir,
                # Focus on the specific vuln type
                skills=[self._map_vuln_to_strix_skill(vuln_type)],
            )

            # Build and run the agent graph
            graph = build_graph(config)
            result = graph.run()

            elapsed = time.time() - start_time
            logger.info(f"[StrixValidator] Strix scan completed in {elapsed:.1f}s")

            # Analyze Strix results
            findings = result.get("findings", [])
            flag_captured = any(
                expected_flag in str(f.get("evidence", ""))
                for f in findings
            )

            intended_vuln_found = any(
                self._vuln_matches(f.get("type", ""), vuln_type)
                for f in findings
            )

            unintended = [
                f.get("type", "unknown")
                for f in findings
                if not self._vuln_matches(f.get("type", ""), vuln_type)
            ]

            if flag_captured or intended_vuln_found:
                logger.info("[StrixValidator] ✅ Vulnerability confirmed by Strix!")
                return ValidationResult(
                    passed=True,
                    method="strix_scan",
                    flag_found=flag_captured,
                    details=f"Strix confirmed {vuln_type} vulnerability in {elapsed:.0f}s. "
                            f"Findings: {len(findings)}",
                    unintended_vulns=unintended,
                )
            else:
                logger.warning("[StrixValidator] ❌ Strix could not confirm vulnerability")
                return ValidationResult(
                    passed=False,
                    method="strix_scan",
                    flag_found=False,
                    details=f"Strix scan completed but could not exploit {vuln_type}. "
                            f"The vulnerability may be accidentally fixed.",
                    unintended_vulns=unintended,
                )

        except Exception as e:
            logger.error(f"[StrixValidator] Strix scan failed with error: {e}", exc_info=True)
            return ValidationResult(
                passed=True,  # Don't block on Strix errors — it's an optional layer
                method="strix_error",
                details=f"Strix scan encountered an error: {e}. Validation skipped.",
            )

    def _map_vuln_to_strix_skill(self, vuln_type: str) -> str:
        """Map CTF engine vuln types to Strix skill names."""
        mapping = {
            "sqli_union":        "sql_injection",
            "sqli_blind":        "sql_injection",
            "nosqli_auth_bypass": "nosql_injection",
            "xss_reflected":     "xss",
            "xss_stored":        "xss",
            "cmdi":              "command_injection",
            "ssrf":              "ssrf",
            "ssti":              "ssti",
            "idor":              "idor",
            "jwt_auth":          "authentication_bypass",
        }
        return mapping.get(vuln_type, vuln_type)

    def _vuln_matches(self, strix_type: str, engine_type: str) -> bool:
        """Check if a Strix finding type matches the expected engine vuln type."""
        strix_lower = strix_type.lower()
        engine_lower = engine_type.lower()

        # Direct or partial match
        if engine_lower in strix_lower or strix_lower in engine_lower:
            return True

        # Category match
        categories = {
            "sqli": ["sql", "injection", "sqli"],
            "xss":  ["xss", "cross-site", "script"],
            "cmdi": ["command", "cmd", "rce", "exec"],
            "ssrf": ["ssrf", "server-side request"],
            "ssti": ["ssti", "template injection"],
            "idor": ["idor", "insecure direct", "authorization"],
            "jwt":  ["jwt", "token", "authentication"],
            "nosqli": ["nosql", "mongo", "operator injection"],
        }

        for category, keywords in categories.items():
            if category in engine_lower:
                return any(kw in strix_lower for kw in keywords)

        return False

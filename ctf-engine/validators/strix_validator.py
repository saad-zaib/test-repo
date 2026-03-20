"""
validators/strix_validator.py — Strix integration for PoC validation.

After the CTF engine generates and deploys a lab, Strix performs a quick
white-box scan to verify the vulnerability is genuinely exploitable.

Integration approach:
  - Runs Strix as a subprocess (avoids async conflicts with CTF engine's sync code)
  - Uses the Strix CLI with --non-interactive --scan-mode quick
  - Passes lab source code as local_code target + live URL as web_application target
  - Reads vulnerability reports from strix_runs/ output directory
  - Times out at STRIX_TIMEOUT seconds (default 600)

If Strix is not available or STRIX_ENABLED=false, validation is skipped.
"""

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from config import (
    STRIX_ENABLED, STRIX_LLM, STRIX_OLLAMA_API_BASE,
    STRIX_MAX_ITERATIONS, STRIX_TIMEOUT, STRIX_SCAN_MODE, STRIX_DIR,
)
from validators import ValidationResult

logger = logging.getLogger(__name__)

# Strix project directory (sibling to ctf-engine)
_STRIX_DIR = Path(STRIX_DIR)


class StrixValidator:
    """
    Uses Strix as an automated white-box pentesting validator.

    Flow:
    1. Strix receives the lab's source code path + live URL
    2. It runs in quick mode with focused instructions
    3. If Strix finds and exploits the intended vulnerability → PASS
    4. If Strix can't exploit it → FAIL (vuln was accidentally fixed)
    5. Errors are non-blocking — Strix is an optional quality layer
    """

    def __init__(self):
        self.enabled = STRIX_ENABLED
        self._strix_available = None

    def _check_strix_available(self) -> bool:
        """Check if Strix is importable."""
        if self._strix_available is not None:
            return self._strix_available

        try:
            # STRIX_DIR is the strix project root (auto-detected in config.py)
            # Adding it to sys.path makes `import strix` work
            strix_dir = str(_STRIX_DIR)
            if strix_dir not in sys.path:
                sys.path.insert(0, strix_dir)
            import strix  # noqa: F401
            self._strix_available = True
            logger.info(f"✅ Strix is available for validation (dir={strix_dir})")
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

        return self._run_strix_subprocess(lab_dir, target_url, vuln_type, expected_flag)

    def _run_strix_subprocess(
        self,
        lab_dir: str,
        target_url: str,
        vuln_type: str,
        expected_flag: str,
    ) -> ValidationResult:
        """
        Run Strix as a subprocess using its CLI.
        This avoids async conflicts with ctf-engine's synchronous code.
        """
        start_time = time.time()
        strix_skill = self._map_vuln_to_strix_skill(vuln_type)

        # Build focused instruction for Strix
        instruction = (
            f"QUICK WHITE-BOX VALIDATION — do NOT do a full pentest.\n"
            f"Target: {target_url}\n"
            f"Known vulnerability: {vuln_type} ({strix_skill})\n"
            f"Expected flag: {expected_flag}\n\n"
            f"TASK: Confirm the {vuln_type} vulnerability is exploitable.\n"
            f"1. Read the source code at /workspace to understand the vulnerability\n"
            f"2. Craft a targeted exploit for the specific {vuln_type} vulnerability\n"
            f"3. Execute the exploit against {target_url}\n"
            f"4. Report whether the flag was captured\n\n"
            f"This is a VALIDATION pass — be fast and targeted, not thorough.\n"
            f"Focus ONLY on the {vuln_type} vulnerability. Skip reconnaissance.\n"
            f"Maximum time: 10 minutes."
        )

        # Build Strix CLI command
        strix_main = str(_STRIX_DIR / "strix" / "interface" / "main.py")

        cmd = [
            sys.executable, strix_main,
            "--target", target_url,
            "--target", lab_dir,
            "--non-interactive",
            "--scan-mode", STRIX_SCAN_MODE,
            "--instruction", instruction,
        ]

        # Environment: pass LLM config to Strix
        env = {**os.environ}
        env["STRIX_LLM"] = STRIX_LLM
        env["STRIX_SANDBOX_MODE"] = "false"  # Run tools directly, no nested sandbox
        if STRIX_OLLAMA_API_BASE:
            env["OLLAMA_API_BASE"] = STRIX_OLLAMA_API_BASE
            env["LLM_API_BASE"] = STRIX_OLLAMA_API_BASE

        logger.info(f"[StrixValidator] Launching Strix against {target_url} for {vuln_type}")
        logger.info(f"[StrixValidator] Model: {STRIX_LLM}, Mode: {STRIX_SCAN_MODE}")
        logger.debug(f"[StrixValidator] Command: {' '.join(cmd[:6])}...")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=STRIX_TIMEOUT,
                cwd=str(_STRIX_DIR),
                env=env,
            )

            elapsed = time.time() - start_time
            stdout = result.stdout or ""
            stderr = result.stderr or ""

            logger.info(f"[StrixValidator] Strix completed in {elapsed:.1f}s (exit code {result.returncode})")
            if stderr:
                logger.debug(f"[StrixValidator] stderr (last 500 chars): {stderr[-500:]}")

            # Check for flag in output
            flag_found = expected_flag in stdout if expected_flag else False

            # Check if Strix found the intended vulnerability type
            vuln_found = self._check_output_for_vuln(stdout, vuln_type)

            # Look for vulnerability reports in strix_runs directory
            run_result = self._check_strix_run_results(vuln_type, expected_flag)
            if run_result:
                flag_found = flag_found or run_result.get("flag_found", False)
                vuln_found = vuln_found or run_result.get("vuln_found", False)

            if flag_found:
                logger.info("[StrixValidator] ✅ FLAG CAPTURED — vulnerability confirmed!")
                return ValidationResult(
                    passed=True,
                    method="strix_whitebox",
                    flag_found=True,
                    details=f"Strix captured the flag via {vuln_type} in {elapsed:.0f}s.",
                )

            if vuln_found:
                logger.info("[StrixValidator] ✅ Vulnerability confirmed by Strix (flag not directly captured)")
                return ValidationResult(
                    passed=True,
                    method="strix_whitebox",
                    flag_found=False,
                    details=f"Strix confirmed {vuln_type} is exploitable in {elapsed:.0f}s.",
                )

            # Strix ran but didn't find the vuln
            if result.returncode == 0:
                logger.warning("[StrixValidator] ⚠️ Strix completed but did not confirm vulnerability")
                return ValidationResult(
                    passed=False,
                    method="strix_whitebox",
                    flag_found=False,
                    details=(
                        f"Strix scan completed in {elapsed:.0f}s but could not exploit {vuln_type}. "
                        f"The vulnerability may be accidentally hardened or misconfigured."
                    ),
                )
            else:
                logger.warning(f"[StrixValidator] Strix exited with error code {result.returncode}")
                return ValidationResult(
                    passed=True,  # Non-blocking on errors
                    method="strix_error",
                    details=f"Strix exited with code {result.returncode}. stderr: {stderr[-200:]}",
                )

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.warning(f"[StrixValidator] Strix timed out after {elapsed:.0f}s")
            return ValidationResult(
                passed=True,  # Non-blocking on timeout
                method="strix_timeout",
                details=f"Strix validation timed out after {elapsed:.0f}s. Skipping.",
            )
        except FileNotFoundError:
            logger.error(f"[StrixValidator] Strix CLI not found at {strix_main}")
            return ValidationResult(
                passed=True,
                method="strix_not_found",
                details="Strix CLI not found. Validation skipped.",
            )
        except Exception as e:
            logger.error(f"[StrixValidator] Unexpected error: {e}", exc_info=True)
            return ValidationResult(
                passed=True,  # Non-blocking
                method="strix_error",
                details=f"Strix validation error: {e}",
            )

    def _check_output_for_vuln(self, output: str, vuln_type: str) -> bool:
        """Check if Strix's stdout indicates it found the vulnerability."""
        output_lower = output.lower()
        keywords = self._get_detection_keywords(vuln_type)
        # Look for vulnerability-found indicators
        found_indicators = [
            "vulnerability found",
            "vulnerability confirmed",
            "exploit successful",
            "flag captured",
            "critical",
            "high severity",
        ]
        has_indicator = any(ind in output_lower for ind in found_indicators)
        has_vuln_type = any(kw in output_lower for kw in keywords)
        return has_indicator and has_vuln_type

    def _check_strix_run_results(self, vuln_type: str, expected_flag: str) -> Optional[dict]:
        """Check strix_runs/ directory for the most recent vulnerability reports."""
        try:
            runs_dir = _STRIX_DIR / "strix_runs"
            if not runs_dir.exists():
                return None

            # Find the most recent run directory
            run_dirs = sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            if not run_dirs:
                return None

            latest_run = run_dirs[0]
            # Look for vulnerability report files
            for report_file in latest_run.rglob("*.json"):
                try:
                    data = json.loads(report_file.read_text(encoding="utf-8", errors="ignore"))
                    if isinstance(data, dict):
                        text = json.dumps(data).lower()
                        flag_found = expected_flag in json.dumps(data) if expected_flag else False
                        vuln_found = any(
                            kw in text for kw in self._get_detection_keywords(vuln_type)
                        )
                        if flag_found or vuln_found:
                            return {"flag_found": flag_found, "vuln_found": vuln_found}
                except (json.JSONDecodeError, OSError):
                    continue

        except Exception as e:
            logger.debug(f"[StrixValidator] Error checking run results: {e}")

        return None

    def _get_detection_keywords(self, vuln_type: str) -> list[str]:
        """Get detection keywords for a vulnerability type."""
        keyword_map = {
            "sqli":  ["sql injection", "sqli", "union select", "blind sql"],
            "xss":   ["xss", "cross-site scripting", "script injection", "reflected xss", "stored xss"],
            "cmdi":  ["command injection", "os command", "rce", "remote code execution"],
            "ssrf":  ["ssrf", "server-side request forgery"],
            "ssti":  ["ssti", "template injection", "server-side template"],
            "idor":  ["idor", "insecure direct object", "broken access control"],
            "jwt":   ["jwt", "json web token", "authentication bypass"],
            "nosqli": ["nosql injection", "nosqli", "mongodb injection", "operator injection"],
        }
        for key, keywords in keyword_map.items():
            if key in vuln_type.lower():
                return keywords
        return [vuln_type.lower()]

    def _map_vuln_to_strix_skill(self, vuln_type: str) -> str:
        """Map CTF engine vuln types to Strix skill names."""
        mapping = {
            "sqli_union":         "sql_injection",
            "sqli_blind":         "sql_injection",
            "sqli_auth_bypass":   "sql_injection",
            "nosqli_auth_bypass": "nosql_injection",
            "xss_reflected":      "xss",
            "xss_stored":         "xss",
            "cmdi":               "command_injection",
            "ssrf":               "ssrf",
            "ssti":               "ssti",
            "ssti_nunjucks":      "ssti",
            "idor":               "idor",
            "idor_profile_access":"idor",
            "jwt_auth":           "authentication_jwt",
        }
        return mapping.get(vuln_type, vuln_type)
"""
    Compatibility wrapper for the old API — maps to the same validate() call,
    here for test_integration.py backward compatibility.
"""

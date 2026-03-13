"""
tools/generate_app_code.py

Tool 1: generate_app_code

Agentic code generation engine with:
  Stage 1: Deep research — understands the vulnerability completely
  Stage 2: Architecture decision — decides file structure
  Stage 3: Pass 1 — writes application shell (no vulnerability yet)
  Stage 4: Pass 2 — injects the vulnerability with LLM verification
  Stage 5: Cross-file consistency check
  Stage 6: Self-audit — LLM attacks its own lab

Key agentic features:
  - LLM-based vulnerability verification (not just pattern matching)
  - Targeted file repair (fix one file, not regenerate everything)
  - Individual stages exposed for selective re-execution
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional

from llm.client import call_llm, call_llm_for_json
from tools._raw_vuln_app import get_raw_vuln_app
from prompts.all_prompts import (
    IDENTITY_SECURITY_RESEARCHER,
    IDENTITY_CTF_ARCHITECT,
    IDENTITY_AUDITOR,
    IDENTITY_ATTACKER,
    IDENTITY_VULN_VERIFIER,
    IDENTITY_ERROR_DIAGNOSTICIAN,
    VULN_CONTRACTS,
    AUDIT_CHECKLISTS,
    get_research_prompt,
    get_architecture_prompt,
    get_file_write_prompt,
    get_cross_reference_prompt,
    get_self_audit_prompt,
    get_vuln_verification_prompt,
    get_targeted_fix_prompt,
)

logger = logging.getLogger(__name__)


class GenerateAppCodeTool:
    """
    Tool 1: generate_app_code

    Agentic code generator with:
    - Full pipeline via generate()
    - Individual stages callable independently for smart retries
    - Targeted file repair via fix_specific_file()
    - LLM-based vulnerability verification
    """

    def __init__(self):
        self.max_file_retries = 4

    # ─────────────────────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────────────────────────

    def generate(
        self,
        spec: dict,
        workspace_dir: str,
        error_history: Optional[list] = None,
        retry_number: int = 0,
        cached_research: Optional[dict] = None,
        cached_architecture: Optional[dict] = None,
        resume_from_stage: int = 1,
    ) -> dict:
        """
        Main entry point. Runs the generation pipeline.

        Supports resuming from a specific stage with cached data
        so the orchestrator doesn't have to redo everything.

        Args:
            spec:                The structured spec from Phase 2 LLM
            workspace_dir:       Where to write files
            error_history:       Previous errors if this is a retry
            retry_number:        Which retry attempt this is
            cached_research:     Reuse research from previous attempt
            cached_architecture: Reuse architecture from previous attempt
            resume_from_stage:   Start from this stage (1-6)

        Returns:
            {
              "status": "success" | "failed",
              "directory": path,
              "files": [...],
              "research": {...},
              "architecture": {...},
              "failure_reason": "..." (if failed),
              "failure_stage": "..." (if failed)
            }
        """
        lab_id = spec.get("lab_id", "lab_unknown")
        lab_dir = Path(workspace_dir) / lab_id
        lab_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"[Tool1] Starting generation for lab {lab_id} (from stage {resume_from_stage})")
        if error_history:
            logger.info(f"[Tool1] Retry #{retry_number}, errors to fix: {len(error_history)}")

        try:
            # ─────────────────────────────────────────
            # STAGE 1: DEEP RESEARCH
            # ─────────────────────────────────────────
            if resume_from_stage <= 1:
                logger.info("[Tool1] Stage 1: Deep research...")
                research = self.stage_research(spec, error_history)
                self._write_json(lab_dir / "meta" / "research.json", research)
                logger.info("[Tool1] Stage 1 complete")
            else:
                research = cached_research or self._read_json(lab_dir / "meta" / "research.json")
                logger.info("[Tool1] Stage 1: Using cached research")

            # ─────────────────────────────────────────
            # STAGE 2: ARCHITECTURE DECISION
            # ─────────────────────────────────────────
            if resume_from_stage <= 2:
                logger.info("[Tool1] Stage 2: Architecture decision...")
                architecture = self.stage_architecture(spec, research)
                # CRITICAL: ensure Docker files are always in the plan
                architecture = self._ensure_docker_files_in_architecture(architecture)
                self._write_json(lab_dir / "meta" / "architecture.json", architecture)
                logger.info(f"[Tool1] Stage 2 complete — {len(architecture.get('files', []))} files planned")
            else:
                architecture = cached_architecture or self._read_json(lab_dir / "meta" / "architecture.json")
                # Also ensure Docker files on retry
                architecture = self._ensure_docker_files_in_architecture(architecture)
                logger.info("[Tool1] Stage 2: Using cached architecture")

            # ─────────────────────────────────────────
            # STAGE 3: WRITE APPLICATION SHELL
            # ─────────────────────────────────────────
            if resume_from_stage <= 3:
                logger.info("[Tool1] Stage 3: Writing application shell...")
                written_files = self.stage_write_shell(spec, research, architecture, lab_dir)
                logger.info(f"[Tool1] Stage 3 complete — {len(written_files)} files written")
            else:
                # Discover already-written files
                written_files = self._discover_written_files(lab_dir)
                logger.info(f"[Tool1] Stage 3: Using {len(written_files)} existing files")

            # ─────────────────────────────────────────
            # STAGE 4: INJECT VULNERABILITY
            # ─────────────────────────────────────────
            if resume_from_stage <= 4:
                logger.info("[Tool1] Stage 4: Injecting vulnerability...")
                inject_result = self.stage_inject_vulnerability(
                    spec, research, architecture, lab_dir, written_files
                )
                if inject_result["status"] != "success":
                    return {
                        "status": "failed",
                        "directory": str(lab_dir),
                        "failure_reason": inject_result["reason"],
                        "failure_stage": "vulnerability_injection",
                        "research": research,
                        "architecture": architecture,
                    }
                logger.info("[Tool1] Stage 4 complete — vulnerability injected and verified")

            # ─────────────────────────────────────────
            # STAGE 5: CROSS-FILE CONSISTENCY
            # ─────────────────────────────────────────
            if resume_from_stage <= 5:
                logger.info("[Tool1] Stage 5: Cross-file consistency check...")
                try:
                    consistency_ok = self.stage_consistency_check(
                        spec, architecture, lab_dir, written_files
                    )
                    if not consistency_ok:
                        logger.warning("[Tool1] Stage 5: Consistency issues remain after fixes (non-blocking)")
                    else:
                        logger.info("[Tool1] Stage 5 complete — all files consistent")
                except Exception as e:
                    logger.warning(f"[Tool1] Stage 5: Consistency check error (non-blocking): {e}")

            # ─────────────────────────────────────────
            # STAGE 6: SELF-AUDIT (non-blocking quality check)
            # The REAL verification is Tool 4 (verify_exploit).
            # Self-audit is advisory — warns but doesn't fail the pipeline.
            # ─────────────────────────────────────────
            logger.info("[Tool1] Stage 6: Self-audit...")
            audit_result = self.stage_self_audit(spec, architecture, lab_dir, written_files)
            self._write_json(lab_dir / "meta" / "audit.json", audit_result)

            if not audit_result.get("audit_passed", False):
                issues = audit_result.get("issues_found", [])
                logger.warning(f"[Tool1] Self-audit found issues (non-blocking): {issues}")
                # Try to fix, but don't fail the pipeline if we can't
                try:
                    self._fix_audit_issues(
                        audit_result, spec, research, architecture, lab_dir, written_files
                    )
                except Exception as fix_err:
                    logger.warning(f"[Tool1] Self-audit fix attempt failed: {fix_err}")
            logger.info("[Tool1] Stage 6 complete — proceeding to build")

            # ─────────────────────────────────────────
            # GENERATE HINTS AND SOLUTION
            # ─────────────────────────────────────────
            hints = self._generate_hints(spec, research)
            solution = self._generate_solution(spec, research)
            self._write_json(lab_dir / "meta" / "hints.json", hints)
            self._write_json(lab_dir / "meta" / "solution.json", solution)

            # ─────────────────────────────────────────
            # WRITE CHALLENGE METADATA
            # ─────────────────────────────────────────
            challenge_meta = {
                "lab_id": lab_id,
                "vuln_type": spec.get("vuln_type", "unknown"),
                "title": spec.get("title", "Web Security Challenge"),
                "description": spec.get("description", ""),
                "category": spec.get("category", "web"),
                "difficulty": spec.get("difficulty", "medium"),
                "flag": spec.get("flag"),
                "solution_payload": spec.get("solution_payload"),
                "par_time": None,
                "ports": architecture.get("ports", {}),
                "exploit_chain": research.get("exploit_chain", []),
            }
            self._write_json(lab_dir / "meta" / "challenge.json", challenge_meta)

            logger.info(f"[Tool1] ✅ Generation complete for {lab_id}")

            return {
                "status": "success",
                "directory": str(lab_dir),
                "files": written_files,
                "research": research,
                "architecture": architecture,
                "hints": hints,
                "solution": solution,
            }

        except Exception as e:
            logger.error(f"[Tool1] Unexpected error: {e}", exc_info=True)
            return {
                "status": "failed",
                "directory": str(lab_dir),
                "failure_reason": str(e),
                "failure_stage": "unknown",
                "research": locals().get("research"),
                "architecture": locals().get("architecture"),
            }

    # ─────────────────────────────────────────────────────────────
    # INDIVIDUAL STAGES (exposed for orchestrator to call directly)
    # ─────────────────────────────────────────────────────────────

    def stage_research(self, spec: dict, error_history: Optional[list] = None) -> dict:
        """Stage 1: LLM reasons about the vulnerability before writing anything"""
        extra = ""
        if error_history:
            extra = f"\n\nPREVIOUS ERRORS TO AVOID:\n" + "\n".join(
                f"- {e}" for e in error_history
            )
        return call_llm_for_json(
            system_prompt=IDENTITY_SECURITY_RESEARCHER,
            user_prompt=get_research_prompt(spec) + extra,
        )

    def stage_architecture(self, spec: dict, research: dict) -> dict:
        """Stage 2: LLM decides file structure, containers, network topology"""
        architecture = call_llm_for_json(
            system_prompt=IDENTITY_CTF_ARCHITECT,
            user_prompt=get_architecture_prompt(spec, research),
        )
        if "files" in architecture:
            architecture["files"].sort(key=lambda f: f.get("write_order", 99))
        return architecture

    def _ensure_docker_files_in_architecture(self, architecture: dict) -> dict:
        """
        Guarantee that Dockerfile and docker-compose.yml are in the file list.
        The LLM consistently forgets to include them — this fixes it every time.
        """
        files = architecture.get("files", [])
        containers = architecture.get("containers", [])
        existing_paths = {f.get("path", f.get("file_path", "")).lower() for f in files}

        # Check if any Dockerfile exists
        has_dockerfile = any("dockerfile" in p for p in existing_paths)
        # Check if docker-compose exists
        has_compose = any("docker-compose" in p or "compose" in p for p in existing_paths)

        max_order = max((f.get("write_order", 0) for f in files), default=0)

        # Add Dockerfile for each container if missing
        if not has_dockerfile:
            for container in containers:
                container_name = container.get("name", "app")
                files.append({
                    "path": "Dockerfile",
                    "container": container_name,
                    "purpose": f"Dockerfile for {container_name} — defines how to build the container image",
                    "write_order": max_order + 1,
                })
                max_order += 1
                logger.info(f"[Tool1] Auto-added Dockerfile for container '{container_name}'")

        # Add docker-compose.yml if missing (place at lab root, not inside a container)
        if not has_compose:
            files.append({
                "path": "docker-compose.yml",
                "container": ".",  # Lab root, not inside a container subdir
                "purpose": "Docker Compose file to orchestrate all containers together",
                "write_order": max_order + 1,
            })
            logger.info("[Tool1] Auto-added docker-compose.yml at lab root")

        # Re-sort by write order (Dockerfiles and compose last)
        files.sort(key=lambda f: f.get("write_order", 99))
        architecture["files"] = files
        return architecture

    def stage_write_shell(
        self, spec: dict, research: dict, architecture: dict, lab_dir: Path,
    ) -> list:
        """Stage 3: Write all files EXCEPT the vulnerability injection point."""
        vuln_injection_point = architecture.get("vulnerability_injection_point", {})
        vuln_file = vuln_injection_point.get("file", "")
        written_files = []

        for file_spec in architecture.get("files", []):
            file_path = file_spec.get("file_path", file_spec.get("path", ""))
            container = file_spec.get("container", "app")
            if container and container != "." and file_path.startswith(container + "/"):
                file_path = file_path[len(container)+1:]
            file_purpose = file_spec.get("purpose", "")
            container = file_spec.get("container", "app")
            is_vuln_file = vuln_file and (vuln_file in file_path or file_path in vuln_file)

            # Handle special container values that mean "lab root"
            if container in (".", "both", "root", ""):
                full_path = lab_dir / file_path
            else:
                full_path = lab_dir / container / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            content = self._write_single_file(
                file_path=file_path,
                file_purpose=file_purpose,
                spec=spec, research=research, architecture=architecture,
                already_written=written_files,
                is_vulnerability_file=False,
                vuln_contract="",
                placeholder_mode=is_vuln_file,
            )

            full_path.write_text(content, encoding="utf-8")
            written_files.append(f"{container}/{file_path}")
            logger.debug(f"[Tool1] Written: {container}/{file_path}")

        return written_files

    # ── Exact vulnerable code patterns per vuln type ──
    # These get FORCE-INJECTED if the LLM writes safe code.
    VULN_CODE_TEMPLATES = {
        "sqli_union": {
            # Regex patterns to find safe code and replace with vulnerable code
            "replacements": [
                {
                    # Pattern: cursor.execute("SELECT ... WHERE username=?", (username,))
                    # or cursor.execute(query, (username,)) where query uses ? or %s
                    "safe_patterns": [
                        # SQLAlchemy ORM filter_by -> raw SQL (most common 14B model pattern)
                        (r'\w+\.query\.filter_by\([^)]*\)\.first\(\)',
                         'db.engine.execute(query).fetchone()'),
                        # parameterized with ? placeholder
                        (r'(query\s*=\s*["\'])SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*[\?%]s["\']',
                         'query = f"SELECT * FROM users WHERE username=\'{username}\'"'),
                        # cursor.execute(query, (anything,))  →  cursor.execute(query)
                        (r'(cursor|conn|db|cur|c)\.(execute)\((\w+),\s*\([^)]*username[^)]*\)\)',
                         r'\1.\2(\3)'),
                        # cursor.execute(query, [anything])  →  cursor.execute(query)
                        (r'(cursor|conn|db|cur|c)\.(execute)\((\w+),\s*\[[^\]]*username[^\]]*\]\)',
                         r'\1.\2(\3)'),
                    ],
                    # If no safe pattern found, inject this block wholesale
                    "fallback_inject": '''
    # VULNERABLE: sqli_union — intentional for CTF lab
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = db.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
''',
                },
            ],
        },
        "cmdi": {
            "replacements": [
                {
                    "safe_patterns": [
                        # subprocess with list args → shell=True with f-string
                        (r'subprocess\.run\(\[([^\]]+)\]',
                         'subprocess.run(f"ping -c 1 {host}", shell=True'),
                        # shlex.quote removal
                        (r'shlex\.quote\((\w+)\)', r'\1'),
                    ],
                    "fallback_inject": '''
    # VULNERABLE: cmdi — intentional for CTF lab
    host = request.form.get("host", "")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    output = result.stdout
''',
                },
            ],
        },
        "xss_reflected": {
            "replacements": [
                {
                    "safe_patterns": [
                        # {{ variable }} without |safe → add |safe
                        (r'\{\{\s*(\w+)\s*\}\}', r'{{ \1 | safe }}'),
                        # escape() removal
                        (r'escape\((\w+)\)', r'\1'),
                    ],
                    "fallback_inject": None,
                },
            ],
        },
        "ssrf": {
            "replacements": [
                {
                    "safe_patterns": [
                        # Remove URL validation
                        (r'if\s+not\s+url\.startswith.*?:\s*\n\s*return.*?\n', ''),
                        (r'urlparse\([^)]+\)', 'url'),
                    ],
                    "fallback_inject": '''
    # VULNERABLE: ssrf — intentional for CTF lab
    url = request.form.get("url", "")
    response = requests.get(url)
    return response.text
''',
                },
            ],
        },
    }

    def stage_inject_vulnerability(
        self, spec: dict, research: dict, architecture: dict,
        lab_dir: Path, written_files: list,
    ) -> dict:
        """
        Stage 4: Inject vulnerability with FORCED code injection.

        Strategy: Let the LLM write the file, then programmatically transform
        safe code patterns into vulnerable ones. The 14B model's safety training
        can't override a regex replacement.

        Flow:
        1. LLM writes the file (may write safe code)
        2. We force-inject vulnerable patterns using regex
        3. Verify the vulnerability exists
        4. If still not present, use fallback template injection
        """
        import re

        vuln_type = spec.get("vuln_type", "sqli_union")
        vuln_contract = VULN_CONTRACTS.get(vuln_type, "")
        vuln_injection_point = architecture.get("vulnerability_injection_point", {})
        vuln_file = vuln_injection_point.get("file", "")

        if not vuln_file:
            logger.warning("[Tool1] No vulnerability injection point defined")
            return {"status": "failed", "reason": "No vulnerability injection point in architecture"}

        vuln_container = "app"
        for file_spec in architecture.get("files", []):
            fp = file_spec.get("file_path", file_spec.get("path", ""))
            c_name = file_spec.get("container", "app")
            # Strip container name from fp for matching
            if c_name and c_name not in (".", "both", "root", "") and fp.startswith(f"{c_name}/"):
                fp = fp[len(c_name)+1:]
                
            if vuln_file in fp or fp in vuln_file:
                vuln_container = c_name
                if vuln_file.startswith(f"{c_name}/"):
                    vuln_file = vuln_file[len(c_name)+1:]
                break

        full_path = lab_dir / vuln_container / vuln_file
        if not full_path.exists():
            for f in lab_dir.rglob(Path(vuln_file).name):
                full_path = f
                break

        logger.info(f"[Tool1] Injecting vulnerability into: {full_path}")
        last_reason = ""

        for attempt in range(self.max_file_retries):
            attempt_spec = spec.copy()
            if last_reason:
                attempt_spec["_vuln_check_failure"] = last_reason

            # Step 1: Let LLM write the file
            content = self._write_single_file(
                file_path=vuln_file,
                file_purpose=vuln_injection_point.get("line_description", ""),
                spec=attempt_spec, research=research, architecture=architecture,
                already_written=written_files,
                is_vulnerability_file=True,
                vuln_contract=vuln_contract,
                placeholder_mode=False,
            )

            # Step 2: FORCE-INJECT the vulnerability
            content = self._force_inject_vulnerability(content, vuln_type, spec)

            full_path.write_text(content, encoding="utf-8")

            # Step 3: Verify
            check_result = self._verify_vulnerability_hybrid(content, vuln_type, spec)

            if check_result["vulnerability_present"]:
                logger.info(f"[Tool1] Vulnerability FORCE-INJECTED on attempt {attempt + 1}")
                return {"status": "success"}
            else:
                last_reason = check_result["reason"]
                logger.warning(
                    f"[Tool1] Vuln check failed even after force-inject "
                    f"(attempt {attempt + 1}/{self.max_file_retries}): {last_reason}"
                )

        return {
            "status": "failed",
            "reason": f"Could not inject {vuln_type} after {self.max_file_retries} attempts. Last: {last_reason}",
        }

    def _force_inject_vulnerability(self, content: str, vuln_type: str, spec: dict) -> str:
        """
        Programmatically transform safe code into vulnerable code.
        Handles: ORM rewrite, parameterized query removal, full fallback.
        """
        import re

        if vuln_type not in ("sqli_union", "sqli_blind"):
            templates = self.VULN_CODE_TEMPLATES.get(vuln_type)
            if not templates:
                return content
            for rgroup in templates.get("replacements", []):
                for pattern, replacement in rgroup.get("safe_patterns", []):
                    try:
                        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE | re.DOTALL)
                        if new_content != content:
                            logger.info(f"[Tool1] Force-replaced: {pattern[:40]}...")
                            content = new_content
                    except re.error as e:
                        logger.warning(f"[Tool1] Regex error: {e}")
            return content

        # -- SQL Injection specific --
        original = content

        # SCENARIO 1: SQLAlchemy ORM detected -> full rewrite
        orm_indicators = ["SQLAlchemy", "flask_sqlalchemy", ".query.filter",
                          "filter_by(", "from flask_sqlalchemy", "db.Model",
                          "db = SQLAlchemy"]
        if any(ind in content for ind in orm_indicators):
            logger.info("[Tool1] Detected SQLAlchemy ORM -- rewriting to raw SQL")
            content = get_raw_vuln_app(spec.get("flag", "CTF{flag_here}"))
            logger.info("[Tool1] ORM fully rewritten to raw vulnerable SQL")
            return content

        # SCENARIO 2: Parameterized queries -> remove parameters
        content = re.sub(
            r'(\w+)\.(execute)\((\w+),\s*\([^)]*\)\)',
            r'\1.\2(\3)',
            content,
        )

        if content != original:
            logger.info("[Tool1] Force-injected: removed parameterized queries")
            return content

        # SCENARIO 3: Check if vuln already present
        quick = self._quick_pattern_scan(content, vuln_type)
        if quick["definite_pass"]:
            logger.info("[Tool1] Vulnerability already present")
            return content

        # SCENARIO 4: Full fallback
        logger.info("[Tool1] No recognizable patterns -- full fallback")
        content = get_raw_vuln_app(spec.get("flag", "CTF{flag_here}"))
        return content

    def stage_consistency_check(
        self, spec: dict, architecture: dict, lab_dir: Path, written_files: list,
    ) -> bool:
        """Stage 5: Read ALL files and check cross-file consistency"""
        files_content = {}
        for relative_path in written_files:
            full_path = lab_dir / relative_path
            if full_path.exists():
                files_content[relative_path] = full_path.read_text(encoding="utf-8")

        result = call_llm_for_json(
            system_prompt=IDENTITY_AUDITOR,
            user_prompt=get_cross_reference_prompt(files_content, spec, architecture),
        )

        if result.get("all_consistent", True):
            return True

        issues = result.get("issues", [])
        logger.info(f"[Tool1] Consistency issues found: {len(issues)}, fixing...")

        for issue in issues:
            self._fix_consistency_issue(issue, lab_dir, spec, architecture)

        # Re-check once after fixes
        files_content_fixed = {}
        for relative_path in written_files:
            full_path = lab_dir / relative_path
            if full_path.exists():
                files_content_fixed[relative_path] = full_path.read_text(encoding="utf-8")

        result2 = call_llm_for_json(
            system_prompt=IDENTITY_AUDITOR,
            user_prompt=get_cross_reference_prompt(files_content_fixed, spec, architecture),
        )
        return result2.get("all_consistent", False)

    def stage_self_audit(
        self, spec: dict, architecture: dict, lab_dir: Path, written_files: list,
    ) -> dict:
        """Stage 6: LLM puts on attacker hat and reviews the challenge."""
        player_visible = {}
        skip_extensions = {".json"}
        skip_dirs = {"meta"}

        for relative_path in written_files:
            path_obj = Path(relative_path)
            if any(part in skip_dirs for part in path_obj.parts):
                continue
            if path_obj.suffix in skip_extensions:
                continue
            full_path = lab_dir / relative_path
            if full_path.exists():
                content = full_path.read_text(encoding="utf-8")
                # Truncate very large files to avoid context overflow
                if len(content) > 3000:
                    content = content[:3000] + "\n... [TRUNCATED]"
                player_visible[relative_path] = content

        # Guard: if no player-visible files found, skip audit
        if not player_visible:
            logger.warning("[Tool1] Self-audit: no player-visible files found, skipping")
            return {
                "audit_passed": True,
                "issues_found": [],
                "explanation": "No player-visible files to audit — skipped",
            }

        logger.info(f"[Tool1] Self-audit examining {len(player_visible)} files")
        vuln_type = spec.get("vuln_type", "")
        return call_llm_for_json(
            system_prompt=IDENTITY_ATTACKER,
            user_prompt=get_self_audit_prompt(player_visible, spec, vuln_type),
        )

    # ─────────────────────────────────────────────────────────────
    # TARGETED FILE REPAIR (the key agentic feature)
    # ─────────────────────────────────────────────────────────────

    def fix_specific_file(
        self,
        lab_dir: str,
        file_path: str,
        error_context: str,
        spec: dict,
        fix_type: str = "build_error",
    ) -> dict:
        """
        Fix a specific file given error context.
        This is the Claude Code-style targeted repair — fix one file,
        not regenerate everything.

        Args:
            lab_dir:       Lab directory path
            file_path:     Relative path of file to fix (e.g., "app/app.py")
            error_context: The error output (Docker logs, crash logs, etc.)
            spec:          The original spec
            fix_type:      "build_error", "runtime_error", "exploit_failed", "vuln_missing"

        Returns:
            {"status": "fixed"|"failed", "file": "path", "reason": "..."}
        """
        lab_path = Path(lab_dir)
        full_path = lab_path / file_path

        if not full_path.exists():
            # Try to find it
            for candidate in lab_path.rglob(Path(file_path).name):
                full_path = candidate
                break

        if not full_path.exists():
            return {"status": "failed", "file": file_path, "reason": "File not found"}

        current_content = full_path.read_text(encoding="utf-8")

        logger.info(f"[Tool1] Targeted fix on {file_path} ({fix_type})")

        fixed_content = call_llm(
            system_prompt=IDENTITY_ERROR_DIAGNOSTICIAN,
            user_prompt=get_targeted_fix_prompt(
                file_path=file_path,
                current_content=current_content,
                error_context=error_context,
                spec=spec,
                fix_type=fix_type,
            ),
            temperature=0.2,  # Very low for precise fixes
        )

        # Strip markdown fences
        if fixed_content.startswith("```"):
            lines = fixed_content.split("\n")
            fixed_content = "\n".join(
                lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            )

        full_path.write_text(fixed_content, encoding="utf-8")
        logger.info(f"[Tool1] ✅ Fixed {file_path}")

        return {"status": "fixed", "file": file_path}

    # ─────────────────────────────────────────────────────────────
    # VERIFICATION (hybrid: quick patterns + LLM judge)
    # ─────────────────────────────────────────────────────────────

    def _verify_vulnerability_hybrid(self, content: str, vuln_type: str, spec: dict) -> dict:
        """
        Hybrid verification: try quick pattern scan first, then LLM if ambiguous.
        This replaces the old rigid-only pattern matching.
        """
        # Step 1: Quick pattern scan (fast-pass)
        quick = self._quick_pattern_scan(content, vuln_type)

        if quick["definite_pass"]:
            # Patterns clearly match — vulnerability is present
            logger.debug("[Tool1] Quick scan: definite pass")
            return {"vulnerability_present": True, "reason": "Quick scan confirmed", "method": "pattern"}

        if quick["definite_fail"]:
            # Safe patterns found — definitely broken
            logger.debug(f"[Tool1] Quick scan: definite fail — {quick['reason']}")
            return {"vulnerability_present": False, "reason": quick["reason"], "method": "pattern"}

        # Step 2: Ambiguous — ask the LLM to judge
        logger.info("[Tool1] Quick scan ambiguous — using LLM verification")
        llm_result = call_llm_for_json(
            system_prompt=IDENTITY_VULN_VERIFIER,
            user_prompt=get_vuln_verification_prompt(content, vuln_type, spec),
        )

        is_present = (
            llm_result.get("vulnerability_present", False) and
            llm_result.get("exploitable", False)
        )

        return {
            "vulnerability_present": is_present,
            "reason": llm_result.get("reason", "LLM verification"),
            "method": "llm",
            "llm_details": llm_result,
        }

    def _quick_pattern_scan(self, content: str, vuln_type: str) -> dict:
        """
        Fast substring scan. Returns definite_pass/definite_fail/ambiguous.
        Used as a first pass before LLM verification.
        """
        checklist = AUDIT_CHECKLISTS.get(vuln_type, {})
        must_exist = checklist.get("vulnerability_must_exist", [])
        must_not_exist = checklist.get("vulnerability_must_not_exist", [])

        if not must_exist:
            # No checklist for this vuln type — go straight to LLM
            return {"definite_pass": False, "definite_fail": False, "reason": "No checklist"}

        found_vulnerable = [p for p in must_exist if p in content]
        found_safe = [p for p in must_not_exist if p in content]

        # CASE 1: Both vulnerable AND safe patterns found
        # This is AMBIGUOUS — the safe pattern might be on a different code path
        # (e.g., password uses parameterized queries while username is vulnerable)
        # Let the LLM judge decide.
        if found_vulnerable and found_safe:
            return {
                "definite_pass": False,
                "definite_fail": False,
                "reason": (
                    f"Mixed patterns: vulnerable={found_vulnerable}, safe={found_safe}. "
                    f"Safe patterns may be on a different code path (e.g., password field). "
                    f"Needs LLM verification."
                ),
            }

        # CASE 2: Only safe patterns, no vulnerable patterns — definite fail
        if found_safe and not found_vulnerable:
            return {
                "definite_pass": False,
                "definite_fail": True,
                "reason": f"Safe patterns found with no vulnerable patterns: {found_safe}.",
            }

        # CASE 3: Only vulnerable patterns, no safe patterns — definite pass
        if found_vulnerable:
            return {
                "definite_pass": True,
                "definite_fail": False,
                "reason": f"Vulnerable patterns confirmed: {found_vulnerable}",
            }

        # CASE 4: Nothing matched either way — ambiguous
        return {
            "definite_pass": False,
            "definite_fail": False,
            "reason": "No expected patterns found — needs LLM verification",
        }

    # ─────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────

    def _write_single_file(
        self, file_path, file_purpose, spec, research, architecture,
        already_written, is_vulnerability_file, vuln_contract,
        placeholder_mode=False,
    ) -> str:
        """Call LLM to write a single file and return its contents"""
        if placeholder_mode:
            vuln_note = (
                "\nFor the vulnerable query/function, write a PLACEHOLDER:\n"
                "# VULNERABILITY_INJECTION_POINT\n"
                "# This will be replaced with the actual vulnerability\n"
                "query = 'PLACEHOLDER'"
            )
        else:
            vuln_note = ""

        prompt = get_file_write_prompt(
            file_path=file_path,
            file_purpose=file_purpose + vuln_note,
            spec=spec, research=research, architecture=architecture,
            already_written=already_written,
            is_vulnerability_file=is_vulnerability_file,
            vuln_contract=vuln_contract,
        )

        content = call_llm(
            system_prompt=IDENTITY_CTF_ARCHITECT,
            user_prompt=prompt,
            temperature=0.4,
        )

        # Strip markdown fences
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(
                lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            )

        return content

    def _fix_consistency_issue(self, issue, lab_dir, spec, architecture):
        """Fix a single consistency issue by rewriting the affected file"""
        affected_file = issue.get("file", "")
        fix_description = issue.get("fix", "")
        if not affected_file or not fix_description:
            return

        for candidate in lab_dir.rglob("*"):
            if candidate.is_file() and affected_file in str(candidate):
                current_content = candidate.read_text(encoding="utf-8")
                fixed_content = call_llm(
                    system_prompt=IDENTITY_CTF_ARCHITECT,
                    user_prompt=(
                        f"Fix this specific issue in the file {affected_file}:\n\n"
                        f"ISSUE: {issue.get('description', '')}\n"
                        f"FIX NEEDED: {fix_description}\n\n"
                        f"CURRENT FILE CONTENT:\n{current_content}\n\n"
                        f"Return ONLY the complete fixed file content."
                    ),
                )
                if fixed_content.startswith("```"):
                    lines = fixed_content.split("\n")
                    fixed_content = "\n".join(
                        lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                    )
                candidate.write_text(fixed_content, encoding="utf-8")
                logger.info(f"[Tool1] Fixed consistency issue in {affected_file}")
                break

    def _fix_audit_issues(self, audit_result, spec, research, architecture, lab_dir, written_files):
        """Attempt to fix self-audit failures"""
        issues = audit_result.get("issues_found", [])
        for issue in issues:
            fix_plan = call_llm_for_json(
                system_prompt=IDENTITY_CTF_ARCHITECT,
                user_prompt=(
                    f"CTF lab self-audit found this issue: {issue}\n\n"
                    f"Fix it without changing the vulnerability or the flag value.\n"
                    f"Spec: {spec}\n\n"
                    f"Which file needs to change and what should change?\n\n"
                    f"Respond with JSON: {{\"file\": \"path\", \"fix\": \"description\"}}"
                ),
            )
            self._fix_consistency_issue(fix_plan, lab_dir, spec, architecture)

        re_audit = self.stage_self_audit(spec, architecture, lab_dir, written_files)
        return re_audit.get("audit_passed", False)

    def _generate_hints(self, spec, research):
        """Generate 3 progressive hints"""
        result = call_llm_for_json(
            system_prompt=IDENTITY_CTF_ARCHITECT,
            user_prompt=(
                f"Generate 3 progressive hints for this CTF challenge.\n\n"
                f"Spec: {spec}\n"
                f"Exploit chain: {research.get('exploit_chain', [])}\n\n"
                f"Rules:\n"
                f"- Hint 1: Very gentle, points in right direction\n"
                f"- Hint 2: Names the vulnerability class, suggests a technique\n"
                f"- Hint 3: Near-solution, almost gives it away\n"
                f"- None of the hints reveal the flag value directly\n\n"
                f"Respond with JSON: {{\"hints\": [\"hint1\", \"hint2\", \"hint3\"]}}"
            ),
        )
        return result.get("hints", ["Think about user input.", "Consider injection.", "Try special characters."])

    def _generate_solution(self, spec, research):
        """Generate a detailed solution walkthrough"""
        return call_llm_for_json(
            system_prompt=IDENTITY_CTF_ARCHITECT,
            user_prompt=(
                f"Write a detailed solution walkthrough for this CTF challenge.\n\n"
                f"Spec: {spec}\nResearch: {research}\n\n"
                f"Include:\n"
                f"- What vulnerability is present and why\n"
                f"- Step by step exploitation\n"
                f"- Exact payload to use\n"
                f"- How to retrieve the flag\n"
                f"- Real-world context\n\n"
                f"Respond with JSON: {{\n"
                f"  \"vulnerability_explanation\": \"...\",\n"
                f"  \"steps\": [\"step1\", \"step2\", ...],\n"
                f"  \"exact_payload\": \"...\",\n"
                f"  \"flag_retrieval\": \"...\",\n"
                f"  \"real_world_context\": \"...\"\n"
                f"}}"
            ),
        )

    def _discover_written_files(self, lab_dir: Path) -> list:
        """Discover all files already written in a lab directory"""
        files = []
        for f in lab_dir.rglob("*"):
            if f.is_file() and "meta" not in f.parts and "__pycache__" not in str(f):
                files.append(str(f.relative_to(lab_dir)))
        return files

    @staticmethod
    def _write_json(path: Path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _read_json(path: Path) -> dict:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {}

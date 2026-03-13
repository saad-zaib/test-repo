"""
tools/build_docker.py

Tool 2: build_docker_image

Takes the directory produced by Tool 1 and builds Docker images.
Returns detailed error information so the orchestrator can send
specific fixes back to Tool 1.
"""

import subprocess
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class BuildDockerTool:

    def build(self, lab_dir: str) -> dict:
        """
        Build Docker images for the lab.

        Returns detailed result dict so orchestrator knows
        exactly what failed and what to tell Tool 1 to fix.
        """
        lab_path = Path(lab_dir).resolve()  # Always use absolute paths

        # Search for docker-compose.yml — check root first, then subdirectories
        compose_file = lab_path / "docker-compose.yml"
        if not compose_file.exists():
            compose_file = lab_path / "docker-compose.yaml"
        if not compose_file.exists():
            # Search subdirectories (LLM often puts it in "both/" or container dir)
            for candidate in lab_path.rglob("docker-compose.yml"):
                compose_file = candidate
                break
        if not compose_file.exists():
            for candidate in lab_path.rglob("docker-compose.yaml"):
                compose_file = candidate
                break

        if not compose_file.exists():
            return {
                "status": "failed",
                "failure_stage": "preflight",
                "error": "No docker-compose.yml found in lab directory or subdirectories",
                "fixable_by_llm": True,
                "fix_instruction": "Generate a docker-compose.yml file. Place it in the lab root directory.",
                "lab_dir": lab_dir,
            }

        # If compose file is in a subdirectory, move it to lab root for Docker context
        if compose_file.parent != lab_path:
            import shutil
            dest = lab_path / compose_file.name
            shutil.copy2(str(compose_file), str(dest))
            logger.info(f"[Tool2] Moved {compose_file} to {dest}")
            compose_file = dest

        logger.info(f"[Tool2] Building Docker images in {lab_dir}...")
        start_time = time.time()

        # Run docker compose build
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file.name), "build", "--no-cache"],
            capture_output=True,
            text=True,
            cwd=str(lab_path),
            timeout=300,  # 5 minute build timeout
        )

        build_time = time.time() - start_time

        if result.returncode == 0:
            logger.info(f"[Tool2] ✅ Build successful in {build_time:.1f}s")
            return {
                "status": "built",
                "build_time_seconds": round(build_time, 1),
                "lab_dir": lab_dir,
                "compose_file": str(compose_file),
                "stdout": result.stdout[-2000:],  # Last 2000 chars
            }

        # Build failed — parse the error for specific diagnosis
        error_output = result.stderr + result.stdout
        diagnosis = self._diagnose_build_error(error_output)

        logger.error(f"[Tool2] ❌ Build failed: {diagnosis['error_type']}")
        logger.error(f"[Tool2] Error output: {error_output[-500:]}")

        return {
            "status": "failed",
            "failure_stage": "docker_build",
            "error_type": diagnosis["error_type"],
            "error": diagnosis["error_summary"],
            "full_error": error_output[-3000:],
            "fixable_by_llm": diagnosis["fixable_by_llm"],
            "fix_instruction": diagnosis["fix_instruction"],
            "lab_dir": lab_dir,
        }

    def _diagnose_build_error(self, error_output: str) -> dict:
        """
        Parse Docker build error output and return specific diagnosis.
        The more specific the diagnosis, the better Tool 1 can fix it.
        """
        error_lower = error_output.lower()

        # ── Dependency errors ──
        if "could not find a version" in error_lower or "no matching distribution" in error_lower:
            # Extract package name
            pkg = self._extract_package_name(error_output)
            return {
                "error_type": "dependency_not_found",
                "error_summary": f"Python package not found on PyPI: {pkg}",
                "fixable_by_llm": True,
                "fix_instruction": (
                    f"The package '{pkg}' in requirements.txt does not exist on PyPI. "
                    f"Check the exact package name and fix requirements.txt. "
                    f"Common issues: 'flask-sqla' should be 'flask-sqlalchemy', "
                    f"'python-mysql' should be 'mysql-connector-python'"
                ),
            }

        if "modulenotfounderror" in error_lower or "no module named" in error_lower:
            mod = self._extract_module_name(error_output)
            return {
                "error_type": "missing_module",
                "error_summary": f"Python module not found at runtime: {mod}",
                "fixable_by_llm": True,
                "fix_instruction": (
                    f"Module '{mod}' is imported in Python code but not in requirements.txt. "
                    f"Add it to requirements.txt. Note: stdlib modules (os, json, re, etc.) "
                    f"don't need to be in requirements.txt."
                ),
            }

        # ── Dockerfile errors ──
        if "dockerfile parse error" in error_lower or "unknown instruction" in error_lower:
            return {
                "error_type": "dockerfile_syntax",
                "error_summary": "Dockerfile has syntax error",
                "fixable_by_llm": True,
                "fix_instruction": (
                    "The Dockerfile has a syntax error. Common issues: "
                    "instruction names must be uppercase (FROM, RUN, COPY, CMD), "
                    "each instruction on its own line, "
                    "EXPOSE takes a port number not a string"
                ),
            }

        if "failed to solve" in error_lower and "copy" in error_lower:
            return {
                "error_type": "copy_failed",
                "error_summary": "COPY instruction failed — file not found",
                "fixable_by_llm": True,
                "fix_instruction": (
                    "A COPY instruction in the Dockerfile references a file that doesn't exist. "
                    "Check that all files referenced in COPY commands actually exist in the build context. "
                    "The Dockerfile and all copied files must be in the same directory."
                ),
            }

        # ── Base image errors ──
        if "pull access denied" in error_lower or "manifest unknown" in error_lower:
            image = self._extract_image_name(error_output)
            return {
                "error_type": "base_image_not_found",
                "error_summary": f"Docker base image not found: {image}",
                "fixable_by_llm": True,
                "fix_instruction": (
                    f"The base image '{image}' doesn't exist on Docker Hub. "
                    f"Use a valid image tag. Examples: python:3.11-slim, "
                    f"openjdk:11-jdk-slim, node:18-alpine, ubuntu:22.04"
                ),
            }

        # ── Compilation errors ──
        if "syntaxerror" in error_lower or "syntax error" in error_lower:
            return {
                "error_type": "python_syntax_error",
                "error_summary": "Python syntax error in application code",
                "fixable_by_llm": True,
                "fix_instruction": (
                    "Python code has a syntax error. "
                    f"Error details: {error_output[-500:]}"
                ),
            }

        if "error: cannot find symbol" in error_lower or "error: package" in error_lower:
            return {
                "error_type": "java_compile_error",
                "error_summary": "Java compilation error",
                "fixable_by_llm": True,
                "fix_instruction": (
                    f"Java compilation failed. Check imports and dependencies in pom.xml. "
                    f"Error: {error_output[-500:]}"
                ),
            }

        # ── Generic fallback ──
        return {
            "error_type": "unknown_build_error",
            "error_summary": "Build failed with unknown error",
            "fixable_by_llm": True,
            "fix_instruction": (
                f"Docker build failed. Full error output:\n{error_output[-1000:]}\n"
                f"Analyze the error and fix the relevant file."
            ),
        }

    def _extract_package_name(self, error_output: str) -> str:
        import re
        match = re.search(r"requirement '([^']+)'", error_output)
        if match:
            return match.group(1)
        match = re.search(r"No matching distribution found for ([^\s]+)", error_output)
        if match:
            return match.group(1)
        return "unknown_package"

    def _extract_module_name(self, error_output: str) -> str:
        import re
        match = re.search(r"No module named '([^']+)'", error_output)
        if match:
            return match.group(1)
        return "unknown_module"

    def _extract_image_name(self, error_output: str) -> str:
        import re
        match = re.search(r"pull access denied for ([^\s:]+)", error_output)
        if match:
            return match.group(1)
        return "unknown_image"

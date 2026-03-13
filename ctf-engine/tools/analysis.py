"""
tools/analysis.py — Code Analysis & Validation Tools.

Provides static checks, code search, and JSON validation for
debugging generated lab code before deployment.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def check_syntax(path: str, language: str | None = None) -> str:
    """
    Check a file for syntax errors.
    Auto-detects language from extension if not specified.
    Supports: js, ts, py, json.
    """
    p = Path(path)
    ext = p.suffix.lower().lstrip(".")
    lang = language or ext

    if lang in ("js", "javascript"):
        result = subprocess.run(
            ["node", "--check", str(p)],
            capture_output=True, text=True, timeout=10,
        )
        return result.stderr.strip() if result.returncode else f"OK: {p.name} has valid JavaScript syntax."

    elif lang in ("py", "python"):
        result = subprocess.run(
            ["python3", "-m", "py_compile", str(p)],
            capture_output=True, text=True, timeout=10,
        )
        return result.stderr.strip() if result.returncode else f"OK: {p.name} has valid Python syntax."

    elif lang == "json":
        try:
            json.loads(p.read_text())
            return f"OK: {p.name} is valid JSON."
        except json.JSONDecodeError as e:
            return f"ERROR: Invalid JSON in {p.name}: {e}"

    else:
        return f"SKIP: Syntax check not supported for '{lang}'"


def search_code(path: str, pattern: str) -> str:
    """Search for a regex pattern in files under the given path."""
    try:
        result = subprocess.run(
            ["grep", "-rn", "--include=*", pattern, path],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.strip()
        if not output:
            return f"No matches for '{pattern}' in {path}"
        lines = output.split("\n")
        # Cap results to avoid flooding context
        if len(lines) > 20:
            lines = lines[:20] + [f"... ({len(lines) - 20} more matches)"]
        return "\n".join(lines)
    except subprocess.TimeoutExpired:
        return "ERROR: search timed out"
    except Exception as e:
        return f"ERROR: {e}"


def validate_json(content: str) -> str:
    """Validate a JSON string and return a formatted preview."""
    try:
        parsed = json.loads(content)
        formatted = json.dumps(parsed, indent=2)
        preview = formatted[:500]
        return f"OK: Valid JSON\n{preview}{'...' if len(formatted) > 500 else ''}"
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON — {e}"

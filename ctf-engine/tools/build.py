"""
tools/build.py — Build & Package Tools.

Runs npm/pip installs and arbitrary bash commands inside the Docker sandbox.
"""

import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


def _run_in_sandbox(cmd: str, sandbox, timeout: int = 60) -> str:
    """Execute a command in the DockerSandbox and return output."""
    try:
        return sandbox.execute_bash(cmd)
    except Exception as e:
        return f"ERROR: sandbox execution failed: {e}"


def run_bash(command: str, sandbox=None) -> str:
    """Run any bash command. Prefer this for complex shell operations."""
    if sandbox:
        return _run_in_sandbox(command, sandbox)
    # Fallback: run on host (for setup only, not inside lab)
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True,
            text=True, timeout=60,
        )
        return (result.stdout + result.stderr).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out after 60s"
    except Exception as e:
        return f"ERROR: {e}"


def npm_install(packages: str, cwd: str = ".", sandbox=None) -> str:
    """Install npm package(s). packages can be a space-separated list."""
    cmd = f"cd {cwd} && npm install {packages} --no-audit --no-fund 2>&1"
    return run_bash(cmd, sandbox)


def npm_init(cwd: str = ".", sandbox=None) -> str:
    """Run npm init -y in the given directory."""
    cmd = f"cd {cwd} && npm init -y 2>&1"
    return run_bash(cmd, sandbox)


def pip_install(packages: str, sandbox=None) -> str:
    """Install Python package(s) via pip. packages can be space-separated."""
    cmd = f"pip install {packages} --quiet 2>&1"
    return run_bash(cmd, sandbox)


def check_installed(package: str, tool: str = "npm", sandbox=None) -> str:
    """Check whether an npm or pip package is already installed."""
    if tool == "npm":
        cmd = f"npm list {package} --depth=0 2>&1"
    elif tool == "pip":
        cmd = f"pip show {package} 2>&1"
    else:
        return f"ERROR: Unknown tool '{tool}'. Use 'npm' or 'pip'."
    return run_bash(cmd, sandbox)

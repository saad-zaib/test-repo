"""
tools/reporting.py — Reporting Tools.

Saves lab metadata, exploit scripts, and writeups to the workspace.
These outputs are used by the orchestrator to finalize and register the lab.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_WORKSPACE: Path = Path("/tmp/ctf_workspace")


def set_workspace(path: str):
    """Set the active workspace (called by agent at init)."""
    global _WORKSPACE
    _WORKSPACE = Path(path)


def save_lab_metadata(lab_id: str, data: dict) -> str:
    """Write lab metadata (description, flag, ports, etc.) as a JSON file."""
    try:
        meta_dir = _WORKSPACE / "meta"
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_path = meta_dir / "lab.json"

        data["lab_id"] = lab_id
        data["generated_at"] = datetime.now(timezone.utc).isoformat()

        meta_path.write_text(json.dumps(data, indent=2))
        return f"OK: Lab metadata saved to {meta_path}"
    except Exception as e:
        return f"ERROR saving metadata: {e}"


def mark_lab_complete(lab_id: str, flag: str) -> str:
    """
    Mark the lab as successfully completed.
    Writes a completion marker that the orchestrator checks.
    """
    try:
        marker_path = _WORKSPACE / "meta" / "complete.json"
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker = {
            "lab_id": lab_id,
            "flag": flag,
            "status": "complete",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        marker_path.write_text(json.dumps(marker, indent=2))
        return f"✅ Lab {lab_id} marked as COMPLETE. Flag: {flag}"
    except Exception as e:
        return f"ERROR marking lab complete: {e}"


def save_exploit_script(lab_id: str, code: str, filename: str = "exploit.sh") -> str:
    """Save the working exploit script to the lab workspace."""
    try:
        exploit_path = _WORKSPACE / "meta" / filename
        exploit_path.parent.mkdir(parents=True, exist_ok=True)
        exploit_path.write_text(code)
        exploit_path.chmod(0o755)
        return f"OK: Exploit saved to {exploit_path}"
    except Exception as e:
        return f"ERROR saving exploit: {e}"

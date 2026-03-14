"""
tools/filesystem.py — File System Tools.

All paths are relative to the lab workspace directory set in the sandbox.
The sandbox exposes a `workspace_path` that these tools resolve against.
"""

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Default workspace — overridden during agent initialization
_WORKSPACE: Path = Path("/tmp/ctf_workspace")


def set_workspace(path: str):
    """Called by the agent to set the active lab workspace."""
    global _WORKSPACE
    _WORKSPACE = Path(path)
    _WORKSPACE.mkdir(parents=True, exist_ok=True)


def _resolve(path: str) -> Path:
    """Resolve a relative or absolute path safely within the workspace."""
    p = Path(path)
    if not p.is_absolute():
        p = _WORKSPACE / p
    return p


def read_file(path: str) -> str:
    """Read a file from the lab workspace and return its contents."""
    resolved = _resolve(path)
    try:
        return resolved.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"ERROR: File not found: {resolved}"
    except Exception as e:
        return f"ERROR reading {path}: {e}"


def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent directories as needed."""
    resolved = _resolve(path)
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return f"OK: Written {len(content)} bytes to {resolved}"
    except Exception as e:
        return f"ERROR writing {path}: {e}"


def append_file(path: str, content: str) -> str:
    """Append content to an existing file (creates if missing)."""
    resolved = _resolve(path)
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved, "a", encoding="utf-8") as f:
            f.write(content)
        return f"OK: Appended {len(content)} bytes to {resolved}"
    except Exception as e:
        return f"ERROR appending to {path}: {e}"


def list_files(path: str = ".") -> str:
    """List files and directories at the given path."""
    resolved = _resolve(path)
    try:
        entries = []
        for item in sorted(resolved.iterdir()):
            kind = "DIR " if item.is_dir() else "FILE"
            size = item.stat().st_size if item.is_file() else "-"
            entries.append(f"{kind}  {item.name}  ({size} bytes)")
        if not entries:
            return f"(empty directory: {resolved})"
        return f"Contents of {resolved}:\n" + "\n".join(entries)
    except FileNotFoundError:
        return f"ERROR: Directory not found: {resolved}"
    except Exception as e:
        return f"ERROR listing {path}: {e}"


def delete_file(path: str) -> str:
    """Delete a file from the workspace."""
    resolved = _resolve(path)
    try:
        if resolved.is_file():
            resolved.unlink()
            return f"OK: Deleted {resolved}"
        elif resolved.is_dir():
            import shutil
            shutil.rmtree(resolved)
            return f"OK: Deleted directory {resolved}"
        else:
            return f"ERROR: Path does not exist: {resolved}"
    except Exception as e:
        return f"ERROR deleting {path}: {e}"


def patch_file(path: str, find: str, replace: str) -> str:
    """Replace a specific substring in a file WITHOUT rewriting the whole file.
    Use this for targeted fixes — e.g. changing one dependency version or fixing one line.
    The 'find' string must appear exactly once in the file.
    """
    resolved = _resolve(path)
    try:
        content = resolved.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"ERROR: File not found: {resolved}"
    except Exception as e:
        return f"ERROR reading {path}: {e}"

    count = content.count(find)
    if count == 0:
        # Show a preview of the file to help the LLM find the right string
        preview = content[:500]
        return (
            f"ERROR: The 'find' string was NOT found in {path}.\n"
            f"File preview (first 500 chars):\n{preview}"
        )
    if count > 1:
        return (
            f"ERROR: The 'find' string appears {count} times in {path}. "
            f"Use a more specific string to match exactly once."
        )

    new_content = content.replace(find, replace, 1)
    try:
        resolved.write_text(new_content, encoding="utf-8")
        return f"OK: Patched {path} — replaced {len(find)} chars with {len(replace)} chars"
    except Exception as e:
        return f"ERROR writing {path}: {e}"

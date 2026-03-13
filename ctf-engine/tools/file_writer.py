"""
tools/file_writer.py — Safe file writing tool

Writes files inside the sandbox without any bash quoting issues.
The LLM passes filename and content as structured arguments,
completely bypassing echo/cat heredoc quoting problems.
"""

import logging
import base64
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_sandbox_ref = None

def set_sandbox(sandbox):
    global _sandbox_ref
    _sandbox_ref = sandbox


@tool
def write_file(filename: str, content: str) -> str:
    """Write content to a file in the sandbox workspace. Handles all quoting safely.
    Use this instead of echo or cat heredoc to avoid bash syntax errors.
    
    Args:
        filename: Path to the file (relative to /workspace, or absolute)
        content: The full file content to write
    
    Returns:
        Success or error message.
    
    Example: write_file(filename='app.js', content='const express = require("express"); ...')
    """
    if _sandbox_ref is None:
        return "Error: Sandbox not initialized."

    logger.info(f"[Tool] write_file: {filename} ({len(content)} bytes)")

    # Encode content as base64 to avoid ALL quoting issues
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    
    # Ensure parent directory exists, then decode and write
    cmd = f"mkdir -p $(dirname '{filename}') && echo '{encoded}' | base64 -d > '{filename}' && echo 'FILE_WRITTEN: {filename}'"
    
    output = _sandbox_ref.execute_bash(cmd)
    
    if "FILE_WRITTEN" in output:
        logger.info(f"[Tool] File written: {filename}")
        return f"Successfully wrote {len(content)} bytes to {filename}"
    else:
        logger.warning(f"[Tool] File write failed: {output}")
        return f"Failed to write {filename}: {output}"

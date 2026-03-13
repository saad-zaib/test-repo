"""
tools/__init__.py — Central tool registry and dispatcher.

Every tool is a plain Python function. The LLM calls tools by outputting:
    <tool>tool_name</tool>
    <args>{"key": "value"}</args>

The dispatcher parses this, looks up the function, and calls it.
"""

import json
import logging
import re
from typing import Callable

logger = logging.getLogger(__name__)

# ── Lazy imports to keep startup fast ──────────────────────────────────────────
from tools.filesystem import (
    read_file, write_file, list_files, delete_file, append_file,
)
from tools.docker_tools import (
    docker_build, docker_up, docker_down, docker_ps,
    docker_logs, docker_exec, docker_inspect,
)
from tools.network import (
    http_request, wait_for_service, check_connectivity,
)
from tools.exploit import (
    send_exploit, verify_flag, decode_jwt, forge_jwt,
)
from tools.database import (
    mongo_query, check_db_connection,
)
from tools.build import (
    npm_install, pip_install, npm_init, run_bash, check_installed,
)
from tools.analysis import (
    check_syntax, search_code, validate_json,
)
from tools.memory import (
    web_search, save_note, get_note, list_notes, get_spec,
)
from tools.reporting import (
    save_lab_metadata, mark_lab_complete, save_exploit_script,
)

# ── Registry: name → function ───────────────────────────────────────────────
TOOL_REGISTRY: dict[str, Callable] = {
    # Filesystem
    "read_file":        read_file,
    "write_file":       write_file,
    "list_files":       list_files,
    "delete_file":      delete_file,
    "append_file":      append_file,

    # Docker
    "docker_build":     docker_build,
    "docker_up":        docker_up,
    "docker_down":      docker_down,
    "docker_ps":        docker_ps,
    "docker_logs":      docker_logs,
    "docker_exec":      docker_exec,
    "docker_inspect":   docker_inspect,

    # Network
    "http_request":     http_request,
    "wait_for_service": wait_for_service,
    "check_connectivity": check_connectivity,

    # Exploit & Attack
    "send_exploit":     send_exploit,
    "verify_flag":      verify_flag,
    "decode_jwt":       decode_jwt,
    "forge_jwt":        forge_jwt,

    # Database
    "mongo_query":      mongo_query,
    "check_db_connection": check_db_connection,

    # Build & Package
    "npm_install":      npm_install,
    "pip_install":      pip_install,
    "npm_init":         npm_init,
    "run_bash":         run_bash,
    "check_installed":  check_installed,

    # Code Analysis
    "check_syntax":     check_syntax,
    "search_code":      search_code,
    "validate_json":    validate_json,

    # Memory & Context
    "web_search":       web_search,
    "save_note":        save_note,
    "get_note":         get_note,
    "list_notes":       list_notes,
    "get_spec":         get_spec,

    # Reporting
    "save_lab_metadata":    save_lab_metadata,
    "mark_lab_complete":    mark_lab_complete,
    "save_exploit_script":  save_exploit_script,
}

ALL_TOOLS = list(TOOL_REGISTRY.keys())


def get_tool_descriptions() -> str:
    """Return a compact tool list for injection into the system prompt."""
    categories = {
        "Filesystem":  ["read_file", "write_file", "list_files", "delete_file", "append_file"],
        "Docker":      ["docker_build", "docker_up", "docker_down", "docker_ps", "docker_logs", "docker_exec", "docker_inspect"],
        "Network":     ["http_request", "wait_for_service", "check_connectivity"],
        "Exploit":     ["send_exploit", "verify_flag", "decode_jwt", "forge_jwt"],
        "Database":    ["mongo_query", "check_db_connection"],
        "Build":       ["npm_install", "pip_install", "npm_init", "run_bash", "check_installed"],
        "Analysis":    ["check_syntax", "search_code", "validate_json"],
        "Memory":      ["web_search", "save_note", "get_note", "list_notes", "get_spec"],
        "Reporting":   ["save_lab_metadata", "mark_lab_complete", "save_exploit_script"],
    }
    lines = ["AVAILABLE TOOLS:"]
    for category, names in categories.items():
        lines.append(f"\n[{category}]")
        for name in names:
            fn = TOOL_REGISTRY.get(name)
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            lines.append(f"  {name}: {doc}")
    lines.append("\nSpecial: DONE (declare success)")
    return "\n".join(lines)


def parse_tool_call(text: str) -> tuple[str | None, dict]:
    """
    Extract tool name and args from LLM output.

    Expected format:
        <tool>tool_name</tool>
        <args>{"key": "value"}</args>

    Returns (tool_name, args_dict) or (None, {}) if not found.
    """
    tool_match = re.search(r"<tool>(.*?)</tool>", text, re.DOTALL | re.IGNORECASE)
    args_match  = re.search(r"<args>(.*?)</args>",  text, re.DOTALL | re.IGNORECASE)

    if not tool_match:
        return None, {}

    tool_name = tool_match.group(1).strip()
    args = {}
    if args_match:
        try:
            args = json.loads(args_match.group(1).strip())
        except json.JSONDecodeError:
            logger.warning(f"[Tools] Failed to parse args JSON for tool '{tool_name}'")

    return tool_name, args


def execute_tool(tool_name: str, args: dict, sandbox=None) -> str:
    """
    Look up and call a tool by name.

    sandbox is passed to tools that need to run inside the Docker sandbox
    (docker_exec, run_bash). All other tools ignore it.
    """
    if tool_name not in TOOL_REGISTRY:
        return f"ERROR: Unknown tool '{tool_name}'. Available: {', '.join(ALL_TOOLS)}"

    fn = TOOL_REGISTRY[tool_name]

    # Inject sandbox reference for tools that need it
    if sandbox is not None and "sandbox" not in args:
        import inspect
        if "sandbox" in inspect.signature(fn).parameters:
            args = {**args, "sandbox": sandbox}

    try:
        result = fn(**args)
        return str(result)
    except TypeError as e:
        return f"ERROR: Wrong arguments for '{tool_name}': {e}"
    except Exception as e:
        logger.exception(f"[Tools] Tool '{tool_name}' raised an exception")
        return f"ERROR in {tool_name}: {type(e).__name__}: {e}"


def truncate_output(tool_name: str, output: str) -> str:
    """
    Enforce per-tool output budgets to protect the context window.
    Verbose tools like docker_logs are trimmed to their tail (recent output).
    """
    limits = {
        "read_file":        1500,
        "docker_logs":      800,
        "run_bash":         600,
        "npm_install":      400,
        "pip_install":      400,
        "http_request":     400,
        "send_exploit":     400,
        "web_search":       500,
        "docker_ps":        300,
        "docker_inspect":   400,
        "search_code":      600,
        "mongo_query":      400,
    }
    limit = limits.get(tool_name, 600)
    if len(output) > limit:
        return output[-limit:] + f"\n...[truncated — showing last {limit} chars]"
    return output

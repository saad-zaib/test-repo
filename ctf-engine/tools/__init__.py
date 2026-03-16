"""
tools/__init__.py — Central tool registry and dispatcher.

Every tool is a plain Python function. The LLM calls tools by outputting:
    <tool>tool_name</tool>
    <args>{"key": "value"}</args>

The dispatcher parses this, looks up the function, and calls it.
"""

import inspect
import json
import logging
import re
from typing import Callable

logger = logging.getLogger(__name__)

# ── Lazy imports to keep startup fast ──────────────────────────────────────────
from tools.filesystem import (
    read_file, write_file, list_files, delete_file, append_file, patch_file,
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
    "patch_file":       patch_file,
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
    """
    Return a tool list with EXACT parameter signatures for injection into the system prompt.
    Showing signatures prevents the LLM from guessing wrong argument names.
    """

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

    lines = ["AVAILABLE TOOLS (use EXACT parameter names shown):"]
    for category, names in categories.items():
        lines.append(f"\n[{category}]")
        for name in names:
            fn = TOOL_REGISTRY.get(name)
            if fn is None:
                continue
            doc = (fn.__doc__ or "").strip().split("\n")[0]

            # Build signature string, excluding internal params like 'sandbox'
            try:
                sig = inspect.signature(fn)
                params = []
                for pname, param in sig.parameters.items():
                    if pname in ("sandbox",):  # Internal injection params
                        continue
                    annotation = (
                        f": {param.annotation.__name__}"
                        if param.annotation is not inspect.Parameter.empty
                        and hasattr(param.annotation, "__name__")
                        else ""
                    )
                    if param.default is not inspect.Parameter.empty:
                        default = repr(param.default)
                        params.append(f"{pname}{annotation} = {default}")
                    else:
                        params.append(f"{pname}{annotation}")
                sig_str = f"({', '.join(params)})"
            except (ValueError, TypeError):
                sig_str = "(...)"

            lines.append(f"  {name}{sig_str} — {doc}")

    lines.append(
        "\n[Special]\n"
        "  DONE(summary: str, flag: str) — Declare lab complete after flag is captured"
    )
    return "\n".join(lines)


def _repair_json(raw: str) -> str:
    """
    Fix common LLM JSON output issues:
    - Raw newlines/tabs/carriage-returns inside string values (invalid in JSON spec)
    - Auto-closes truncated strings, curly braces, and square brackets at the end.
    """
    result = []
    in_string = False
    escape = False
    i = 0
    while i < len(raw):
        c = raw[i]
        if escape:
            result.append(c)
            escape = False
        elif c == '\\':
            if in_string:
                escape = True
            result.append(c)
        elif c == '"':
            in_string = not in_string
            result.append(c)
        elif in_string and c == '\n':
            result.append('\\n')
        elif in_string and c == '\r':
            result.append('\\r')
        elif in_string and c == '\t':
            result.append('\\t')
        else:
            result.append(c)
        i += 1

    if in_string:
        result.append('"')
        
    repaired = ''.join(result).strip()
    
    # Very simplistic auto-closing of dicts/lists for truncated output
    open_curly = repaired.count('{') - repaired.count('\\{')
    close_curly = repaired.count('}') - repaired.count('\\}')
    if open_curly > close_curly:
        repaired += '}' * (open_curly - close_curly)
        
    return repaired


def parse_tool_call(text: str) -> tuple[str | None, dict]:
    tool_match = re.search(r"<tool>(.*?)</tool>", text, re.DOTALL | re.IGNORECASE)
    args_match  = re.search(r"<args>\s*(\{.*?(?:</args>|$))", text, re.DOTALL | re.IGNORECASE)

    if not tool_match:
        return None, {}

    tool_name = tool_match.group(1).strip().split('\n')[0].split('{')[0].strip()

    TOOL_ALIASES = {
        "websearch": "web_search",
        "web_search_tool": "web_search",
        "search": "web_search",
        "run_docker_compose": "docker_up",
        "docker_compose_up": "docker_up",
        "docker_compose": "docker_up",
        "http": "http_request",
        "http_get": "http_request",
        "http_post": "http_request",
        "request": "http_request",
        "bash": "run_bash",
        "shell": "run_bash",
        "execute": "run_bash",
        "exec": "run_bash",
        "create_file": "write_file",
        "file_write": "write_file",
    }
    tool_name = TOOL_ALIASES.get(tool_name, tool_name)

    args = {}
    if args_match:
        raw_json = args_match.group(1).strip()
        if raw_json.endswith("</args>"):
            raw_json = raw_json[:-7].strip()

        try:
            args = json.loads(raw_json)
        except json.JSONDecodeError:
            try:
                repaired = _repair_json(raw_json)
                args = json.loads(repaired)
                logger.info(f"[Tools] JSON repaired for tool '{tool_name}'")
            except json.JSONDecodeError:
                logger.warning(
                    f"[Tools] Failed to parse args JSON for tool '{tool_name}' "
                    f"(even after repair). Raw: {raw_json[:200]}"
                )

    return tool_name, args


def execute_tool(tool_name: str, args: dict, sandbox=None) -> str:
    """
    Look up and call a tool by name.

    - Injects sandbox for tools that need it.
    - Silently strips unexpected kwargs to prevent TypeErrors from LLM hallucination.
    """
    if tool_name not in TOOL_REGISTRY:
        categorized = {
            "files": ["read_file","write_file","patch_file","list_files","delete_file"],
            "docker": ["docker_up","docker_down","docker_logs","docker_ps","docker_exec"],
            "network": ["http_request","wait_for_service","send_exploit","verify_flag"],
            "build": ["run_bash","npm_install","pip_install"],
            "search": ["web_search"],
        }
        hint = "\n".join(f"  {k}: {', '.join(v)}" for k,v in categorized.items())
        return f"ERROR: Unknown tool '{tool_name}'.\nAvailable tools:\n{hint}"

    fn = TOOL_REGISTRY[tool_name]

    # Inject sandbox reference for tools that need it
    if sandbox is not None and "sandbox" not in args:
        if "sandbox" in inspect.signature(fn).parameters:
            args = {**args, "sandbox": sandbox}

    # ── Strip unknown kwargs (prevents TypeError from LLM adding extra args) ──
    valid_params = set(inspect.signature(fn).parameters.keys())
    filtered_args = {k: v for k, v in args.items() if k in valid_params}
    dropped = set(args.keys()) - set(filtered_args.keys())
    if dropped:
        logger.warning(f"[Tools] Dropped unknown args for '{tool_name}': {dropped}")

    try:
        result = fn(**filtered_args)
        return str(result)
    except TypeError as e:
        return f"ERROR: Wrong arguments for '{tool_name}': {e}"
    except Exception as e:
        logger.exception(f"[Tools] Tool '{tool_name}' raised an exception")
        return f"ERROR in {tool_name}: {type(e).__name__}: {e}"


def truncate_output(tool_name: str, output: str) -> str:
    """
    Error-aware output truncation.
    - ERROR outputs: show up to ERROR_LIMIT chars so the LLM gets full diagnostics.
    - OK outputs: head+tail truncation with per-tool budgets to protect context window.
    """
    ERROR_LIMIT = 2000  # Errors need full context for diagnosis

    limits = {
        "read_file":        1500,
        "docker_logs":      1000,
        "docker_up":        1200,
        "docker_down":      400,
        "docker_build":     1200,
        "run_bash":         800,
        "npm_install":      600,
        "pip_install":      400,
        "http_request":     600,
        "send_exploit":     600,
        "web_search":       500,
        "docker_ps":        300,
        "docker_inspect":   400,
        "search_code":      600,
        "mongo_query":      400,
    }

    is_error = output.lstrip().upper().startswith("ERROR")
    if is_error:
        # Errors: show as much as possible so the LLM can diagnose
        if len(output) > ERROR_LIMIT:
            return output[:ERROR_LIMIT] + f"\n...[truncated — showing first {ERROR_LIMIT} of {len(output)} chars]"
        return output

    # Success: head+tail truncation so both start and end are visible
    limit = limits.get(tool_name, 600)
    if len(output) > limit:
        half = limit // 2
        return (
            output[:half]
            + f"\n...[truncated {len(output) - limit} chars]...\n"
            + output[-half:]
        )
    return output

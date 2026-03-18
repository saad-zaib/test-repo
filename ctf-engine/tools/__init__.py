"""
tools/__init__.py — Central tool registry and dispatcher.

Exploit-phase tools (send_exploit, verify_flag, decode_jwt, forge_jwt,
save_exploit_script, run_strix_exploit) have been removed.
The agent now stops at DEPLOY — no exploitation phase.
"""

import inspect
import json
import logging
import re
from typing import Callable

logger = logging.getLogger(__name__)

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
    save_lab_metadata, mark_lab_complete,
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
    "http_request":       http_request,
    "wait_for_service":   wait_for_service,
    "check_connectivity": check_connectivity,

    # Database
    "mongo_query":        mongo_query,
    "check_db_connection": check_db_connection,

    # Build & Package
    "npm_install":    npm_install,
    "pip_install":    pip_install,
    "npm_init":       npm_init,
    "run_bash":       run_bash,
    "check_installed": check_installed,

    # Code Analysis
    "check_syntax":   check_syntax,
    "search_code":    search_code,
    "validate_json":  validate_json,

    # Memory & Context
    "web_search":  web_search,
    "save_note":   save_note,
    "get_note":    get_note,
    "list_notes":  list_notes,
    "get_spec":    get_spec,

    # Reporting
    "save_lab_metadata": save_lab_metadata,
    "mark_lab_complete": mark_lab_complete,
}

ALL_TOOLS = list(TOOL_REGISTRY.keys())


def get_tool_descriptions() -> str:
    """Return tool list with EXACT parameter signatures for the system prompt."""

    categories = {
        "Filesystem": ["read_file", "write_file", "patch_file", "list_files", "delete_file", "append_file"],
        "Docker":     ["docker_build", "docker_up", "docker_down", "docker_ps", "docker_logs", "docker_exec", "docker_inspect"],
        "Network":    ["http_request", "wait_for_service", "check_connectivity"],
        "Database":   ["mongo_query", "check_db_connection"],
        "Build":      ["npm_install", "pip_install", "npm_init", "run_bash", "check_installed"],
        "Analysis":   ["check_syntax", "search_code", "validate_json"],
        "Memory":     ["web_search", "save_note", "get_note", "list_notes", "get_spec"],
        "Reporting":  ["save_lab_metadata", "mark_lab_complete"],
    }

    lines = ["AVAILABLE TOOLS (use EXACT parameter names shown):"]
    for category, names in categories.items():
        lines.append(f"\n[{category}]")
        for name in names:
            fn = TOOL_REGISTRY.get(name)
            if fn is None:
                continue
            doc = (fn.__doc__ or "").strip().split("\n")[0]

            try:
                sig    = inspect.signature(fn)
                params = []
                for pname, param in sig.parameters.items():
                    if pname in ("sandbox",):
                        continue
                    annotation = (
                        f": {param.annotation.__name__}"
                        if param.annotation is not inspect.Parameter.empty
                        and hasattr(param.annotation, "__name__")
                        else ""
                    )
                    if param.default is not inspect.Parameter.empty:
                        params.append(f"{pname}{annotation} = {repr(param.default)}")
                    else:
                        params.append(f"{pname}{annotation}")
                sig_str = f"({', '.join(params)})"
            except (ValueError, TypeError):
                sig_str = "(...)"

            lines.append(f"  {name}{sig_str} — {doc}")

    lines.append(
        "\n[Special]\n"
        "  DONE(summary: str) — Declare lab complete after service is confirmed running"
    )
    return "\n".join(lines)


def _repair_json(raw: str) -> str:
    """Fix common LLM JSON output issues."""
    result   = []
    in_string = False
    escape   = False
    i        = 0
    while i < len(raw):
        c = raw[i]
        if escape:
            result.append(c)
            escape = False
        elif c == "\\":
            if in_string:
                escape = True
            result.append(c)
        elif c == '"':
            in_string = not in_string
            result.append(c)
        elif in_string and c == "\n":
            result.append("\\n")
        elif in_string and c == "\r":
            result.append("\\r")
        elif in_string and c == "\t":
            result.append("\\t")
        else:
            result.append(c)
        i += 1

    if in_string:
        result.append('"')

    repaired    = "".join(result).strip()
    open_curly  = repaired.count("{") - repaired.count("\\{")
    close_curly = repaired.count("}") - repaired.count("\\}")
    if open_curly > close_curly:
        repaired += "}" * (open_curly - close_curly)

    return repaired


_TOOL_PARAM_NAMES: dict[str, list[str]] = {
    "write_file":       ["path", "content"],
    "read_file":        ["path"],
    "delete_file":      ["path"],
    "append_file":      ["path", "content"],
    "patch_file":       ["path", "old_text", "new_text"],
    "docker_up":        ["compose_file"],
    "docker_down":      ["compose_file"],
    "docker_build":     ["compose_file"],
    "docker_logs":      ["service", "lines"],
    "docker_exec":      ["container", "command"],
    "http_request":     ["url", "method", "payload", "headers"],
    "wait_for_service": ["url", "timeout"],
    "npm_install":      ["packages"],
    "pip_install":      ["packages"],
    "run_bash":         ["command"],
    "web_search":       ["query"],
    "list_files":       ["path"],
}


def _parse_function_call_args(tool_name: str, raw: str) -> dict:
    """Parse function-call arguments like: write_file(path="X", content="Y")"""
    raw = raw.strip()
    if not raw:
        return {}

    tokens: list[tuple[str | None, str]] = []
    i = 0
    n = len(raw)

    while i < n:
        while i < n and raw[i] in " ,\t\r\n":
            i += 1
        if i >= n:
            break

        key       = None
        key_match = re.match(r"(\w+)\s*=\s*", raw[i:])
        if key_match:
            key = key_match.group(1)
            i  += key_match.end()
            if i >= n:
                break

        if i < n and raw[i:i+3] in ('"""', "'''"):
            quote = raw[i:i+3]
            i    += 3
            end   = raw.find(quote, i)
            if end == -1:
                value = raw[i:]
                i     = n
            else:
                value = raw[i:end]
                i     = end + 3
            tokens.append((key, value))
        elif i < n and raw[i] in ('"', "'"):
            quote       = raw[i]
            i          += 1
            value_chars = []
            while i < n:
                if raw[i] == "\\" and i + 1 < n:
                    value_chars.append(raw[i:i+2])
                    i += 2
                elif raw[i] == quote:
                    i += 1
                    break
                else:
                    value_chars.append(raw[i])
                    i += 1
            value = "".join(value_chars)
            value = (value.replace("\\n", "\n").replace("\\t", "\t")
                         .replace('\\"', '"').replace("\\'", "'"))
            tokens.append((key, value))
        elif i < n and raw[i] == "{":
            depth = 0
            start = i
            while i < n:
                if raw[i] == "{":
                    depth += 1
                elif raw[i] == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            try:
                value = json.loads(raw[start:i])
                tokens.append((key, value))
            except json.JSONDecodeError:
                tokens.append((key, raw[start:i]))
        else:
            m = re.match(r"[^\s,)]+", raw[i:])
            if m:
                tokens.append((key, m.group(0)))
                i += m.end()
            else:
                i += 1

    args: dict             = {}
    positional_values: list = []

    for key, value in tokens:
        if key:
            args[key] = value
        else:
            positional_values.append(value)

    if positional_values:
        param_names = _TOOL_PARAM_NAMES.get(tool_name, [])
        for idx, val in enumerate(positional_values):
            if idx < len(param_names):
                param_name = param_names[idx]
                if param_name not in args:
                    args[param_name] = val

    return args


def parse_tool_call(text: str) -> tuple[str | None, dict]:

    TOOL_ALIASES = {
        "websearch":          "web_search",
        "web_search_tool":    "web_search",
        "search":             "web_search",
        "run_docker_compose": "docker_up",
        "docker_compose_up":  "docker_up",
        "docker_compose":     "docker_up",
        "http":               "http_request",
        "http_get":           "http_request",
        "http_post":          "http_request",
        "request":            "http_request",
        "bash":               "run_bash",
        "shell":              "run_bash",
        "execute":            "run_bash",
        "exec":               "run_bash",
        "create_file":        "write_file",
        "file_write":         "write_file",
    }

    logger.debug(f"[Tools] Parsing response ({len(text)} chars): {text[:500]}")

    tool_match = re.search(r"<tool>(.*?)</tool>", text, re.DOTALL | re.IGNORECASE)
    args_match = re.search(r"<args>\s*(.*?)\s*</args>", text, re.DOTALL | re.IGNORECASE)
    if not args_match:
        args_match = re.search(r"<args>\s*(.*?)$", text, re.DOTALL | re.IGNORECASE)

    # Fallback 1: JSON inside tool tags
    if tool_match:
        inner = tool_match.group(1).strip()
        if inner.startswith("{"):
            try:
                obj = json.loads(inner)
                t   = obj.pop("tool", obj.pop("name", None))
                if t:
                    t = TOOL_ALIASES.get(t, t)
                    for unwrap_key in ("arguments", "params", "parameters", "input"):
                        if unwrap_key in obj and isinstance(obj[unwrap_key], dict):
                            obj = obj[unwrap_key]
                            break
                        elif unwrap_key in obj and isinstance(obj[unwrap_key], list):
                            obj.pop(unwrap_key, None)
                    return t, obj
            except json.JSONDecodeError:
                pass

    # Fallback 2: action key format
    if not tool_match:
        action_match = re.search(r'^\s*\{.*?"action"\s*:\s*"([^"]+)"', text, re.DOTALL)
        if action_match:
            tool_name = TOOL_ALIASES.get(action_match.group(1).strip(), action_match.group(1).strip())
            try:
                obj = json.loads(text.strip())
                obj.pop("action", None)
                return tool_name, obj
            except json.JSONDecodeError:
                pass

    # Fallback 3: name/arguments format
    if not tool_match:
        name_match = re.search(r'"name"\s*:\s*"([^"]+)".*?"arguments"\s*:\s*(\{.*\})', text, re.DOTALL)
        if name_match:
            tool_name = TOOL_ALIASES.get(name_match.group(1).strip(), name_match.group(1).strip())
            try:
                return tool_name, json.loads(name_match.group(2))
            except json.JSONDecodeError:
                pass

    # Fallback 4: function_call syntax
    if not tool_match:
        func_match = re.match(r"^(\w+)\s*\((.*)\)\s*$", text.strip(), re.DOTALL)
        if func_match:
            tool_name = TOOL_ALIASES.get(func_match.group(1).strip(), func_match.group(1).strip())
            try:
                return tool_name, _parse_function_call_args(tool_name, func_match.group(2))
            except Exception:
                pass

    if not tool_match:
        return None, {}

    tool_name = tool_match.group(1).strip().split("\n")[0].split("{")[0].strip()
    tool_name = TOOL_ALIASES.get(tool_name, tool_name)
    args      = {}

    if args_match:
        raw_args = args_match.group(1).strip()

        if raw_args.startswith("{"):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                try:
                    args = json.loads(_repair_json(raw_args))
                    logger.info(f"[Tools] JSON repaired for tool '{tool_name}'")
                except json.JSONDecodeError:
                    logger.warning(f"[Tools] JSON parse failed for tool '{tool_name}'. Raw: {raw_args[:200]}")
        else:
            xml_pairs = re.findall(r"<(\w+)>(.*?)</\1>", raw_args, re.DOTALL)
            if xml_pairs:
                args = {k: v.strip() for k, v in xml_pairs}
            else:
                kv_pairs = re.findall(r"(\w+)\s*=\s*(.+?)(?:\s+\w+=|$)", raw_args)
                if kv_pairs:
                    args = {k: v.strip() for k, v in kv_pairs}

    return tool_name, args


def execute_tool(tool_name: str, args: dict, sandbox=None) -> str:
    """Look up and call a tool by name."""
    if tool_name not in TOOL_REGISTRY:
        categorized = {
            "files":   ["read_file", "write_file", "patch_file", "list_files", "delete_file"],
            "docker":  ["docker_up", "docker_down", "docker_logs", "docker_ps", "docker_exec"],
            "network": ["http_request", "wait_for_service"],
            "build":   ["run_bash", "npm_install", "pip_install"],
            "search":  ["web_search"],
        }
        hint = "\n".join(f"  {k}: {', '.join(v)}" for k, v in categorized.items())
        return f"ERROR: Unknown tool '{tool_name}'.\nAvailable tools:\n{hint}"

    fn = TOOL_REGISTRY[tool_name]

    if sandbox is not None and "sandbox" not in args:
        if "sandbox" in inspect.signature(fn).parameters:
            args = {**args, "sandbox": sandbox}

    valid_params  = set(inspect.signature(fn).parameters.keys())
    filtered_args = {k: v for k, v in args.items() if k in valid_params}
    dropped       = set(args.keys()) - set(filtered_args.keys())
    if dropped:
        logger.warning(f"[Tools] Dropped unknown args for '{tool_name}': {dropped}")

    try:
        return str(fn(**filtered_args))
    except TypeError as e:
        return f"ERROR: Wrong arguments for '{tool_name}': {e}"
    except Exception as e:
        logger.exception(f"[Tools] Tool '{tool_name}' raised an exception")
        return f"ERROR in {tool_name}: {type(e).__name__}: {e}"


def truncate_output(tool_name: str, output: str) -> str:
    """Error-aware output truncation."""
    ERROR_LIMIT = 4000

    limits = {
        "read_file":     1500,
        "docker_logs":   1000,
        "docker_up":     3000,
        "docker_down":    400,
        "docker_build":  3000,
        "run_bash":       800,
        "npm_install":    600,
        "pip_install":    400,
        "http_request":   600,
        "web_search":     500,
        "docker_ps":      300,
        "docker_inspect": 400,
        "search_code":    600,
        "mongo_query":    400,
    }

    is_error = output.lstrip().upper().startswith("ERROR")
    if is_error:
        if len(output) > ERROR_LIMIT:
            return output[:ERROR_LIMIT] + f"\n...[truncated — showing first {ERROR_LIMIT} of {len(output)} chars]"
        return output

    limit = limits.get(tool_name, 600)
    if len(output) > limit:
        half = limit // 2
        return (
            output[:half]
            + f"\n...[truncated {len(output) - limit} chars]...\n"
            + output[-half:]
        )
    return output
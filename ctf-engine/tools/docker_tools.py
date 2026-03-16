"""
tools/docker_tools.py — Docker Tools.

Uses the `docker` Python SDK (docker-py) for container management.
Falls back to subprocess for compose operations (docker-py doesn't support compose v2).

All paths are resolved relative to the lab workspace (same as filesystem.py).
"""

import logging
import subprocess
from pathlib import Path

import docker as docker_sdk
import docker.errors

logger = logging.getLogger(__name__)
_client: docker_sdk.DockerClient | None = None

# Workspace — mirrors filesystem.py; set via set_workspace() in agent init
_WORKSPACE: Path = Path("/tmp/ctf_workspace")


def set_workspace(path: str):
    """Called by the agent to set the active lab workspace directory."""
    global _WORKSPACE
    _WORKSPACE = Path(path)


def _resolve(path: str) -> Path:
    """Resolve a relative path against the lab workspace."""
    p = Path(path)
    if not p.is_absolute():
        p = _WORKSPACE / p
    return p.resolve()


def _get_client() -> docker_sdk.DockerClient:
    global _client
    if _client is None:
        _client = docker_sdk.from_env()
    return _client


def _run_compose(cmd: list[str], cwd: str) -> str:
    # Try v2 first, fall back to v1
    for binary in [["docker", "compose"], ["docker-compose"]]:
        try:
            result = subprocess.run(
                binary + cmd,
                cwd=str(resolved_cwd),
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0 and "unknown command" in result.stderr:
                continue  # try next binary
            output = (result.stdout + result.stderr).strip()
            if result.returncode != 0:
                return f"ERROR: docker compose failed:\n{output}"
            return output or "(no output)"
        except FileNotFoundError:
            continue
    return "ERROR: Neither 'docker compose' nor 'docker-compose' found in PATH"


def docker_build(context_path: str = ".") -> str:
    """Build a Docker image from the lab workspace directory (context_path is relative to workspace)."""
    try:
        client = _get_client()
        abs_path = str(_resolve(context_path))
        logger.info(f"[docker_build] Building from: {abs_path}")
        image, logs = client.images.build(
            path=abs_path,
            dockerfile="Dockerfile",  # Explicitly name it to avoid case issues
            rm=True,
            forcerm=True,
        )
        # Consume the generator fully to collect all log lines
        log_list = list(logs)
        last_lines = [l.get("stream", "") for l in log_list if l.get("stream")][-5:]
        return f"OK: Image built: {image.id[:12]}\nLast log:\n{''.join(last_lines)}"
    except docker.errors.BuildError as e:
        # Fix C: Include the actual build output so the LLM can diagnose
        error_detail = str(e)
        if hasattr(e, 'build_log') and e.build_log:
            log_lines = [l.get('stream', '') for l in e.build_log if l.get('stream')]
            tail = ''.join(log_lines[-15:])
            error_detail += f"\n--- Build Log (last 15 lines) ---\n{tail}"
        return f"ERROR: docker build failed: {error_detail}"
    except Exception as e:
        return f"ERROR: docker build failed: {e}"



def docker_up(compose_file: str = ".") -> str:
    """Run docker compose up -d --build in the workspace directory (path is relative to workspace)."""
    # Fix A: Always tear down stale containers first to prevent
    # merge_volume_bindings crashes in docker-compose v1.
    # This is idempotent — safe even on first run.
    teardown = _run_compose(["down", "--remove-orphans"], cwd=compose_file)
    logger.info(f"[docker_up] Pre-teardown: {teardown[:120]}")
    return _run_compose(["up", "-d", "--build"], cwd=compose_file)


def docker_down(compose_file: str = ".") -> str:
    """Stop and remove containers defined in docker-compose.yml."""
    return _run_compose(["down", "--remove-orphans"], cwd=compose_file)



def docker_ps(filter_name: str = "") -> str:
    """List running Docker containers (optionally filtered by name)."""
    try:
        client = _get_client()
        filters = {"name": filter_name} if filter_name else {}
        containers = client.containers.list(filters=filters)
        if not containers:
            return "No running containers."
        rows = ["NAME                    STATUS      PORTS"]
        for c in containers:
            ports = ", ".join(
                f"{v[0]['HostPort']}->{k}" for k, v in (c.ports or {}).items() if v
            )
            rows.append(f"{c.name:<24} {c.status:<10} {ports}")
        return "\n".join(rows)
    except Exception as e:
        return f"ERROR: docker ps failed: {e}"


def docker_logs(container: str, tail: int = 50) -> str:
    """Fetch the last N lines of a container's logs."""
    try:
        client = _get_client()
        c = client.containers.get(container)
        logs = c.logs(tail=tail, timestamps=False).decode("utf-8", errors="replace")
        return logs.strip() if logs.strip() else "(no log output)"
    except docker_sdk.errors.NotFound:
        return f"ERROR: Container '{container}' not found"
    except Exception as e:
        return f"ERROR: docker logs failed: {e}"


def docker_exec(container: str, cmd: str) -> str:
    """Run a shell command inside a running container."""
    try:
        client = _get_client()
        c = client.containers.get(container)
        exit_code, output = c.exec_run(
            cmd=["sh", "-c", cmd],
            stdout=True,
            stderr=True,
        )
        text = output.decode("utf-8", errors="replace").strip()
        return f"Exit {exit_code}:\n{text}" if text else f"Exit {exit_code}: (no output)"
    except docker_sdk.errors.NotFound:
        return f"ERROR: Container '{container}' not found"
    except Exception as e:
        return f"ERROR: docker exec failed: {e}"


def docker_inspect(container: str) -> str:
    """Get the IP address and exposed ports of a container."""
    try:
        client = _get_client()
        c = client.containers.get(container)
        networks = c.attrs.get("NetworkSettings", {}).get("Networks", {})
        ip = next(
            (v["IPAddress"] for v in networks.values() if v.get("IPAddress")), "N/A"
        )
        ports = c.ports
        return f"Container: {c.name}\nStatus: {c.status}\nIP: {ip}\nPorts: {ports}"
    except docker_sdk.errors.NotFound:
        return f"ERROR: Container '{container}' not found"
    except Exception as e:
        return f"ERROR: docker inspect failed: {e}"

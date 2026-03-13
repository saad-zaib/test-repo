"""
tools/docker_tools.py — Docker Tools.

Uses the `docker` Python SDK (docker-py) for container management.
Falls back to subprocess for compose operations (docker-py doesn't support compose v2).
"""

import logging
import subprocess
from pathlib import Path

import docker as docker_sdk

logger = logging.getLogger(__name__)
_client: docker_sdk.DockerClient | None = None


def _get_client() -> docker_sdk.DockerClient:
    global _client
    if _client is None:
        _client = docker_sdk.from_env()
    return _client


def _run_compose(cmd: list[str], cwd: str) -> str:
    """Run a docker compose command and return combined stdout+stderr."""
    try:
        result = subprocess.run(
            ["docker", "compose"] + cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (result.stdout + result.stderr).strip()
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: docker compose timed out after 120s"
    except FileNotFoundError:
        return "ERROR: docker or docker-compose not found in PATH"


def docker_build(context_path: str) -> str:
    """Build a Docker image from the given build context directory."""
    try:
        client = _get_client()
        image, logs = client.images.build(path=context_path, rm=True)
        last_lines = [l.get("stream", "") for l in logs if l.get("stream")][-5:]
        return f"OK: Image built: {image.id[:12]}\nLast log:\n{''.join(last_lines)}"
    except Exception as e:
        return f"ERROR: docker build failed: {e}"


def docker_up(compose_file: str = ".") -> str:
    """Run docker compose up -d --build in the given directory."""
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

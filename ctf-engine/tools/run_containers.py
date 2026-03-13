"""
tools/run_containers.py

Tool 3: run_containers

Spins up the built Docker images, waits for them to be healthy,
and returns the service URLs.
"""

import subprocess
import time
import httpx
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)

HEALTH_CHECK_TIMEOUT = 60   # seconds to wait for container to be ready
HEALTH_CHECK_INTERVAL = 2   # seconds between health check attempts


class RunContainersTool:

    def run(self, lab_dir: str) -> dict:
        """
        Start containers and verify they are healthy.

        Returns service URLs on success, crash logs on failure.
        """
        lab_path = Path(lab_dir).resolve()  # Always use absolute paths
        # Search for docker-compose.yml — check root first, then subdirectories
        compose_file = self._find_compose_file(lab_path)

        logger.info(f"[Tool3] Starting containers in {lab_dir}...")

        # Start containers in detached mode
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file.name, "up", "-d"],
            capture_output=True,
            text=True,
            cwd=str(lab_path),
            timeout=120,
        )

        if result.returncode != 0:
            return {
                "status": "failed",
                "failure_stage": "container_start",
                "error": result.stderr[-2000:],
                "fixable_by_llm": True,
                "fix_instruction": f"Containers failed to start: {result.stderr[-500:]}",
            }

        # Read expected ports from challenge metadata
        ports = self._read_ports(lab_path)

        # Wait for each service to be healthy
        service_urls = {}
        for service_name, port in ports.items():
            url = f"http://localhost:{port}"
            healthy = self._wait_for_health(url, service_name)

            if not healthy:
                # Get crash logs
                logs = self._get_container_logs(lab_path, service_name)
                diagnosis = self._diagnose_crash(logs)

                # Stop containers
                self._stop_containers(lab_path)

                return {
                    "status": "failed",
                    "failure_stage": "health_check",
                    "service": service_name,
                    "error": f"Service {service_name} failed health check",
                    "container_logs": logs[-3000:],
                    "fixable_by_llm": True,
                    "fix_instruction": diagnosis,
                }

            service_urls[service_name] = url
            logger.info(f"[Tool3] ✅ {service_name} healthy at {url}")

        return {
            "status": "running",
            "service_urls": service_urls,
            "lab_dir": lab_dir,
            "compose_file": str(compose_file),
        }

    def _wait_for_health(self, url: str, service_name: str) -> bool:
        """Poll URL until it responds or timeout"""
        logger.info(f"[Tool3] Waiting for {service_name} at {url}...")
        deadline = time.time() + HEALTH_CHECK_TIMEOUT

        while time.time() < deadline:
            try:
                resp = httpx.get(url, timeout=5)
                # Any HTTP response (even 404) means the server is up
                if resp.status_code < 600:
                    return True
            except Exception:
                pass
            time.sleep(HEALTH_CHECK_INTERVAL)

        return False

    def _get_container_logs(self, lab_path: Path, service_name: str) -> str:
        """Get recent logs from a container"""
        compose_file = self._find_compose_file(lab_path)
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file.name, "logs", "--tail=100", service_name],
            capture_output=True,
            text=True,
            cwd=str(lab_path),
        )
        return result.stdout + result.stderr

    def _diagnose_crash(self, logs: str) -> str:
        """Turn crash logs into actionable fix instruction"""
        logs_lower = logs.lower()

        if "modulenotfounderror" in logs_lower or "no module named" in logs_lower:
            import re
            match = re.search(r"No module named '([^']+)'", logs)
            mod = match.group(1) if match else "unknown"
            return (
                f"App crashed at runtime: missing Python module '{mod}'. "
                f"Add '{mod}' to requirements.txt. "
                f"Note: stdlib modules don't need to be listed."
            )

        if "operationalerror" in logs_lower and "no such table" in logs_lower:
            return (
                "App crashed: database table does not exist. "
                "The schema.sql file is not being executed on startup. "
                "Add schema initialization to app.py before first request, "
                "or add it to the Dockerfile as a setup step."
            )

        if "address already in use" in logs_lower:
            return (
                "Port conflict: the port is already in use on the host. "
                "Change the host port mapping in docker-compose.yml."
            )

        if "syntaxerror" in logs_lower:
            return (
                f"Python syntax error at runtime. "
                f"Error details from logs: {logs[-500:]}"
            )

        if "permissionerror" in logs_lower:
            return (
                "Permission error: the app cannot access a required file. "
                "Check file permissions in the Dockerfile."
            )

        return (
            f"App crashed at startup. Full logs:\n{logs[-1000:]}\n"
            f"Fix the startup error in the application code."
        )

    def _stop_containers(self, lab_path: Path):
        """Stop and remove containers for this lab"""
        compose_file = self._find_compose_file(lab_path)
        subprocess.run(
            ["docker", "compose", "-f", compose_file.name, "down", "--remove-orphans"],
            capture_output=True,
            cwd=str(lab_path),
        )


    def _find_compose_file(self, lab_path):
        """Search for docker-compose.yml in lab root and subdirectories."""
        from pathlib import Path
        compose_file = lab_path / "docker-compose.yml"
        if compose_file.exists():
            return compose_file
        compose_file = lab_path / "docker-compose.yaml"
        if compose_file.exists():
            return compose_file
        # Search subdirectories (LLM often puts it in "both/" or container dir)
        for candidate in lab_path.rglob("docker-compose.yml"):
            # Copy to lab root for Docker context
            import shutil
            dest = lab_path / "docker-compose.yml"
            shutil.copy2(str(candidate), str(dest))
            return dest
        for candidate in lab_path.rglob("docker-compose.yaml"):
            import shutil
            dest = lab_path / "docker-compose.yaml"
            shutil.copy2(str(candidate), str(dest))
            return dest
        # Return the default path (doesn't exist, caller handles error)
        return lab_path / "docker-compose.yml"

    def _read_ports(self, lab_path: Path) -> dict:
        """Read expected service ports from challenge metadata"""
        meta_file = lab_path / "meta" / "challenge.json"
        if meta_file.exists():
            data = json.loads(meta_file.read_text())
            return data.get("ports", {"app": 5000})

        # Fallback: try to parse docker-compose.yml for ports
        return {"app": 5000}

    def stop(self, lab_dir: str):
        """Stop all containers for a lab (cleanup)"""
        lab_path = Path(lab_dir).resolve()  # Always use absolute paths
        self._stop_containers(lab_path)
        logger.info(f"[Tool3] Stopped containers for {lab_dir}")

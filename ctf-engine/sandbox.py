"""
sandbox.py — Docker sandbox for CTF lab generation.

Manages an isolated Docker container where the LLM-driven agent
executes bash commands, writes files, and builds/deploys Docker labs.

Improvements over original:
- Pre-built image support (skips apt-get install if image exists)
- Dynamic skills path detection (no hardcoded paths)
- Proper orphan container cleanup
- Better error handling and logging
"""

import subprocess
import logging
import uuid
import os
import socket
import shutil
from pathlib import Path

from config import WORKSPACE_DIR, LAB_PORT_RANGE_START, LAB_PORT_RANGE_END

logger = logging.getLogger(__name__)

# Pre-built sandbox image name. Build once, reuse across runs.
SANDBOX_IMAGE = "ctf-sandbox:latest"

# Skills directory auto-detection
SKILLS_DIR = Path(__file__).parent / "skills"

# Track allocated ports across instances
_allocated_ports: set[int] = set()


class DockerSandbox:
    """
    Manages an isolated Docker container for CTF lab building.
    Provides Docker-in-Docker (DinD) via socket mounting.
    Each sandbox gets a unique port to avoid conflicts.
    """

    def __init__(self, workspace_root: str = None):
        if not workspace_root:
            workspace_root = WORKSPACE_DIR

        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.container_name = f"ctf_sandbox_{uuid.uuid4().hex[:8]}"
        self.host_workspace_dir = None
        self.is_running = False
        self.assigned_port = self._allocate_port()  # Dynamic port

    @staticmethod
    def _allocate_port() -> int:
        """
        Find the first available port in the configured range.
        Checks both the OS (socket bind test) and our internal tracker.
        """
        for port in range(LAB_PORT_RANGE_START, LAB_PORT_RANGE_END + 1):
            if port in _allocated_ports:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('0.0.0.0', port))
                    _allocated_ports.add(port)
                    logger.info(f"Allocated port {port} for new lab")
                    return port
            except OSError:
                continue

        raise RuntimeError(
            f"No available ports in range {LAB_PORT_RANGE_START}-{LAB_PORT_RANGE_END}. "
            f"Stop some running labs or increase LAB_PORT_RANGE_END."
        )

    def start(self, lab_id: str):
        """Spin up the sandbox container."""
        self.host_workspace_dir = self.workspace_root / lab_id

        # Clean up if exists from previous run
        if self.host_workspace_dir.exists():
            shutil.rmtree(self.host_workspace_dir, ignore_errors=True)
        self.host_workspace_dir.mkdir(parents=True, exist_ok=True)

        # Kill any existing sandbox with the same name
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True, text=True,
        )

        logger.info(f"🚀 Starting Sandbox: {self.container_name}")

        # Check if pre-built image exists
        image = self._get_sandbox_image()

        # Build run command
        run_cmd = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "--network", "host",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{self.host_workspace_dir.absolute()}:/workspace",
        ]

        # Mount skills if dir exists
        if SKILLS_DIR.exists():
            run_cmd.extend(["-v", f"{SKILLS_DIR.absolute()}:/skills:ro"])

        run_cmd.extend(["-w", "/workspace", image, "sleep", "infinity"])

        res = subprocess.run(run_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to start sandbox: {res.stderr}")

        self.is_running = True

        # Install tools if using base ubuntu image (skip if pre-built)
        if image == "ubuntu:22.04":
            self._install_tools()

        logger.info("✅ Sandbox Ready!")

    def _get_sandbox_image(self) -> str:
        """Use pre-built image if available, otherwise fall back to ubuntu:22.04."""
        res = subprocess.run(
            ["docker", "images", "-q", SANDBOX_IMAGE],
            capture_output=True, text=True,
        )
        if res.stdout.strip():
            logger.info(f"Using pre-built sandbox image: {SANDBOX_IMAGE}")
            return SANDBOX_IMAGE
        logger.info("Pre-built image not found, using ubuntu:22.04 (slower startup)")
        return "ubuntu:22.04"

    def _install_tools(self):
        """Install tools in a fresh ubuntu container. Slow but works without pre-build."""
        logger.info("📦 Installing tools inside sandbox (this takes ~30s)...")
        setup_cmd = (
            "apt-get update -qq && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "curl wget netcat-traditional python3 python3-pip docker.io "
            "nodejs npm 2>&1 | tail -5 && "
            "curl -sL https://github.com/docker/compose/releases/download/v2.24.6/"
            "docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose && "
            "chmod +x /usr/local/bin/docker-compose && "
            "mkdir -p /usr/local/lib/docker/cli-plugins && "
            "cp /usr/local/bin/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose"
        )
        result = self.execute_bash(setup_cmd, timeout=180)
        if result.startswith("Error:"):
            logger.warning(f"Setup may have failed: {result[:200]}")

    def execute_bash(self, command: str, timeout: int = 120) -> str:
        """Run a bash command inside the sandbox container."""
        if not self.is_running:
            return "Error: Sandbox is not running."

        exec_cmd = [
            "docker", "exec", self.container_name,
            "bash", "-c", command,
        ]

        try:
            res = subprocess.run(
                exec_cmd, capture_output=True, text=True, timeout=timeout,
            )

            output = ""
            if res.stdout:
                output += res.stdout
            if res.stderr:
                if output:
                    output += "\n--- STDERR ---\n"
                output += res.stderr

            if not output.strip():
                output = "Command executed successfully with no output."

            # Truncate extremely long outputs
            if len(output) > 15000:
                output = output[:5000] + "\n...[TRUNCATED]...\n" + output[-5000:]

            return output

        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {timeout} seconds."
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def cleanup(self):
        """Kill and remove the sandbox container. Release the port."""
        if self.is_running or self.container_name:
            logger.info(f"🧹 Destroying Sandbox: {self.container_name}")
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True,
            )
            self.is_running = False
            _allocated_ports.discard(self.assigned_port)

"""
tools/security_scanner.py — Port scanning and container health tools

Gives the agent "eyes" to debug deployment issues instead of guessing.
"""

import logging
import re
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_sandbox_ref = None

def set_sandbox(sandbox):
    global _sandbox_ref
    _sandbox_ref = sandbox


@tool
def scan_ports(host: str = "localhost", port_range: str = "1-10000") -> str:
    """Scan for open ports on a host. Useful for finding which port the lab is running on.
    
    Args:
        host: Hostname or IP to scan (default: localhost)
        port_range: Port range to scan (default: 1-10000)
    
    Returns:
        List of open ports with service names.
    
    Example: scan_ports(host='localhost', port_range='1-10000')
    """
    if _sandbox_ref is None:
        return "Error: Sandbox not initialized."

    logger.info(f"[Tool] scan_ports: {host}:{port_range}")

    # Try nmap first, fall back to simple bash scan
    nmap_check = _sandbox_ref.execute_bash("which nmap 2>/dev/null || echo 'NO_NMAP'")
    
    if "NO_NMAP" not in nmap_check:
        output = _sandbox_ref.execute_bash(
            f"nmap -p {port_range} --open -T4 {host} 2>&1 | head -50"
        )
    else:
        # Fallback: quick bash port scan for common ports
        common_ports = "22,80,443,3000,3306,5000,5432,8000,8080,8443,9000,27017"
        scan_script = f"""
        for port in $(echo {common_ports} | tr ',' ' '); do
            (echo >/dev/tcp/{host}/$port) 2>/dev/null && echo "Port $port: OPEN"
        done
        """
        output = _sandbox_ref.execute_bash(scan_script)
        if not output.strip() or "Command executed successfully" in output:
            output = "No open ports found in common range. Try running the containers first."

    logger.info(f"[Tool] Port scan results: {output[:200]}")
    return f"Port scan results for {host}:\n{output}"


@tool
def check_service_health(container_name: str = "") -> str:
    """Check Docker container health: running status, logs, and port bindings.
    If no container_name is given, shows all running containers.
    
    Args:
        container_name: Docker container name (leave empty to list all)
    
    Returns:
        Container status, recent logs, and port mappings.
    """
    if _sandbox_ref is None:
        return "Error: Sandbox not initialized."

    logger.info(f"[Tool] check_service_health: {container_name or 'all'}")

    if not container_name:
        # List all containers
        output = _sandbox_ref.execute_bash("docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'")
        return f"All containers:\n{output}"

    # Get specific container info
    parts = []
    
    # Status
    status = _sandbox_ref.execute_bash(f"docker inspect --format '{{{{.State.Status}}}}' {container_name} 2>&1")
    parts.append(f"Status: {status.strip()}")
    
    # Ports
    ports = _sandbox_ref.execute_bash(f"docker port {container_name} 2>&1")
    parts.append(f"Ports: {ports.strip()}")
    
    # Recent logs
    logs = _sandbox_ref.execute_bash(f"docker logs --tail 20 {container_name} 2>&1")
    parts.append(f"Recent logs:\n{logs}")

    return "\n".join(parts)

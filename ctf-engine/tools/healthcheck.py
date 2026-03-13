"""
tools/healthcheck.py — Service health checking tool

Polls a URL until it returns HTTP 200 or times out.
Eliminates the "Connection Refused" failures in Phase 5.
"""

import time
import logging
import subprocess
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# Reference to sandbox, set before graph invocation
_sandbox_ref = None

def set_sandbox(sandbox):
    global _sandbox_ref
    _sandbox_ref = sandbox


@tool
def wait_for_service(url: str, timeout: int = 30) -> str:
    """Poll a URL until it returns a successful HTTP response, or fail after timeout seconds.
    Use this after running 'docker compose up -d' to wait for the service to be ready before exploiting.
    Example: wait_for_service('http://localhost:3000/login', timeout=30)
    """
    if _sandbox_ref is None:
        return "Error: Sandbox not initialized."

    logger.info(f"[Tool] wait_for_service: {url} (timeout={timeout}s)")

    # Run a polling loop inside the sandbox
    poll_script = f"""
    end=$((SECONDS + {timeout}))
    while [ $SECONDS -lt $end ]; do
        status=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 2 {url} 2>/dev/null)
        if [ "$status" -ge "200" ] && [ "$status" -lt "500" ]; then
            echo "SERVICE_READY: $status"
            exit 0
        fi
        sleep 1
    done
    echo "SERVICE_TIMEOUT: Could not reach {url} after {timeout} seconds"
    exit 1
    """
    output = _sandbox_ref.execute_bash(poll_script)
    
    if "SERVICE_READY" in output:
        logger.info(f"[Tool] Service is ready: {url}")
        return f"Service is ready at {url}. You can now proceed with exploit validation."
    else:
        logger.warning(f"[Tool] Service timeout: {url}")
        return f"Service at {url} did not become ready within {timeout} seconds. Check container logs with: docker compose logs"

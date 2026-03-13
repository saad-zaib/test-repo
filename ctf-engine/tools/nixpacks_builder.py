"""
tools/nixpacks_builder.py — Auto-build containers using Nixpacks

Nixpacks auto-detects the language and builds a Docker image without
needing a Dockerfile. Supports Node.js, Python, Go, Rust, Java, etc.
"""

import logging
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_sandbox_ref = None

def set_sandbox(sandbox):
    global _sandbox_ref
    _sandbox_ref = sandbox


@tool
def build_with_nixpacks(app_dir: str = ".", name: str = "ctf-app", port: int = 3000) -> str:
    """Auto-detect language and build a Docker image using Nixpacks.
    No Dockerfile needed — Nixpacks auto-detects Node.js, Python, Go, Rust, Java, etc.
    
    Args:
        app_dir: Directory containing the app source code (default: current directory)
        name: Name for the built Docker image
        port: Port the app listens on
    
    Returns:
        Build output or error message.
    
    Example: build_with_nixpacks(app_dir='.', name='ctf-app', port=3000)
    """
    if _sandbox_ref is None:
        return "Error: Sandbox not initialized."

    logger.info(f"[Tool] build_with_nixpacks: dir={app_dir}, name={name}, port={port}")

    # Check if nixpacks is installed
    check = _sandbox_ref.execute_bash("which nixpacks 2>/dev/null || echo 'NOT_INSTALLED'")
    if "NOT_INSTALLED" in check:
        logger.info("[Tool] Installing Nixpacks...")
        install_result = _sandbox_ref.execute_bash(
            "curl -sSL https://nixpacks.com/install.sh | bash 2>&1"
        )
        if "error" in install_result.lower():
            return f"Failed to install Nixpacks: {install_result}"

    # Build with nixpacks
    build_cmd = f"cd {app_dir} && nixpacks build . --name {name} 2>&1"
    output = _sandbox_ref.execute_bash(build_cmd)
    
    if "error" in output.lower() and "successfully" not in output.lower():
        logger.warning(f"[Tool] Nixpacks build may have failed: {output[:200]}")
        return f"Nixpacks build encountered issues:\n{output}\n\nYou may need to fall back to writing a Dockerfile manually."
    
    logger.info(f"[Tool] Nixpacks build completed for {name}")
    return f"Nixpacks built image '{name}' successfully.\n{output[-500:]}\n\nYou can now run it with: docker run -d -p {port}:{port} --name {name} {name}"

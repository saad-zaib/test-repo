"""
skills/__init__.py — Skill loader for CTF lab generation.

Each skill is a Markdown file in the skills/ directory that provides
vulnerability-specific knowledge for the LLM: what code pattern to use,
what to avoid, how to structure the Docker setup, and what the exploit looks like.

Adapted from Strix's skill loading pattern.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SKILLS_DIR = Path(__file__).parent


def load_skill(vuln_type: str) -> str | None:
    """
    Load a skill blueprint for a given vulnerability type.

    Searches for:
      1. skills/{vuln_type}.md (exact match)
      2. skills/{vuln_type without suffix}.md (e.g., sqli_union → sqli)

    Returns the markdown content or None if no skill file found.
    """
    # Try exact match first
    skill_path = _SKILLS_DIR / f"{vuln_type}.md"
    if skill_path.exists():
        logger.info(f"Loaded skill blueprint: {skill_path.name}")
        return skill_path.read_text(encoding="utf-8")

    # Try base vuln type (e.g., sqli_union → sqli)
    base_type = vuln_type.rsplit("_", 1)[0]
    if base_type != vuln_type:
        skill_path = _SKILLS_DIR / f"{base_type}.md"
        if skill_path.exists():
            logger.info(f"Loaded base skill blueprint: {skill_path.name}")
            return skill_path.read_text(encoding="utf-8")

    logger.info(f"No skill blueprint for '{vuln_type}' — using LLM knowledge only")
    return None


def list_skills() -> list[str]:
    """List all available skill names (without .md extension)."""
    return sorted(
        p.stem for p in _SKILLS_DIR.glob("*.md")
        if not p.name.startswith("_")
    )

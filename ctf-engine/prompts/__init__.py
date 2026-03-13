"""
prompts/__init__.py — Prompt loading and rendering.

Uses Jinja2 to render the system prompt with dynamic skill injection.
"""

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from tools import get_tool_descriptions as _get_tool_descriptions


_PROMPTS_DIR = Path(__file__).parent
_SKILLS_DIR = Path(__file__).parent.parent / "skills"


def render_system_prompt(
    spec: dict,
    skill_content: str | None = None,
) -> str:
    """
    Render the Jinja2 system prompt with spec and skill injection.

    Args:
        spec: Lab specification dict with vuln_type, difficulty, flag, description.
        skill_content: Optional skill markdown to inject. If None, auto-loads from skills/.

    Returns:
        Fully rendered system prompt string.
    """
    # Auto-load skill if not provided
    if skill_content is None:
        from skills import load_skill
        skill_content = load_skill(spec.get("vuln_type", ""))

    env = Environment(
        loader=FileSystemLoader([str(_PROMPTS_DIR), str(_SKILLS_DIR)]),
        autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
    )

    template = env.get_template("system_prompt.jinja")

    return template.render(
        vuln_type=spec.get("vuln_type", "unknown"),
        difficulty=spec.get("difficulty", "medium"),
        flag=spec.get("flag", "CTF{flag_here}"),
        description=spec.get("description", ""),
        skill_content=skill_content or "",
        tool_descriptions=_get_tool_descriptions(),
    )

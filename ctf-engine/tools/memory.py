"""
tools/memory.py — Context & Memory Tools.

Provides web search (via Tavily — purpose-built for AI agents) and
session-scoped note storage so the LLM can persist important
information across the sliding context window.
"""

import logging
import os
from typing import Any

from config import TAVILY_API_KEY

logger = logging.getLogger(__name__)

# Session notes — persisted for the lifetime of one lab generation run
_session_notes: dict[str, Any] = {}
_spec: dict = {}


def set_spec(spec: dict):
    """Called by the agent at start to make the original spec available."""
    global _spec
    _spec = spec


def web_search(query: str, max_results: int = 3) -> str:
    """
    Search the web for Docker image tags, library versions, or exploit techniques.
    Uses Tavily Search API (fast, structured, built for agents).
    """
    try:
        from tavily import TavilyClient

        # Auto-scope Docker image queries to Docker Hub
        docker_keywords = ["docker", "image", "tag", "dockerfile", "FROM", "base image"]
        is_docker_query = any(kw.lower() in query.lower() for kw in docker_keywords)

        client = TavilyClient(TAVILY_API_KEY)

        search_kwargs = {
            "query": query,
            "max_results": max_results,
            "search_depth": "basic",  # "basic" is fast; "advanced" for deep research
        }

        # Scope to Docker Hub for image/tag queries
        if is_docker_query:
            search_kwargs["include_domains"] = ["hub.docker.com", "docs.docker.com"]
            search_kwargs["query"] = f"docker hub {query}"

        response = client.search(**search_kwargs)
        results = response.get("results", [])

        if not results:
            return f"No results for: {query}"

        formatted = []
        for r in results:
            title = r.get("title", "")
            content = r.get("content", "")[:250]
            url = r.get("url", "")
            formatted.append(f"• {title}\n  {content}\n  {url}")

        return f"Search: '{query}'\n\n" + "\n\n".join(formatted)

    except ImportError:
        return (
            "ERROR: tavily-python is not installed.\n"
            "Run: pip install tavily-python"
        )
    except Exception as e:
        return f"ERROR: Web search failed: {type(e).__name__}: {e}"


def save_note(key: str, value: str) -> str:
    """Save a key-value note that persists within this generation session."""
    _session_notes[key] = value
    return f"OK: Note saved — '{key}'"


def get_note(key: str) -> str:
    """Retrieve a previously saved note by key."""
    if key not in _session_notes:
        return f"NOTE NOT FOUND: '{key}'. Available keys: {list(_session_notes.keys())}"
    return _session_notes[key]


def list_notes() -> str:
    """List all notes saved in this session."""
    if not _session_notes:
        return "(no notes saved yet)"
    lines = [f"  {k}: {str(v)[:100]}" for k, v in _session_notes.items()]
    return "Session Notes:\n" + "\n".join(lines)


def get_spec() -> str:
    """Return the original lab specification (vuln_type, flag, description, etc.)."""
    if not _spec:
        return "ERROR: No spec loaded."
    import json
    return json.dumps(_spec, indent=2)

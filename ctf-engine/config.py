"""
config.py — All configuration in one place.

Supports multiple LLM backends via LiteLLM.
Default: Qwen via Ollama (local).
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# LLM PROVIDER — Works with any LiteLLM-supported model
# ─────────────────────────────────────────────
# Format: "provider/model-name" (e.g., "ollama/qwen2.5-coder:32b-instruct")
# For Ollama: "ollama/model-name" or "ollama_chat/model-name"
# For OpenAI: "openai/gpt-4o"
# For Anthropic: "anthropic/claude-sonnet-4-20250514"
LLM_MODEL = os.getenv(
    "LLM_MODEL",
    os.getenv("QWEN_MODEL_NAME", "ollama_chat/qwen2.5-coder:14b-instruct"),
)

# API endpoint — for Ollama this is the local server, for cloud providers leave empty
LLM_API_BASE = os.getenv(
    "LLM_API_BASE",
    os.getenv("QWEN_BASE_URL", "http://localhost:11434"),
)

# API key — only needed for cloud providers; Ollama doesn't need one
LLM_API_KEY = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", ""))

# Timeout per LLM call (seconds) — 1800 = 30 minutes
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", os.getenv("QWEN_TIMEOUT", "1800")))

# Generation parameters
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "8192"))

# ─────────────────────────────────────────────
# BACKWARD COMPAT — old QWEN_* env vars still work
# ─────────────────────────────────────────────
QWEN_BASE_URL = LLM_API_BASE
QWEN_MODEL_NAME = LLM_MODEL.split("/", 1)[-1] if "/" in LLM_MODEL else LLM_MODEL
QWEN_TIMEOUT = LLM_TIMEOUT

# ─────────────────────────────────────────────
# ENGINE SERVER
# ─────────────────────────────────────────────
ENGINE_HOST = os.getenv("ENGINE_HOST", "0.0.0.0")
ENGINE_PORT = int(os.getenv("ENGINE_PORT", "9001"))

# ─────────────────────────────────────────────
# WORKSPACE & DOCKER
# ─────────────────────────────────────────────
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "./workspace")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
DOCKER_NETWORK_PREFIX = "ctflab"
LAB_SESSION_HOURS = int(os.getenv("LAB_SESSION_HOURS", "2"))

# Port range for dynamic allocation (avoids conflicts when multiple labs run)
LAB_PORT_RANGE_START = int(os.getenv("LAB_PORT_RANGE_START", "3000"))
LAB_PORT_RANGE_END = int(os.getenv("LAB_PORT_RANGE_END", "3999"))

# ─────────────────────────────────────────────
# AGENT SETTINGS
# ─────────────────────────────────────────────
MAX_AGENT_ITERATIONS = int(os.getenv("MAX_AGENT_ITERATIONS", "150"))
MAX_STEPS_PER_PHASE = int(os.getenv("MAX_STEPS_PER_PHASE", "15"))

# ─────────────────────────────────────────────
# SEARCH (Tavily)
# ─────────────────────────────────────────────
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

# ─────────────────────────────────────────────
# STRIX VALIDATION (optional)
# ─────────────────────────────────────────────
STRIX_ENABLED = os.getenv("STRIX_ENABLED", "false").lower() == "true"
STRIX_LLM = os.getenv("STRIX_LLM", LLM_MODEL)
STRIX_MAX_ITERATIONS = int(os.getenv("STRIX_MAX_ITERATIONS", "50"))

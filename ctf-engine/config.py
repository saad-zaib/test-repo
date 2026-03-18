"""
config.py — All configuration in one place.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# LLM PROVIDER
# ─────────────────────────────────────────────
LLM_MODEL = os.getenv(
    "LLM_MODEL",
    os.getenv("QWEN_MODEL_NAME", "ollama_chat/qwen2.5-coder:14b-instruct"),
)

LLM_API_BASE = os.getenv(
    "LLM_API_BASE",
    os.getenv("QWEN_BASE_URL", "http://localhost:11434"),
)

LLM_API_KEY  = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", ""))
LLM_TIMEOUT  = int(os.getenv("LLM_TIMEOUT", os.getenv("QWEN_TIMEOUT", "1800")))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
LLM_MAX_TOKENS  = int(os.getenv("LLM_MAX_TOKENS", "8192"))

# ─────────────────────────────────────────────
# BACKWARD COMPAT
# ─────────────────────────────────────────────
QWEN_BASE_URL   = LLM_API_BASE
QWEN_MODEL_NAME = LLM_MODEL.split("/", 1)[-1] if "/" in LLM_MODEL else LLM_MODEL
QWEN_TIMEOUT    = LLM_TIMEOUT

# ─────────────────────────────────────────────
# ENGINE SERVER
# ─────────────────────────────────────────────
ENGINE_HOST = os.getenv("ENGINE_HOST", "0.0.0.0")
ENGINE_PORT = int(os.getenv("ENGINE_PORT", "9001"))

# ─────────────────────────────────────────────
# WORKSPACE & DOCKER
# ─────────────────────────────────────────────
WORKSPACE_DIR        = os.getenv("WORKSPACE_DIR", "./workspace")
MAX_RETRIES          = int(os.getenv("MAX_RETRIES", "5"))
DOCKER_NETWORK_PREFIX = "ctflab"
LAB_SESSION_HOURS    = int(os.getenv("LAB_SESSION_HOURS", "2"))

LAB_PORT_RANGE_START = int(os.getenv("LAB_PORT_RANGE_START", "3000"))
LAB_PORT_RANGE_END   = int(os.getenv("LAB_PORT_RANGE_END", "3999"))

# ─────────────────────────────────────────────
# AGENT SETTINGS
# Lowered from 150 — research+build+deploy only, no exploit phase
# ─────────────────────────────────────────────
MAX_AGENT_ITERATIONS = int(os.getenv("MAX_AGENT_ITERATIONS", "50"))
MAX_STEPS_PER_PHASE  = int(os.getenv("MAX_STEPS_PER_PHASE", "15"))

# ─────────────────────────────────────────────
# SEARCH (Tavily)
# ─────────────────────────────────────────────
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

# ─────────────────────────────────────────────
# STRIX VALIDATION (optional)
# ─────────────────────────────────────────────
STRIX_ENABLED        = os.getenv("STRIX_ENABLED", "false").lower() == "true"
STRIX_LLM            = os.getenv("STRIX_LLM", LLM_MODEL)
STRIX_MAX_ITERATIONS = int(os.getenv("STRIX_MAX_ITERATIONS", "50"))
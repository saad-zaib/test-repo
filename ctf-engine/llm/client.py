"""
llm/client.py

Universal LLM client powered by LiteLLM.
Supports Ollama, OpenAI, Anthropic, and any other LiteLLM-supported provider.

The startup probe auto-detects the provider and uses the appropriate health check.
Generation uses LiteLLM's unified completion API with retry logic.
"""

import json
import logging
import re
import time
from typing import Optional

import litellm
from litellm import completion, acompletion

from config import (
    LLM_MODEL,
    LLM_API_BASE,
    LLM_API_KEY,
    LLM_TIMEOUT,
    LLM_TEMPERATURE,
    LLM_MAX_TOKENS,
)

logger = logging.getLogger(__name__)

# LiteLLM settings
litellm.drop_params = True        # Drop unsupported params silently
litellm.modify_params = True      # Let LiteLLM adapt params per provider
litellm.set_verbose = False       # Quiet unless debugging


# ── Request Stats Tracking ────────────────────────────────────────────────────

class RequestStats:
    """Track cumulative LLM usage across all calls."""

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.total_requests = 0
        self.total_errors = 0

    def record(self, response):
        """Record usage from a LiteLLM response."""
        self.total_requests += 1
        try:
            usage = getattr(response, "usage", None)
            if usage:
                self.total_input_tokens += getattr(usage, "prompt_tokens", 0) or 0
                self.total_output_tokens += getattr(usage, "completion_tokens", 0) or 0
            try:
                from litellm import completion_cost
                self.total_cost += completion_cost(response) or 0.0
            except Exception:
                pass
        except Exception:
            pass

    def summary(self) -> dict:
        return {
            "requests": self.total_requests,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "cost_usd": round(self.total_cost, 4),
            "errors": self.total_errors,
        }


# Global stats tracker
_stats = RequestStats()


def get_stats() -> dict:
    """Return cumulative LLM usage stats."""
    return _stats.summary()


# ── Provider Detection ────────────────────────────────────────────────────────

def _is_ollama() -> bool:
    """Check if we're using an Ollama-based model."""
    return any(p in LLM_MODEL.lower() for p in ["ollama", "ollama_chat"])


def _is_cloud() -> bool:
    """Check if we're using a cloud provider (OpenAI, Anthropic, etc.)."""
    return any(p in LLM_MODEL.lower() for p in [
        "openai/", "anthropic/", "azure/", "gpt-", "claude",
    ])


# ── Startup Health Check ─────────────────────────────────────────────────────

def probe_llm() -> bool:
    """
    Fast connectivity check.
    For Ollama: uses /api/tags endpoint.
    For cloud: sends a minimal completion to verify API key.
    Returns True if the model is available.
    """
    if _is_ollama():
        return _probe_ollama()
    return _probe_cloud()


def _probe_ollama() -> bool:
    """Check Ollama server is up and model is loaded."""
    import httpx
    try:
        # Extract base URL (strip ollama_chat/ prefix from model)
        base = LLM_API_BASE.rstrip("/")
        resp = httpx.get(f"{base}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False

        model_name = LLM_MODEL.split("/", 1)[-1] if "/" in LLM_MODEL else LLM_MODEL
        models = [m["name"] for m in resp.json().get("models", [])]

        if not any(model_name in m for m in models):
            logger.warning(
                f"Ollama is up but model '{model_name}' not found. "
                f"Loaded models: {models}"
            )
            return False

        logger.info(f"✅ LLM ready: {LLM_MODEL} at {base}")
        return True
    except Exception as e:
        logger.warning(f"LLM probe failed: {e}")
        return False


def _probe_cloud() -> bool:
    """Check cloud provider connectivity with a tiny completion."""
    try:
        resp = completion(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
            api_key=LLM_API_KEY or None,
            api_base=LLM_API_BASE if LLM_API_BASE and not _is_cloud() else None,
            timeout=10,
        )
        logger.info(f"✅ LLM ready: {LLM_MODEL}")
        return True
    except Exception as e:
        logger.warning(f"LLM probe failed: {e}")
        return False


# ── Main LLM Call ─────────────────────────────────────────────────────────────

def call_llm(
    system_prompt: str,
    user_prompt: str,
    temperature: float = LLM_TEMPERATURE,
    max_tokens: int = LLM_MAX_TOKENS,
    json_mode: bool = False,
    conversation: Optional[list] = None,
) -> str:
    """
    Call the LLM via LiteLLM's unified API.

    Args:
        system_prompt: Sets the LLM identity/role.
        user_prompt:   The actual task/question.
        temperature:   0.0 = deterministic, 1.0 = creative.
        max_tokens:    Max response length.
        json_mode:     If True, instructs model to respond with raw JSON only.
        conversation:  Optional full conversation history (overrides system+user).

    Returns:
        The model's response text (think-blocks stripped).
    """
    if json_mode:
        system_prompt += (
            "\n\nCRITICAL: Respond ONLY with valid JSON. "
            "No markdown, no explanation, no code fences. Raw JSON only."
        )

    # Build messages
    if conversation:
        messages = conversation
    else:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    # Build completion args
    kwargs = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": LLM_TIMEOUT,
    }

    if LLM_API_KEY:
        kwargs["api_key"] = LLM_API_KEY
    if LLM_API_BASE and _is_ollama():
        kwargs["api_base"] = LLM_API_BASE

    # Retry with exponential backoff
    max_retries = 3
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            resp = completion(**kwargs)
            _stats.record(resp)

            text = resp.choices[0].message.content.strip()

            # Strip think blocks (Qwen3, DeepSeek, etc.)
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

            return text

        except Exception as e:
            last_error = e
            _stats.total_errors += 1

            if attempt < max_retries:
                wait = min(10, 2 ** (attempt + 1))
                logger.warning(
                    f"LLM call failed (attempt {attempt + 1}/{max_retries + 1}): "
                    f"{type(e).__name__}: {e}. Retrying in {wait}s..."
                )
                time.sleep(wait)
            else:
                logger.error(f"LLM call failed after {max_retries + 1} attempts: {e}")

    raise RuntimeError(
        f"LLM request failed after {max_retries + 1} attempts: "
        f"{type(last_error).__name__}: {last_error}"
    )


# ── Async LLM Call ────────────────────────────────────────────────────────────

async def call_llm_async(
    system_prompt: str,
    user_prompt: str,
    temperature: float = LLM_TEMPERATURE,
    max_tokens: int = LLM_MAX_TOKENS,
    json_mode: bool = False,
) -> str:
    """Async version of call_llm for use in async agent loops."""
    import asyncio

    if json_mode:
        system_prompt += (
            "\n\nCRITICAL: Respond ONLY with valid JSON. "
            "No markdown, no explanation, no code fences. Raw JSON only."
        )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    kwargs = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": LLM_TIMEOUT,
    }

    if LLM_API_KEY:
        kwargs["api_key"] = LLM_API_KEY
    if LLM_API_BASE and _is_ollama():
        kwargs["api_base"] = LLM_API_BASE

    max_retries = 3
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            resp = await acompletion(**kwargs)
            _stats.record(resp)

            text = resp.choices[0].message.content.strip()
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
            return text

        except Exception as e:
            last_error = e
            _stats.total_errors += 1
            if attempt < max_retries:
                wait = min(10, 2 ** (attempt + 1))
                logger.warning(f"Async LLM call failed (attempt {attempt + 1}): {e}")
                await asyncio.sleep(wait)

    raise RuntimeError(f"Async LLM failed after {max_retries + 1} attempts: {last_error}")


# ── JSON Helper ───────────────────────────────────────────────────────────────

def call_llm_for_json(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.1,
) -> dict:
    """
    Call LLM and parse the response as JSON.
    Retries once with a correction prompt if parsing fails.
    """
    raw = call_llm(
        system_prompt, user_prompt,
        json_mode=True, temperature=temperature,
    )

    def _clean_and_parse(text: str) -> dict:
        text = text.strip()
        # Strip markdown fences if the model still added them
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(
                lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            )
        # Try to extract JSON from surrounding text
        if not text.startswith("{") and not text.startswith("["):
            # Find first { or [
            for i, c in enumerate(text):
                if c in "{[":
                    text = text[i:]
                    break
        return json.loads(text, strict=False)

    try:
        return _clean_and_parse(raw)
    except json.JSONDecodeError:
        logger.warning("JSON parse failed — retrying with correction prompt")
        correction = (
            f"Your previous response could not be parsed as JSON:\n\n{raw[:500]}\n\n"
            "Return ONLY valid JSON. No other text."
        )
        raw2 = call_llm(
            system_prompt, correction,
            json_mode=True, temperature=0.0,
        )
        return _clean_and_parse(raw2)

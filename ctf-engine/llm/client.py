"""
llm/client.py

Universal LLM client.
- Ollama: Direct HTTP to /api/chat (bypasses LiteLLM's broken timeout handling)
- Cloud (OpenAI, Anthropic, etc.): Uses LiteLLM as before

The startup probe auto-detects the provider and uses the appropriate health check.
"""

import json
import logging
import re
import sys
import time
from typing import Optional

import httpx

from config import (
    LLM_MODEL,
    LLM_API_BASE,
    LLM_API_KEY,
    LLM_TIMEOUT,
    LLM_TEMPERATURE,
    LLM_MAX_TOKENS,
)

logger = logging.getLogger(__name__)


# ── Request Stats Tracking ────────────────────────────────────────────────────

class RequestStats:
    """Track cumulative LLM usage across all calls."""

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_requests = 0
        self.total_errors = 0

    def record(self, input_tokens: int = 0, output_tokens: int = 0):
        self.total_requests += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

    def summary(self) -> dict:
        return {
            "requests": self.total_requests,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "errors": self.total_errors,
        }


_stats = RequestStats()


def get_stats() -> dict:
    return _stats.summary()


# ── Provider Detection ────────────────────────────────────────────────────────

def _is_ollama() -> bool:
    return any(p in LLM_MODEL.lower() for p in ["ollama", "ollama_chat"])


def _ollama_model_name() -> str:
    """Strip ollama/ or ollama_chat/ prefix to get raw model name."""
    if "/" in LLM_MODEL:
        return LLM_MODEL.split("/", 1)[-1]
    return LLM_MODEL


# ── Startup Health Check ─────────────────────────────────────────────────────

def probe_llm() -> bool:
    if _is_ollama():
        return _probe_ollama()
    return _probe_cloud()


def _probe_ollama() -> bool:
    """Check Ollama server is up and model is available."""
    try:
        base = LLM_API_BASE.rstrip("/")
        resp = httpx.get(f"{base}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False

        model_name = _ollama_model_name()
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
    """Check cloud provider with a tiny completion."""
    try:
        from litellm import completion
        resp = completion(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
            api_key=LLM_API_KEY or None,
            timeout=10,
        )
        logger.info(f"✅ LLM ready: {LLM_MODEL}")
        return True
    except Exception as e:
        logger.warning(f"LLM probe failed: {e}")
        return False


# ── Direct Ollama Call ────────────────────────────────────────────────────────

def _call_ollama(
    messages: list,
    temperature: float,
    max_tokens: int,
) -> str:
    """
    Call Ollama's /api/chat with streaming enabled.
    Waits infinitely for the model to think (no timeouts).
    Tokens are printed instantly to the console.
    """
    base = LLM_API_BASE.rstrip("/")
    url = f"{base}/api/chat"
    model_name = _ollama_model_name()

    payload = {
        "model": model_name,
        "messages": messages,
        "stream": True,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "think": False,
        },
    }

    logger.info(
        f"Ollama request: model={model_name}, msgs={len(messages)} "
        f"(Infinite Timeout — waiting for first token...)"
    )

    print(f"\n{'─'*70}", flush=True)
    print(f"🤖 QWEN STREAMING [{model_name}]:", flush=True)
    print(f"{'─'*70}", flush=True)

    full_text = []
    in_tokens = 0
    out_tokens = 0

    # No timeout on the connection to allow for infinite "thinking" time
    timeout = httpx.Timeout(None)
    
    with httpx.Client(timeout=timeout) as client:
        # We MUST use iter_bytes() to avoid buffering issues waiting for newlines
        with client.stream("POST", url, json=payload) as resp:
            resp.raise_for_status()
            
            buffer = ""
            for byte_chunk in resp.iter_bytes():
                if not byte_chunk:
                    continue
                    
                buffer += byte_chunk.decode("utf-8")
                
                # Try to parse complete JSON objects out of the buffer
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        # If a single line is cut off (rare for Ollama, but possible), put it back
                        buffer = line + "\n" + buffer
                        break

                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        sys.stdout.write(token)
                        sys.stdout.flush()
                        full_text.append(token)

                    if chunk.get("done"):
                        in_tokens  = chunk.get("prompt_eval_count", 0)
                        out_tokens = chunk.get("eval_count", 0)
                        eval_dur   = chunk.get("eval_duration", 0) / 1e9
                        total_dur  = chunk.get("total_duration", 0) / 1e9
                        tok_rate   = out_tokens / max(eval_dur, 0.001)
                        print(f"\n{'─'*70}", flush=True)
                        print(
                            f"✅ Done — in: {in_tokens} tok | out: {out_tokens} tok | "
                            f"{tok_rate:.1f} tok/s | total: {total_dur:.1f}s",
                            flush=True,
                        )
                        print(f"{'─'*70}\n", flush=True)

    _stats.record(input_tokens=in_tokens, output_tokens=out_tokens)
    text = "".join(full_text).strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    return text



# ── Cloud Call via LiteLLM ────────────────────────────────────────────────────

def _call_cloud(
    messages: list,
    temperature: float,
    max_tokens: int,
) -> str:
    """Call cloud providers via LiteLLM."""
    from litellm import completion

    kwargs = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": LLM_TIMEOUT,
    }

    if LLM_API_KEY:
        kwargs["api_key"] = LLM_API_KEY

    resp = completion(**kwargs)

    # Track usage
    usage = getattr(resp, "usage", None)
    if usage:
        _stats.record(
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )
    else:
        _stats.record()

    text = resp.choices[0].message.content.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    return text


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
    Call the LLM. Routes to Ollama (direct HTTP) or cloud (LiteLLM).

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

    # Pick the right backend
    backend_fn = _call_ollama if _is_ollama() else _call_cloud

    # Retry with exponential backoff
    max_retries = 3
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            return backend_fn(messages, temperature, max_tokens)

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
    """Async version of call_llm."""
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

    if _is_ollama():
        # Run synchronous Ollama call in a thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, _call_ollama, messages, temperature, max_tokens,
        )
    else:
        from litellm import acompletion

        kwargs = {
            "model": LLM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": LLM_TIMEOUT,
        }
        if LLM_API_KEY:
            kwargs["api_key"] = LLM_API_KEY

        max_retries = 3
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                resp = await acompletion(**kwargs)
                usage = getattr(resp, "usage", None)
                if usage:
                    _stats.record(
                        input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                        output_tokens=getattr(usage, "completion_tokens", 0) or 0,
                    )
                else:
                    _stats.record()
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

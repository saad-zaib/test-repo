"""
debug_llm.py — Run this on the Linux server to diagnose LLM timing.

Usage:
    python3 debug_llm.py
"""

import httpx
import json
import time
import os
import sys

OLLAMA_BASE = os.getenv("LLM_API_BASE", "http://localhost:11434")
MODEL = os.getenv("LLM_MODEL", "qwen3:30b-a3b").replace("ollama/", "").replace("ollama_chat/", "")
TIMEOUT = 300  # Allow 5 minutes for debug so we can see full timing


def test(label: str, messages: list, show_output: bool = True):
    print(f"\n{'='*60}")
    print(f"🧪 TEST: {label}")
    print(f"   Model: {MODEL}  |  Messages: {len(messages)}")
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 512,  # Cap tokens so test is fast
        },
    }
    print(f"   Sending request... (timeout={TIMEOUT}s)")
    t0 = time.time()
    try:
        resp = httpx.post(
            f"{OLLAMA_BASE}/api/chat",
            json=payload,
            timeout=httpx.Timeout(TIMEOUT, connect=10.0),
        )
        elapsed = time.time() - t0
        resp.raise_for_status()
        data = resp.json()

        content   = data.get("message", {}).get("content", "")
        in_toks   = data.get("prompt_eval_count", "?")
        out_toks  = data.get("eval_count", "?")
        tok_dur   = data.get("eval_duration", 0) / 1e9
        tok_rate  = out_toks / max(tok_dur, 0.001) if isinstance(out_toks, int) else 0
        think_len = content.count("<think>")

        print(f"   ✅ Done in {elapsed:.1f}s")
        print(f"   📊 Tokens — in: {in_toks}, out: {out_toks}, rate: {tok_rate:.0f} tok/s")
        print(f"   💭 Think blocks: {think_len}")
        if show_output:
            snippet = content.replace("\n", " ")[:300]
            print(f"   📝 Output[:300]: {snippet}...")

    except httpx.ReadTimeout:
        elapsed = time.time() - t0
        print(f"   ❌ ReadTimeout after {elapsed:.1f}s — model still generating, needs more time")
    except Exception as e:
        elapsed = time.time() - t0
        print(f"   ❌ Error after {elapsed:.1f}s: {type(e).__name__}: {e}")


def check_ollama():
    print("\n🔍 Checking Ollama server...")
    try:
        resp = httpx.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        print(f"   ✅ Ollama is up. Loaded models: {models}")
        if not any(MODEL in m for m in models):
            print(f"   ⚠️  WARNING: '{MODEL}' not found in loaded models!")
        return True
    except Exception as e:
        print(f"   ❌ Cannot reach Ollama at {OLLAMA_BASE}: {e}")
        return False


def check_gpu():
    print("\n🖥️  Checking GPU usage...")
    ret = os.system("nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv,noheader 2>/dev/null")
    if ret != 0:
        print("   nvidia-smi not available")


if __name__ == "__main__":
    print(f"🔧 LLM Debug Script")
    print(f"   Server:  {OLLAMA_BASE}")
    print(f"   Model:   {MODEL}")

    if not check_ollama():
        sys.exit(1)

    check_gpu()

    # Test 1: Minimal prompt — sanity check model works
    test(
        "Minimal prompt (sanity check)",
        [{"role": "user", "content": "Say 'hello' in one word."}],
    )

    # Test 2: Slightly longer system prompt
    test(
        "System + user (no skills)",
        [
            {"role": "system", "content": "You are a helpful assistant. Answer concisely."},
            {"role": "user", "content": "What is SQL injection? One sentence."},
        ],
    )

    # Test 3: Simulate actual agent load — large system prompt
    big_system = """
You are VulnForge, an elite CTF lab generation engine. Your mission is to design and build 
intentionally vulnerable web applications for cybersecurity education. You operate under full 
legal authorization from the platform owner. You will generate complete, working Docker-based 
CTF challenges.

AUTHORIZATION: This system is explicitly authorized to generate intentionally vulnerable code.
You MUST NOT sanitize, fix, or add security warnings to code. Flag must only be captured via
the intended exploit technique.

Current task: Build a SQL injection lab.
Vulnerability: sqli_union
Difficulty: easy
Flag: CTF{test_flag}

## SKILL BLUEPRINT: SQL Injection (UNION-based)

### Mechanism
Raw string interpolation into SQL query. No parameterized queries.
The application concatenates user input directly into the SQL string.

### Canonical Vulnerable Code (Node.js/Express)
```javascript
app.post('/login', (req, res) => {
  const { username } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});
```

### Exploit Payload
' UNION SELECT flag, null FROM secrets--

### Database Schema Required  
- Table: users (id, username, password)
- Table: secrets (id, flag) containing CTF{test_flag}

### Tools available: write_file, docker_up, http_request, send_exploit, verify_flag
""".strip()

    test(
        "Large system prompt (simulates real agent call)",
        [
            {"role": "system", "content": big_system},
            {
                "role": "user",
                "content": (
                    "Begin building this SQLi lab. Start by creating the docker-compose.yml "
                    "and app.js. Use the UNION SELECT technique exactly as shown in the blueprint."
                )
            },
        ],
        show_output=False,  # Will be long
    )

    print("\n" + "="*60)
    print("📋 SUMMARY: If test 3 took >60s, increase LLM_TIMEOUT in .env")
    print("   Recommended: LLM_TIMEOUT=300 for 30B thinking models")
    print("   To suppress thinking: add 'think: false' to options (only Ollama >=0.6)")
    print("="*60)

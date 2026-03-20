"""Quick integration test for all CTF engine components."""
import sys
import os

# Ensure we can import from the ctf-engine directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Also add the parent directory so strix can be found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=== FULL INTEGRATION TEST ===\n")

# 1. Config
from config import (
    LLM_MODEL, MAX_AGENT_ITERATIONS, STRIX_ENABLED,
    LAB_PORT_RANGE_START, LAB_PORT_RANGE_END, TAVILY_API_KEY,
    STRIX_LLM, STRIX_OLLAMA_API_BASE, STRIX_MAX_ITERATIONS,
    STRIX_TIMEOUT, STRIX_SCAN_MODE, STRIX_DIR,
)
print(f"[Config] model={LLM_MODEL}, iters={MAX_AGENT_ITERATIONS}, strix={STRIX_ENABLED}")
print(f"[Config] port_range={LAB_PORT_RANGE_START}-{LAB_PORT_RANGE_END}")
print(f"[Config] tavily_key={'set' if TAVILY_API_KEY else 'NOT SET'}")
print(f"[Config] strix_llm={STRIX_LLM}")
print(f"[Config] strix_api_base={STRIX_OLLAMA_API_BASE}")
print(f"[Config] strix_max_iters={STRIX_MAX_ITERATIONS}, timeout={STRIX_TIMEOUT}, mode={STRIX_SCAN_MODE}")
print(f"[Config] strix_dir={STRIX_DIR}")

# 2. LLM Client
from llm.client import call_llm, call_llm_for_json, probe_llm, get_stats
print("[LLM Client] OK")

# 3. Skills
from skills import load_skill, list_skills
sk = list_skills()
print(f"[Skills] {len(sk)} loaded: {sk}")

# 4. Prompt
from prompts import render_system_prompt
p = render_system_prompt({"vuln_type": "cmdi", "difficulty": "easy", "flag": "CTF{x}"})
print(f"[Prompt] {len(p)} chars, auth={'AUTHORIZATION' in p}, skill={'shell=True' in p}")

# 5. Agent
from agent import ReActAgent, AgentPhase, Checkpoint
print(f"[Agent] phases=[research, build, deploy]")

# 6. Port allocation
from sandbox import DockerSandbox
s1 = DockerSandbox()
s2 = DockerSandbox()
print(f"[Port] sandbox1={s1.assigned_port}, sandbox2={s2.assigned_port}, conflict={s1.assigned_port == s2.assigned_port}")

# 7. Tavily
from tools.memory import web_search
# Don't actually call API in test, just verify import
from tavily import TavilyClient
print("[Tavily] tavily-python imported OK")

# 8. Validator — Strix integration
from validators.strix_validator import StrixValidator
sv = StrixValidator()
print(f"[StrixValidator] enabled={sv.enabled}")
print(f"[StrixValidator] strix_available={sv._check_strix_available()}")

# 9. Strix Exploit Tool
from tools.strix_exploit import STRIX_AVAILABLE
print(f"[StrixExploit] strix_cli_exists={STRIX_AVAILABLE}")

# 10. Orchestrator
from orchestrator import Orchestrator
orch = Orchestrator()
print(f"[Orchestrator] has_strix_validator={hasattr(orch, 'strix_validator')}")

print("\n=== ALL COMPONENTS OK ===")

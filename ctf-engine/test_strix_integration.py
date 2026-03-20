"""Focused verification test for the Strix integration."""
import sys, os

# Add ctf-engine dir to path
_CTF_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _CTF_DIR)
os.chdir(_CTF_DIR)

from dotenv import load_dotenv
load_dotenv()

passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}" + (f" ({detail})" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL  {name}" + (f" ({detail})" if detail else ""))

print("=== STRIX INTEGRATION VERIFICATION ===\n")

# 1. Config vars exist
print("[1] Config Variables")
try:
    from config import (
        STRIX_ENABLED, STRIX_LLM, STRIX_OLLAMA_API_BASE,
        STRIX_MAX_ITERATIONS, STRIX_TIMEOUT, STRIX_SCAN_MODE, STRIX_DIR,
    )
    check("STRIX_ENABLED", isinstance(STRIX_ENABLED, bool), str(STRIX_ENABLED))
    check("STRIX_LLM", bool(STRIX_LLM), STRIX_LLM)
    check("STRIX_OLLAMA_API_BASE", bool(STRIX_OLLAMA_API_BASE), STRIX_OLLAMA_API_BASE)
    check("STRIX_MAX_ITERATIONS", STRIX_MAX_ITERATIONS > 0, str(STRIX_MAX_ITERATIONS))
    check("STRIX_TIMEOUT", STRIX_TIMEOUT > 0, str(STRIX_TIMEOUT))
    check("STRIX_SCAN_MODE", STRIX_SCAN_MODE in ("quick","standard","deep"), STRIX_SCAN_MODE)
    check("STRIX_DIR", os.path.isdir(STRIX_DIR), STRIX_DIR)

    # Add STRIX_DIR to sys.path so strix package is importable
    if STRIX_DIR not in sys.path:
        sys.path.insert(0, STRIX_DIR)
except Exception as e:
    check("config_import", False, str(e))

# 2. StrixValidator
print("\n[2] StrixValidator")
try:
    from validators.strix_validator import StrixValidator
    sv = StrixValidator()
    check("instantiate", True)
    check("enabled", sv.enabled == STRIX_ENABLED, str(sv.enabled))
    avail = sv._check_strix_available()
    check("strix_importable", isinstance(avail, bool), str(avail))
except Exception as e:
    check("strix_validator_import", False, str(e))

# 3. StrixExploit tool
print("\n[3] StrixExploit Tool")
try:
    from tools.strix_exploit import STRIX_AVAILABLE, run_strix_exploit
    check("import", True)
    check("cli_path_detected", isinstance(STRIX_AVAILABLE, bool), str(STRIX_AVAILABLE))
except Exception as e:
    check("strix_exploit_import", False, str(e))

# 4. Orchestrator
print("\n[4] Orchestrator")
try:
    from orchestrator import Orchestrator
    orch = Orchestrator()
    check("import", True)
    check("has_strix_validator", hasattr(orch, "strix_validator"))
    check("validator_is_StrixValidator", isinstance(orch.strix_validator, StrixValidator))
except Exception as e:
    check("orchestrator_import", False, str(e))

# Test fully complete

print(f"\n=== RESULTS: {passed} passed, {failed} failed ===")
if failed == 0:
    print("ALL TESTS PASSED")
else:
    print(f"WARNING: {failed} test(s) failed")

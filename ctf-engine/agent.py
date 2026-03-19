"""
agent.py — CTF Lab Generation Agent (Multi-Phase Architecture)

Phases:
  Phase 1: RESEARCH — web_search + architecture planning
  Phase 2: BUILD    — write all files using skill blueprints
  Phase 3: DEPLOY   — docker compose up, health checks, log validation, then DONE

DONE flow (no exploitation):
  1. docker_build  — build image, catch errors early
  2. docker_up     — start containers
  3. wait_for_service — wait for port to respond
  4. docker_logs   — check for errors; fix broken file if needed
  5. http_request  — confirm endpoint responds
  6. DONE (background checks: flag in workspace file, logs + http confirmed)
"""

import inspect
import json
import logging
import re
from pathlib import Path
from typing import Optional
from tools import (
    execute_tool, truncate_output, get_tool_descriptions,
    TOOL_REGISTRY, parse_all_tool_calls,
)
from config import LLM_MAX_TOKENS, MAX_AGENT_ITERATIONS
from llm.client import call_llm
from prompts import render_system_prompt
from skills import load_skill
from sandbox import DockerSandbox
from tools import (
    execute_tool, truncate_output, get_tool_descriptions,
    TOOL_REGISTRY,
)
from tools.filesystem import set_workspace as fs_set_workspace
from tools.docker_tools import set_workspace as docker_set_workspace
from tools.memory import set_spec as memory_set_spec
from tools.reporting import set_workspace as reporting_set_workspace

logger = logging.getLogger(__name__)

# ── Configuration ───────────────────────────────────────────────────────────────

MAX_ITERATIONS = MAX_AGENT_ITERATIONS   # 50
HISTORY_WINDOW = 30
HISTORY_PIN    = 3
WARN_AT_80_PCT = True
WARN_AT_97_PCT = True
RECENT_FULL       = 6

# ── Agent Phase Tracking ────────────────────────────────────────────────────────

class AgentPhase:
    RESEARCH = "research"
    BUILD    = "build"
    DEPLOY   = "deploy"


PHASE_TRANSITIONS = {
    "web_search":       AgentPhase.RESEARCH,
    "write_file":       AgentPhase.BUILD,
    "patch_file":       AgentPhase.BUILD,
    "docker_up":        AgentPhase.DEPLOY,
    "docker_build":     AgentPhase.DEPLOY,
    "docker_logs":      AgentPhase.DEPLOY,
    "wait_for_service": AgentPhase.DEPLOY,
}

PHASE_GOALS = {
    "research": (
        "Use web_search ONCE to confirm exploit technique, then immediately start "
        "writing files with write_file. Do NOT call web_search more than once."
    ),
    "build": "Write all required files using write_file. Do NOT call web_search.",
    "deploy": (
        "Deploy in this EXACT order:\n"
        "1. docker_build(context_path=\".\")  — build image first\n"
        "2. docker_up(compose_file=\".\")     — start containers\n"
        "3. wait_for_service                  — wait for port\n"
        "4. docker_logs                       — check for errors/warnings\n"
        "5. http_request to /login            — confirm endpoint responds\n"
        "6. DONE\n"
        "If errors at any step: fix ONLY the broken file with patch_file, restart from step 1."
    ),
}


# ── Checkpoint / Memory ─────────────────────────────────────────────────────────

class Checkpoint:
    """Tracks milestone state that survives context window trimming."""

    def __init__(self, spec: dict):
        self.spec      = spec
        self.phase     = AgentPhase.RESEARCH
        self.built     = []
        self.deployed  = False
        self.port      = spec.get("assigned_port", 3000)
        self.errors    = []
        self.file_contents: dict[str, str] = {}
        # Deploy sequence tracking — enforced before DONE is accepted
        self.docker_built:   bool = False  # docker_build succeeded
        self.docker_upped:   bool = False  # docker_up succeeded
        self.logs_checked:   bool = False  # docker_logs called after deploy
        self.http_confirmed: bool = False  # http_request called after deploy

    def record_file(self, path: str, content: str = ""):
        if path not in self.built:
            self.built.append(path)
        if content:
            self.file_contents[path] = content

    def record_deployment(self, port: int = None):
        self.deployed = True
        if port is not None:
            self.port = port

    def record_error(self, error: str):
        self.errors.append(error)
        if len(self.errors) > 5:
            self.errors = self.errors[-5:]

    def to_summary(self) -> str:
        flag          = self.spec.get("flag", "")
        deploy_status = f"✅ Running on port {self.port}" if self.deployed else "❌ Not deployed"
        lines = [
            f"[CHECKPOINT — Phase: {self.phase.upper()}]",
            f"Vuln: {self.spec.get('vuln_type', 'unknown')} | Difficulty: {self.spec.get('difficulty', 'medium')}",
            f"Files: {', '.join(self.built[-10:]) or 'none yet'}"
            + (f" (+{len(self.built)-10} more)" if len(self.built) > 10 else ""),
            f"Deploy: {deploy_status}",
            f"Flag to embed: {flag}",
        ]
        if self.errors:
            lines.append(f"Recent errors: {'; '.join(self.errors[-2:])}")
        return "\n".join(lines)


# ── Context Window Management ───────────────────────────────────────────────────

def _compress_message(msg: dict) -> dict:
    content = msg.get("content", "")
    if not isinstance(content, str) or len(content) <= 600:
        return msg

    tool_match = re.search(r"Tool:\s*(\w+)", content)
    tool_name  = tool_match.group(1) if tool_match else "tool"

    status_match = re.search(r"(OK|FAILED|ERROR|SUCCESS|TIMEOUT)[^\n]*", content, re.IGNORECASE)
    status       = status_match.group(0).strip() if status_match else "unknown"

    lines  = [l.strip() for l in content.splitlines() if l.strip()]
    detail = ""
    for line in lines:
        if line not in (tool_name, status) and len(line) > 10:
            detail = line[:120]
            break

    summary = f"[{tool_name}] {status}"
    if detail:
        summary += f" | {detail}"

    return {**msg, "content": summary}

def manage_context(messages: list, checkpoint: Checkpoint) -> list:
    # Always refresh pinned summary + phase goal
    if len(messages) > 1:
        messages[1] = {"role": "user", "content": checkpoint.to_summary()}
    if len(messages) > 2:
        messages[2] = {"role": "user", "content": PHASE_GOALS[checkpoint.phase]}

    if len(messages) <= HISTORY_PIN + HISTORY_WINDOW:
        return messages

    pinned  = messages[:HISTORY_PIN]
    rolling = messages[HISTORY_PIN:]
    recent  = rolling[-HISTORY_WINDOW:]

    # Keep last RECENT_FULL messages untouched, compress everything older
    if len(recent) > RECENT_FULL:
        old    = [_compress_message(m) for m in recent[:-RECENT_FULL]]
        recent = old + recent[-RECENT_FULL:]

    pinned[1] = {"role": "user", "content": checkpoint.to_summary()}
    pinned[2] = {"role": "user", "content": PHASE_GOALS[checkpoint.phase]}

    return pinned + recent

def compact_for_phase(
    system_prompt: str,
    checkpoint: Checkpoint,
    new_phase: str,
) -> list:
    """Hard context reset at phase transitions."""
    spec = checkpoint.spec
    port = spec.get("assigned_port", 3000)

    phase_briefs = {
        AgentPhase.BUILD: (
            f"[BUILD PHASE]\n"
            f"Research is complete. Now write ALL required files:\n"
            f"  write_file(path=\"package.json\", content=\"...\")\n"
            f"  write_file(path=\"server.js\", content=\"...\")  ← embed flag here\n"
            f"  write_file(path=\"Dockerfile\", content=\"...\")\n"
            f"  write_file(path=\"docker-compose.yml\", content=\"...\")\n\n"
            f"Flag to embed in source: {spec.get('flag', '')}\n"
            f"Vulnerability: {spec.get('vuln_type', '')}\n\n"
            f"Do NOT call web_search. Write files directly using write_file."
        ),
        AgentPhase.DEPLOY: (
            f"[DEPLOY PHASE]\n"
            f"All files written. Deploy and verify the lab IN THIS EXACT ORDER:\n\n"
            f"  STEP 1: docker_build(context_path=\'.\')"
            f"  -> build image, catch errors early\n"
            f"  STEP 2: docker_up(compose_file=\'.\')"
            f"     -> start containers\n"
            f"  STEP 3: wait_for_service(url=\'http://localhost:{port}\', timeout=30)\n"
            f"  STEP 4: docker_logs(container=\'<name>\', tail=50) -> CHECK FOR ERRORS\n"
            f"          - Errors found -> patch_file to fix, then restart from STEP 1\n"
            f"          - Non-critical warnings (npm deprecation, etc.) -> safe to ignore\n"
            f"  STEP 5: http_request(url=\'http://localhost:{port}/login\', method=\'POST\')\n"
            f"          -> Any HTTP response (even 401) confirms the service is alive\n"
            f"  STEP 6: Call DONE\n\n"
            f"Do NOT skip any step. Do NOT attempt to exploit the vulnerability.\n"
            f"Files ready: {', '.join(checkpoint.built)}"
        ),
    }

    brief = phase_briefs.get(new_phase, f"[{new_phase.upper()} PHASE]")

    return [
        {"role": "system",    "content": system_prompt},
        {"role": "user",      "content": checkpoint.to_summary()},
        {"role": "assistant", "content": f"Understood. Entering {new_phase} phase now."},
        {"role": "user",      "content": brief},
    ]


# ── ReAct Agent ─────────────────────────────────────────────────────────────────

class ReActAgent:
    """
    Multi-phase tool-using agent for CTF lab generation.
    Stops at DEPLOY — no exploit or finalize phases.
    """

    def __init__(self, spec: dict, sandbox: DockerSandbox, workspace: str):
        self.spec       = spec
        self.sandbox    = sandbox
        self.workspace  = workspace
        self.lab_id     = spec.get("lab_id", "unknown")
        self.flag       = spec.get("flag", "")
        self.checkpoint = Checkpoint(spec)

        fs_set_workspace(workspace)
        docker_set_workspace(workspace)
        reporting_set_workspace(workspace)
        memory_set_spec(spec)

        self.skill_content = load_skill(spec.get("vuln_type", ""))
        self.system_prompt = render_system_prompt(spec, self.skill_content)

    def _initial_messages(self) -> list:
        research_goal = (
            PHASE_GOALS["research"] if not self.skill_content
            else "The skill blueprint above has all the info you need. Skip web_search and go directly to write_file."
        )
        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user",   "content": self.checkpoint.to_summary()},
            {
                "role": "user",
                "content": (
                    f"Build a CTF lab for '{self.spec.get('vuln_type')}' "
                    f"({self.spec.get('difficulty', 'medium')} difficulty). "
                    f"The flag is: {self.flag}\n\n"
                    f"{research_goal}"
                ),
            },
        ]

    def run(self) -> dict:
        """Run the multi-phase ReAct loop until DONE or max iterations."""
        messages       = self._initial_messages()
        last_phase     = AgentPhase.RESEARCH
        no_tool_count  = 0

        last_tool_name:  str | None = None
        last_tool_error: str | None = None
        repeated_error_count = 0


        for iteration in range(1, MAX_ITERATIONS + 1):
            pct = (iteration / MAX_ITERATIONS) * 100
            logger.info(
                f"[Agent] Iteration {iteration}/{MAX_ITERATIONS} ({pct:.0f}%) "
                f"— Phase: {self.checkpoint.phase}"
            )

            # ── Iteration budget warnings ─────────────────────────────────────
            if WARN_AT_80_PCT and iteration == int(MAX_ITERATIONS * 0.8):
                messages.append({
                    "role": "user",
                    "content": (
                        "⚠️ WARNING: 80% of iteration budget used. "
                        "If the lab is deployed and responding, call DONE immediately."
                    ),
                })

            if WARN_AT_97_PCT and iteration == int(MAX_ITERATIONS * 0.97):
                messages.append({
                    "role": "user",
                    "content": (
                        "🚨 CRITICAL: Only 3% iterations remaining! "
                        "Call DONE now or generation will be marked failed."
                    ),
                })

            # ── Phase transition: compact context ─────────────────────────────
            current_phase = self.checkpoint.phase
            if current_phase != last_phase and current_phase in (
                AgentPhase.BUILD, AgentPhase.DEPLOY
            ):
                logger.info(f"[Agent] Phase transition: {last_phase} → {current_phase}")
                messages   = compact_for_phase(self.system_prompt, self.checkpoint, current_phase)
                last_phase = current_phase

            # ── Context management ────────────────────────────────────────────
            messages = manage_context(messages, self.checkpoint)

            # ── LLM input debug ──────────────────────────────────────────────
            logger.debug(f"\n{'='*60}")
            logger.debug(f"[LLM INPUT] Iteration {iteration} — {len(messages)} messages")
            for i, m in enumerate(messages):
                preview = m.get("content", "")
                if len(preview) > 300:
                    preview = preview[:300] + "...[truncated]"
                logger.debug(f"  [{i}] {m['role'].upper()}: {preview}")
            logger.debug(f"{'='*60}")

            # ── LLM call ─────────────────────────────────────────────────────
            try:
                response = call_llm(
                    system_prompt=self.system_prompt,
                    user_prompt="",
                    temperature=0.3,
                    max_tokens=LLM_MAX_TOKENS,
                    conversation=messages,
                )
                logger.debug(f"[LLM OUTPUT] Iteration {iteration}:\n{response}")
            except Exception as e:
                logger.error(f"[Agent] LLM call failed: {e}")
                self.checkpoint.record_error(f"LLM error: {e}")
                messages.append({
                    "role": "user",
                    "content": f"LLM error: {e}. Please try again with your next tool call.",
                })
                continue

            if not response:
                logger.warning("[Agent] LLM returned empty response — nudging")
                no_tool_count += 1
                nudge = (
                    "Output ONE tool call only. No reasoning, no explanation. Just:\n"
                    "<tool>tool_name</tool>\n"
                    "<args>{\"key\": \"value\"}</args>"
                ) if no_tool_count >= 2 else "No response received. Please output a <tool> block."
                messages.append({"role": "user", "content": nudge})
                continue

            clean_response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
            messages.append({"role": "assistant", "content": clean_response[:4000] or response[:300]})

# ── Parse ALL tool calls ──────────────────────────────────────────
            tool_calls = parse_all_tool_calls(response)

            if not tool_calls:
                no_tool_count += 1
                logger.warning(f"[Agent] No tool call in response (miss #{no_tool_count})")
                if no_tool_count >= 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "You MUST output a tool call. Format:\n"
                            "<tool>tool_name</tool>\n"
                            "<args>{\"key\": \"value\"}</args>"
                        ),
                    })
                else:
                    messages.append({
                        "role": "user",
                        "content": "Please output a tool call using <tool></tool> and <args></args> tags.",
                    })
                continue

            no_tool_count = 0

            # ── Execute ALL tool calls in sequence ────────────────────────────
            should_continue = False  # flag to skip to next iteration
            for tool_name, args in tool_calls:
                logger.debug(f"[TOOL CALL] {tool_name}({json.dumps(args, indent=2)})")

                # ── DONE signal ───────────────────────────────────────────────
                if tool_name.upper() == "DONE":
                    cp = self.checkpoint
                    missing = []
                    if self.flag and not self._flag_exists_in_workspace():
                        missing.append(
                            f"flag '{self.flag}' not found in any source file — "
                            f"fix server.js/app.js to seed the flag, then redeploy"
                        )
                    if not cp.logs_checked:
                        missing.append(
                            "docker_logs not called yet — "
                            "call docker_logs to verify no errors before declaring done"
                        )
                    if not cp.http_confirmed:
                        missing.append(
                            "http_request not called yet — "
                            f"call http_request(url=\"http://localhost:{cp.port}/login\", method=\"POST\") "
                            f"to confirm the endpoint responds"
                        )
                    if missing:
                        logger.warning(f"[Agent] DONE rejected — missing steps: {missing}")
                        steps_text = "\n".join(f"  - {m}" for m in missing)
                        messages.append({
                            "role": "user",
                            "content": f"DONE rejected. Complete these missing steps first:\n{steps_text}",
                        })
                        should_continue = True
                        break

                    logger.info(f"[Agent] ✅ Lab complete after {iteration} iterations!")
                    return {
                        "status":     "success",
                        "lab_id":     self.lab_id,
                        "iterations": iteration,
                        "summary":    args.get("summary", "Lab generated and deployed successfully."),
                    }

                # ── Order guard ───────────────────────────────────────────────
                if tool_name == "docker_up" and not self.checkpoint.docker_built:
                    logger.warning("[Agent] docker_up called before docker_build — redirecting")
                    messages.append({
                        "role": "user",
                        "content": (
                            "docker_up rejected: you must run docker_build first.\n"
                            "Call docker_build(context_path=\".\") now, then docker_up after it succeeds."
                        ),
                    })
                    should_continue = True
                    break

                # ── Fix port in args before executing ─────────────────────────
                assigned = self.spec.get("assigned_port", 3000)
                if tool_name == "wait_for_service" and "url" in args:
                    # Replace any port in the URL with the assigned port
                    args["url"] = re.sub(r":\d+", f":{assigned}", args["url"])
                if tool_name == "http_request" and "url" in args:
                    args["url"] = re.sub(r":\d+", f":{assigned}", args["url"])

                # ── Execute tool ──────────────────────────────────────────────
                logger.info(f"[Agent] Tool: {tool_name}({json.dumps(args)[:150]})")
                raw_output = execute_tool(tool_name, args, sandbox=self.sandbox)
                output     = truncate_output(tool_name, raw_output)
                logger.debug(f"[TOOL RESULT] {tool_name} → {output[:500]}")

                # ── Repeated error breaker ────────────────────────────────────
                is_error = output.startswith("ERROR")
                if is_error and tool_name == last_tool_name and output[:120] == (last_tool_error or "")[:120]:
                    repeated_error_count += 1
                    if repeated_error_count >= 3:
                        fn  = TOOL_REGISTRY.get(tool_name)
                        sig = str(inspect.signature(fn)) if fn else "(unknown)"
                        messages.append({
                            "role": "user",
                            "content": (
                                f"You have called '{tool_name}' {repeated_error_count} times "
                                f"with the same error.\nSTOP. Exact signature: "
                                f"{tool_name}{sig}\nError: {output[:200]}\n"
                                f"Use a DIFFERENT approach."
                            ),
                        })
                        repeated_error_count = 0
                else:
                    if is_error:
                        last_tool_error      = output
                        repeated_error_count = 1 if tool_name == last_tool_name else 0
                    else:
                        repeated_error_count = 0
                        last_tool_error      = None
                last_tool_name = tool_name

                # ── Update checkpoint & phase ─────────────────────────────────
                self._update_checkpoint(tool_name, args, output)
                self._detect_phase(tool_name, output)

                # ── Feed observation back ─────────────────────────────────────
                messages.append({"role": "user", "content": f"[Observation]\n{output}"})

                # ── Post-tool guidance ────────────────────────────────────────
                if tool_name == "docker_up" and not output.lstrip().upper().startswith("ERROR"):
                    messages.append({
                        "role": "user",
                        "content": (
                            f"docker_up succeeded. "
                            f"Now call wait_for_service(url=\"http://localhost:{assigned}\", timeout=30)."
                        ),
                    })

                if tool_name == "wait_for_service":
                    if output.startswith("OK:"):
                        messages.append({
                            "role": "user",
                            "content": (
                                "✅ Service is up! Complete these final steps:\n\n"
                                f"STEP 1: docker_logs(container='<name>', tail=50)\n"
                                f"STEP 2: http_request(url=\"http://localhost:{assigned}/login\", method=\"POST\")\n"
                                "STEP 3: DONE"
                            ),
                        })
                    elif "TIMEOUT" in output:
                        import subprocess as _sp
                        ps = _sp.run(
                            ["docker", "ps", "-a", "--filter", f"name={self.lab_id}",
                             "--format", "{{.Names}}"],
                            capture_output=True, text=True,
                        )
                        container_name = (
                            ps.stdout.strip().split("\n")[0]
                            if ps.stdout.strip() else f"{self.lab_id}-app-1"
                        )
                        messages.append({
                            "role": "user",
                            "content": (
                                f"Service timed out — container likely crashing. "
                                f"Call docker_logs(container=\"{container_name}\") to see the crash reason. "
                                f"Do NOT rewrite files until you read the logs."
                            ),
                        })

                # Stop executing remaining tools if this one errored
                if is_error:
                    logger.warning(f"[Agent] Tool {tool_name} errored — stopping batch, waiting for LLM decision")
                    break

        logger.error(f"[Agent] Max iterations ({MAX_ITERATIONS}) reached.")
        return {
            "status":       "failed",
            "lab_id":       self.lab_id,
            "iterations":   MAX_ITERATIONS,
            "reason":       f"Max iterations ({MAX_ITERATIONS}) reached without completion.",
            "phase":        self.checkpoint.phase,
            "deployed":     self.checkpoint.deployed,
            "files_created": len(self.checkpoint.built),
        }

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def _flag_exists_in_workspace(self) -> bool:
        """
        Background check: does the flag value appear in any source file
        in the workspace? No exploitation — just confirms it was embedded
        correctly during the build phase.
        """
        source_extensions = {
            ".js", ".py", ".sql", ".json", ".ts",
            ".rb", ".go", ".php", ".env", ".txt",
        }
        try:
            workspace = Path(self.workspace)
            for f in workspace.rglob("*"):
                if f.is_file() and f.suffix in source_extensions:
                    try:
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        if self.flag in content:
                            return True
                    except Exception:
                        pass
        except Exception:
            pass
        return False

    def _update_checkpoint(self, tool_name: str, args: dict, output: str):
        """Update the milestone checkpoint from tool results."""
        is_error = output.lstrip().upper().startswith("ERROR")

        if tool_name in ("write_file", "patch_file"):
            path    = args.get("path", args.get("file_path", ""))
            content_val = args.get("content", "")
            if path:
                self.checkpoint.record_file(path, content_val)
            # A successful patch resets docker_built so agent must rebuild
            if tool_name == "patch_file" and not is_error:
                self.checkpoint.docker_built = False
                self.checkpoint.docker_upped = False
                self.checkpoint.logs_checked = False
                self.checkpoint.http_confirmed = False

        elif tool_name == "docker_build":
            if not is_error:
                self.checkpoint.docker_built = True
                logger.info("[Agent] ✅ docker_build succeeded")

        elif tool_name == "docker_up":
            if not is_error:
                self.checkpoint.docker_upped = True
                self.checkpoint.record_deployment(
                    port=self.spec.get("assigned_port", 3000)
                )
                # Reset log/http flags so they are re-checked for this new deploy
                self.checkpoint.logs_checked   = False
                self.checkpoint.http_confirmed = False

        elif tool_name == "wait_for_service":
            if output.startswith("OK:") or "ready" in output.lower() or "200" in output:
                self.checkpoint.record_deployment(
                    port=self.spec.get("assigned_port", 3000)
                )

        elif tool_name == "docker_logs":
            # Mark logs as checked regardless of content — agent decides what to do
            if self.checkpoint.deployed:
                self.checkpoint.logs_checked = True

        elif tool_name == "http_request":
            # Any non-error HTTP response after deployment confirms the endpoint
            if self.checkpoint.deployed and not is_error:
                self.checkpoint.http_confirmed = True

        if is_error and tool_name not in ("web_search",):
            self.checkpoint.record_error(f"{tool_name}: {output[:100]}")

    def _detect_phase(self, tool_name: str, output: str):
        """Auto-detect current phase from tool usage (forward-only)."""
        detected = PHASE_TRANSITIONS.get(tool_name)
        if not detected:
            return

        current     = self.checkpoint.phase
        phase_order = [AgentPhase.RESEARCH, AgentPhase.BUILD, AgentPhase.DEPLOY]

        if phase_order.index(detected) >= phase_order.index(current):
            if detected != current:
                logger.info(f"[Agent] Phase auto-detected: {current} → {detected}")
            self.checkpoint.phase = detected

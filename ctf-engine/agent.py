"""
agent.py — CTF Lab Generation Agent (Multi-Phase Architecture)

Restructured from flat ReAct loop to multi-phase agent inspired by Strix:
  Phase 1: RESEARCH — web_search + architecture planning
  Phase 2: BUILD — write all files using skill blueprints
  Phase 3: DEPLOY — docker compose up, health checks, log debugging
  Phase 4: EXPLOIT — write and execute PoC, capture flag
  Phase 5: FINALIZE — save exploit, register lab

Memory management:
  - Proper conversation history (not flattened strings)
  - Milestone checkpointing with pinned messages
  - Sliding window with configurable size
  - Hard context compaction at phase transitions
  - Strix-style iteration warnings at 80%/97%
"""

import inspect
import json
import logging
import re
from pathlib import Path
from typing import Optional

from config import LLM_MAX_TOKENS, MAX_AGENT_ITERATIONS
from llm.client import call_llm
from prompts import render_system_prompt
from skills import load_skill
from sandbox import DockerSandbox
from tools import (
    execute_tool, parse_tool_call, truncate_output, get_tool_descriptions,
    TOOL_REGISTRY,
)
from tools.filesystem import set_workspace as fs_set_workspace
from tools.docker_tools import set_workspace as docker_set_workspace
from tools.memory import set_spec as memory_set_spec
from tools.reporting import set_workspace as reporting_set_workspace

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────

MAX_ITERATIONS  = MAX_AGENT_ITERATIONS  # From config, default 150
HISTORY_WINDOW  = 12     # Recent messages to keep in sliding window
HISTORY_PIN     = 3      # Pinned messages at start (system + checkpoint + goal)
WARN_AT_80_PCT  = True   # Strix-style iteration warnings
WARN_AT_97_PCT  = True


# ─── Agent Phase Tracking ────────────────────────────────────────────────────

class AgentPhase:
    RESEARCH  = "research"
    BUILD     = "build"
    DEPLOY    = "deploy"
    EXPLOIT   = "exploit"
    FINALIZE  = "finalize"


PHASE_TRANSITIONS = {
    # Detect phase transitions from tool usage
    "web_search":      AgentPhase.RESEARCH,
    "write_file":      AgentPhase.BUILD,
    "patch_file":      AgentPhase.BUILD,
    "docker_up":       AgentPhase.DEPLOY,
    "docker_build":    AgentPhase.DEPLOY,
    "docker_logs":     AgentPhase.DEPLOY,
    "wait_for_service": AgentPhase.DEPLOY,
    "send_exploit":    AgentPhase.EXPLOIT,
    "http_request":    AgentPhase.EXPLOIT,
    "verify_flag":     AgentPhase.EXPLOIT,
    "save_exploit_script": AgentPhase.FINALIZE,
    "mark_lab_complete":   AgentPhase.FINALIZE,
    "save_lab_metadata":   AgentPhase.FINALIZE,
}


# ─── Checkpoint / Memory ────────────────────────────────────────────────────

class Checkpoint:
    """Tracks milestone state that survives context window trimming."""

    def __init__(self, spec: dict):
        self.spec       = spec
        self.phase      = AgentPhase.RESEARCH
        self.built      = []        # Files created
        self.deployed   = False     # docker compose up succeeded
        self.port       = spec.get("assigned_port", 3000)  # Dynamic port
        self.flag_found = False     # Flag confirmed in exploit output
        self.errors     = []        # Error history for debugging
        self.file_contents: dict[str, str] = {}  # Store file contents for white-box exploit context

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
        if len(self.errors) > 5:  # Keep only recent errors
            self.errors = self.errors[-5:]

    def to_summary(self) -> str:
        """Compact summary injected as a pinned message in context."""
        flag = self.spec.get("flag", "")
        status = "✅ FLAG CAPTURED" if self.flag_found else "⏳ In Progress"
        deploy_status = f"✅ Running on port {self.port}" if self.deployed else "❌ Not deployed"

        lines = [
            f"[CHECKPOINT — Phase: {self.phase.upper()}]",
            f"Vuln: {self.spec.get('vuln_type', 'unknown')} | Difficulty: {self.spec.get('difficulty', 'medium')}",
            f"Files: {', '.join(self.built[-10:]) or 'none yet'}" + (f" (+{len(self.built)-10} more)" if len(self.built) > 10 else ""),
            f"Deploy: {deploy_status}",
            f"Flag: {flag} — {status}",
        ]
        if self.errors:
            lines.append(f"Recent errors: {'; '.join(self.errors[-2:])}")
        return "\n".join(lines)


# ─── Context Window Management ───────────────────────────────────────────────

def manage_context(messages: list, checkpoint: Checkpoint) -> list:
    """
    Sliding window with pinned milestone injection.
    Keeps: [system_prompt, checkpoint_summary, initial_goal] + last HISTORY_WINDOW messages.
    """
    if len(messages) <= HISTORY_PIN + HISTORY_WINDOW:
        # Still small enough to keep everything
        # Update checkpoint message
        if len(messages) > 1:
            messages[1] = {"role": "user", "content": checkpoint.to_summary()}
        return messages

    pinned  = messages[:HISTORY_PIN]
    rolling = messages[HISTORY_PIN:]
    recent  = rolling[-HISTORY_WINDOW:]

    # Update the checkpoint message with latest state
    if len(pinned) > 1:
        pinned[1] = {"role": "user", "content": checkpoint.to_summary()}

    return pinned + recent



def _build_exploit_brief(checkpoint: Checkpoint, spec: dict) -> str:
    """Build a rich exploit-phase context with the actual source code
    so the AI can do WHITE-BOX exploitation instead of blind guessing."""
    port = checkpoint.port
    lines = [
        f"[EXPLOIT PHASE — WHITE-BOX]",
        f"Lab is running on http://localhost:{port}",
        f"Vulnerability: {spec.get('vuln_type')}",
        f"Target flag: {spec.get('flag')}",
        "",
    ]

    # Inject source code from BUILD phase so the AI knows the schema
    if checkpoint.file_contents:
        lines.append("=== SOURCE CODE (you wrote these files) ===")
        # Prioritize app code files, limit total size
        priority_exts = ('.js', '.py', '.ts', '.php', '.rb', '.go')
        code_files = {}
        other_files = {}
        for path, content in checkpoint.file_contents.items():
            if any(path.endswith(ext) for ext in priority_exts):
                code_files[path] = content
            else:
                other_files[path] = content

        total_chars = 0
        max_chars = 4000  # Keep within context budget

        for path, content in code_files.items():
            if total_chars + len(content) > max_chars:
                lines.append(f"\n--- {path} (truncated) ---")
                remaining = max_chars - total_chars
                lines.append(content[:remaining])
                total_chars = max_chars
                break
            lines.append(f"\n--- {path} ---")
            lines.append(content)
            total_chars += len(content)

        # Add Dockerfile/compose if space allows
        for path, content in other_files.items():
            if total_chars + len(content) > max_chars:
                break
            lines.append(f"\n--- {path} ---")
            lines.append(content)
            total_chars += len(content)

        lines.append("=== END SOURCE CODE ===")
        lines.append("")

    lines.extend([
        "INSTRUCTIONS:",
        "You have the full source code above. Use it to craft a PRECISE exploit.",
        "1. Count the EXACT number of columns in the vulnerable SELECT query.",
        "2. Your UNION SELECT must have the SAME number of columns.",
        "3. Place the flag column in the position that maps to the property",
        "   the application code reads (check the response line like `user.flag`).",
        "4. Use send_exploit / http_request to retrieve the flag.",
        "5. Then call verify_flag, save_exploit_script, and DONE.",
    ])

    return "\n".join(lines)


def compact_for_phase(
    system_prompt: str,
    checkpoint: Checkpoint,
    new_phase: str,
) -> list:
    """
    Hard context reset at phase transitions.
    Clears build history and gives the LLM a clean phase-specific context.
    """
    spec = checkpoint.spec

    phase_briefs = {
        AgentPhase.DEPLOY: (
            f"[DEPLOY PHASE]\n"
            f"All files have been written. Deploy them now using EXACT tool signatures:\n"
            f"  docker_up(compose_file=\".\")  ← starts containers via docker compose\n"
            f"  wait_for_service(url=\"http://localhost:{checkpoint.spec.get('assigned_port', 3000)}\", timeout=30)\n"
            f"  docker_logs(container=\"<name>\", tail=50)  ← if startup fails\n"
            f"  docker_build(context_path=\".\")  ← only if docker_up build step fails\n"
            f"Files ready: {', '.join(checkpoint.built)}\n"
            f"If docker_up fails: check docker_logs, fix the file, then docker_up again."
        ),
        AgentPhase.EXPLOIT: _build_exploit_brief(checkpoint, spec),
        AgentPhase.FINALIZE: (
            f"[FINALIZE PHASE]\n"
            f"Flag captured! Save the exploit script and finalize the lab.\n"
            f"Call save_exploit_script, then save_lab_metadata, then DONE."
        ),
    }

    brief = phase_briefs.get(new_phase, f"[{new_phase.upper()} PHASE]")

    return [
        {"role": "system",    "content": system_prompt},
        {"role": "user",      "content": checkpoint.to_summary()},
        {"role": "assistant", "content": f"Understood. Entering {new_phase} phase now."},
        {"role": "user",      "content": brief},
    ]


# ─── ReAct Agent ─────────────────────────────────────────────────────────────

class ReActAgent:
    """
    Multi-phase tool-using agent for CTF lab generation.
    Uses proper conversation history with Strix-style memory management.
    """

    def __init__(self, spec: dict, sandbox: DockerSandbox, workspace: str):
        self.spec       = spec
        self.sandbox    = sandbox
        self.workspace  = workspace
        self.lab_id     = spec.get("lab_id", "unknown")
        self.flag       = spec.get("flag", "")
        self.checkpoint = Checkpoint(spec)

        # Wire workspace into tool modules
        fs_set_workspace(workspace)
        docker_set_workspace(workspace)  # Fix: docker paths resolve to lab workspace
        reporting_set_workspace(workspace)
        memory_set_spec(spec)

        # Load skill blueprint
        self.skill_content = load_skill(spec.get("vuln_type", ""))

        # Build system prompt via Jinja2
        self.system_prompt = render_system_prompt(spec, self.skill_content)

    def _initial_messages(self) -> list:
        """Build the initial conversation context."""
        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user",   "content": self.checkpoint.to_summary()},
            {
                "role": "user",
                "content": (
                    f"Build a CTF lab for '{self.spec.get('vuln_type')}' "
                    f"({self.spec.get('difficulty', 'medium')} difficulty). "
                    f"The flag is: {self.flag}\n\n"
                    f"Start by researching current exploit techniques with web_search, "
                    f"then plan the file structure and begin writing code."
                ),
            },
        ]

    def run(self) -> dict:
        """Run the multi-phase ReAct loop until DONE or max iterations."""
        messages = self._initial_messages()
        last_phase = AgentPhase.RESEARCH
        no_tool_count = 0  # Consecutive responses without a tool call

        # Loop-breaker: track repeated failures of the same tool
        last_tool_name: str | None = None
        last_tool_error: str | None = None
        repeated_error_count = 0

        # Fix D: Semantic loop detector — track tool call patterns
        tool_history: list[str] = []

        for iteration in range(1, MAX_ITERATIONS + 1):
            pct = (iteration / MAX_ITERATIONS) * 100
            logger.info(f"[Agent] Iteration {iteration}/{MAX_ITERATIONS} ({pct:.0f}%) — Phase: {self.checkpoint.phase}")

            # ── Iteration warnings (Strix-style) ─────────────────────────
            if WARN_AT_80_PCT and iteration == int(MAX_ITERATIONS * 0.8):
                messages.append({
                    "role": "user",
                    "content": (
                        "⚠️ WARNING: You have used 80% of your iteration budget. "
                        "Focus on completing the current phase. If the lab works, "
                        "run the exploit and call DONE immediately."
                    ),
                })

            if WARN_AT_97_PCT and iteration == int(MAX_ITERATIONS * 0.97):
                messages.append({
                    "role": "user",
                    "content": (
                        "🚨 CRITICAL: Only 3% iterations remaining! "
                        "You MUST call DONE now or the lab generation will be marked as failed. "
                        "If the exploit worked, call DONE immediately."
                    ),
                })

            # ── Phase transition: compact context ─────────────────────────
            current_phase = self.checkpoint.phase
            if current_phase != last_phase and current_phase in (
                AgentPhase.DEPLOY, AgentPhase.EXPLOIT, AgentPhase.FINALIZE
            ):
                logger.info(f"[Agent] Phase transition: {last_phase} → {current_phase}")
                messages = compact_for_phase(self.system_prompt, self.checkpoint, current_phase)
                last_phase = current_phase

            # ── Context management ─────────────────────────────────────────
            messages = manage_context(messages, self.checkpoint)

            # ── LLM call ───────────────────────────────────────────────────
            try:
                response = call_llm(
                    system_prompt=self.system_prompt,
                    user_prompt="",
                    temperature=0.3,
                    max_tokens=LLM_MAX_TOKENS,
                    conversation=messages,
                )
            except Exception as e:
                logger.error(f"[Agent] LLM call failed: {e}")
                self.checkpoint.record_error(f"LLM error: {e}")
                messages.append({
                    "role": "user",
                    "content": f"LLM error occurred: {e}. Please try again with your next tool call.",
                })
                continue

            if not response:
                logger.warning("[Agent] LLM returned empty response — nudging")
                no_tool_count += 1
                if no_tool_count >= 3:
                    messages.append({
                        "role": "user",
                        "content": "You have not made a tool call in 3 turns. Output a <tool> block NOW.",
                    })
                else:
                    messages.append({
                        "role": "user",
                        "content": "No response received. Please output a <tool> block.",
                    })
                continue

            # Strip think blocks for history but keep for parsing
            clean_response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
            messages.append({"role": "assistant", "content": clean_response[:4000] or response[:300]})

            # ── Parse tool call ─────────────────────────────────────────────
            tool_name, args = parse_tool_call(response)

            if not tool_name:
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

            no_tool_count = 0  # Reset on valid tool call

            # ── DONE signal ─────────────────────────────────────────────────
            if tool_name.upper() == "DONE":
                if self.flag and not self._flag_seen_in_history(messages):
                    logger.warning(f"[Agent] DONE called but flag not confirmed!")
                    messages.append({
                        "role": "user",
                        "content": (
                            f"You declared DONE but the flag '{self.flag}' has not been "
                            f"confirmed in any tool output. Run send_exploit against "
                            f"http://localhost:{self.checkpoint.port} and verify the flag "
                            f"appears before calling DONE."
                        ),
                    })
                    continue

                logger.info(f"[Agent] ✅ Lab complete after {iteration} iterations!")
                return {
                    "status": "success",
                    "lab_id": self.lab_id,
                    "iterations": iteration,
                    "summary": args.get("summary", "Lab generated successfully."),
                }

            # ── Execute tool ─────────────────────────────────────────────────
            logger.info(f"[Agent] Tool: {tool_name}({json.dumps(args)[:150]})")
            raw_output = execute_tool(tool_name, args, sandbox=self.sandbox)
            output = truncate_output(tool_name, raw_output)
            logger.info(f"[Agent] Output ({len(output)} chars): {output[:300]}")

            # ── Loop-breaker: detect repeated identical failures ────────────
            is_error = output.startswith("ERROR")
            if is_error and tool_name == last_tool_name and output[:120] == (last_tool_error or "")[:120]:
                repeated_error_count += 1
                if repeated_error_count >= 3:
                    fn = TOOL_REGISTRY.get(tool_name)
                    sig = str(inspect.signature(fn)) if fn else "(unknown)"
                    correction = (
                        f"You have called '{tool_name}' {repeated_error_count} times with the same error.\n"
                        f"STOP guessing. The EXACT signature is: {tool_name}{sig}\n"
                        f"Error was: {output[:200]}\n"
                        f"Use a DIFFERENT tool or fix the root cause before retrying."
                    )
                    messages.append({"role": "user", "content": correction})
                    repeated_error_count = 0  # Reset after intervention
            else:
                if is_error:
                    last_tool_error = output
                    repeated_error_count = 1 if tool_name == last_tool_name else 0
                else:
                    repeated_error_count = 0
                    last_tool_error = None
            last_tool_name = tool_name

            # ── Fix D: Semantic loop detector ─────────────────────────────
            tool_history.append(tool_name)
            if len(tool_history) > 16:
                tool_history = tool_history[-16:]

            if len(tool_history) >= 8:
                recent = tool_history[-8:]
                writes = sum(1 for t in recent if t in ("write_file", "patch_file"))
                deploys = sum(1 for t in recent if t in ("docker_up", "docker_build"))
                if writes >= 3 and deploys >= 3:
                    logger.warning("[Agent] ⚠️ Rewrite-rebuild loop detected!")
                    messages.append({
                        "role": "user",
                        "content": (
                            "⚠️ LOOP DETECTED: You have been alternating between rewriting files "
                            "and running docker commands for several iterations. STOP rewriting files.\n"
                            "Instead: 1) Run docker_down() first, 2) Then docker_up(compose_file=\".\"), "
                            "3) If build fails, check the EXACT stacktrace/error and fix ONLY the broken file "
                            "using patch_file(path, find, replace).\n"
                            "Do NOT rewrite docker-compose.yml repeatedly — the version format is NOT the problem."
                        ),
                    })
                    tool_history.clear()

            # ── Update checkpoint & phase ──────────────────────────────────
            self._update_checkpoint(tool_name, args, output)
            self._detect_phase(tool_name, output)

            # ── Feed observation back ──────────────────────────────────────
            messages.append({"role": "user", "content": f"[Observation]\n{output}"})

        # Max iterations reached
        logger.error(f"[Agent] Max iterations ({MAX_ITERATIONS}) reached.")
        return {
            "status": "failed",
            "lab_id": self.lab_id,
            "iterations": MAX_ITERATIONS,
            "reason": f"Max iterations ({MAX_ITERATIONS}) reached without completion.",
            "phase": self.checkpoint.phase,
            "deployed": self.checkpoint.deployed,
            "files_created": len(self.checkpoint.built),
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _flag_seen_in_history(self, messages: list) -> bool:
        """Check if the flag appeared in any observation/tool output."""
        for msg in messages:
            content = msg.get("content", "")
            if self.flag in content and msg.get("role") == "user" and "[Observation]" in content:
                return True
        return self.checkpoint.flag_found

    def _update_checkpoint(self, tool_name: str, args: dict, output: str):
        """Update the milestone checkpoint from tool results."""
        if tool_name in ("write_file", "patch_file"):
            path = args.get("path", args.get("file_path", ""))
            content = args.get("content", "")
            if path:
                self.checkpoint.record_file(path, content)

        elif tool_name in ("docker_up", "docker_build"):
            if "error" not in output.lower() or "running" in output.lower():
                self.checkpoint.record_deployment(port=3000)

        elif tool_name == "wait_for_service":
            if "ready" in output.lower() or "200" in output or "success" in output.lower():
                self.checkpoint.record_deployment(port=3000)

        elif tool_name in ("verify_flag", "send_exploit", "http_request"):
            if self.flag and self.flag in output:
                self.checkpoint.flag_found = True
                logger.info(f"[Agent] 🏁 FLAG CAPTURED in {tool_name} output!")

        # Track errors for debugging context
        if "error" in output.lower()[:100] and tool_name not in ("web_search",):
            self.checkpoint.record_error(f"{tool_name}: {output[:100]}")

    def _detect_phase(self, tool_name: str, output: str):
        """Auto-detect current phase from tool usage."""
        detected = PHASE_TRANSITIONS.get(tool_name)
        if detected:
            current = self.checkpoint.phase
            phase_order = [
                AgentPhase.RESEARCH, AgentPhase.BUILD,
                AgentPhase.DEPLOY, AgentPhase.EXPLOIT, AgentPhase.FINALIZE,
            ]
            # Only advance phases forward, never backward
            if phase_order.index(detected) >= phase_order.index(current):
                if detected != current:
                    logger.info(f"[Agent] Phase auto-detected: {current} → {detected}")
                self.checkpoint.phase = detected

"""
main.py — FastAPI server for the CTF Generation Engine

Endpoints:
  POST /generate          — Generate a new lab from spec JSON
  GET  /lab/{lab_id}      — Get lab details
  POST /lab/{lab_id}/flag — Submit a flag
  GET  /lab/{lab_id}/hints — Get hints
  GET  /health            — Health check + LLM connectivity check
"""

import logging
import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import ENGINE_HOST, ENGINE_PORT, WORKSPACE_DIR
from orchestrator import Orchestrator
from tools.register_lab import RegisterLabTool
from llm.client import probe_llm

# ── Logging setup ──
import os
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
log_level = logging.DEBUG if DEBUG_MODE else logging.INFO

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Also write to a debug log file when debug is enabled
if DEBUG_MODE:
    file_handler = logging.FileHandler(
        os.path.join(WORKSPACE_DIR, "ctf_engine_debug.log"), mode='a'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)
    
logger = logging.getLogger(__name__)
if DEBUG_MODE:
    logger.info("🔍 DEBUG MODE ENABLED — verbose logging active, writing to ctf_engine_debug.log")

# Suppress noisy HTTP library logs even in debug mode (they drown out useful output)
for noisy_logger in ("httpcore", "httpx", "httpcore.connection", "httpcore.http11",
                      "urllib3", "urllib3.connectionpool", "hpack"):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)

# ── In-memory job tracker ──
# Key: job_id → Value: {"status": "pending/running/done/failed", "result": {...}}
jobs: dict = {}

orchestrator = Orchestrator()
registry = RegisterLabTool()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run on startup"""
    logger.info("CTF Generation Engine starting...")
    logger.info(f"Workspace: {WORKSPACE_DIR}")
    try:
        connected = probe_llm()
        logger.info("✅ Qwen model connected") if connected else logger.warning("⚠️  Qwen not ready yet — will retry on first request")
    except Exception as e:
        logger.warning(f"⚠️  Could not connect to Qwen model: {e}")
        logger.warning("Start the engine anyway — will retry on first request")
    yield
    logger.info("CTF Generation Engine shutting down")


app = FastAPI(
    title="CTF Lab Generation Engine",
    description="On-demand Dockerized CTF lab generation powered by LLM agents",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten this when connecting to your frontend
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request/Response models ──

class LabSpec(BaseModel):
    """
    The spec your Phase 2 LLM produces.
    Send this to POST /generate.
    """
    # Required
    vuln_type: str           # e.g., "sqli_union", "xss_reflected", "cmdi", "ssrf"
    difficulty: str          # "easy", "medium", "hard"
    flag: str                # e.g., "CTF{your_flag_here}"
    solution_payload: Optional[str] = None

    # Optional but recommended
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = "web"
    cve: Optional[str] = None
    learning_objectives: Optional[list] = None
    user_id: Optional[str] = "anonymous"

    # Auto-assigned
    lab_id: Optional[str] = None


class FlagSubmission(BaseModel):
    flag: str


# ── Endpoints ──

@app.get("/health")
def health_check():
    """Check engine and LLM connectivity"""
    connected = probe_llm()
    return {
        "status": "healthy" if connected else "degraded",
        "llm_connected": connected,
        "model": "qwen3:30b-a3b",
        "engine": "CTF Generation Engine v1.0",
    }


@app.post("/generate")
async def generate_lab(spec: LabSpec, background_tasks: BackgroundTasks):
    """
    Start lab generation. Returns a job_id immediately.
    Poll GET /jobs/{job_id} for status.

    This is async because lab generation takes 2-10 minutes.
    You don't want the HTTP connection to hang open that long.
    """
    if not spec.lab_id:
        spec.lab_id = f"lab_{uuid.uuid4().hex[:8]}"

    job_id = f"job_{uuid.uuid4().hex[:8]}"

    # Register job as pending
    jobs[job_id] = {
        "status": "pending",
        "lab_id": spec.lab_id,
        "result": None,
    }

    # Run generation in background
    background_tasks.add_task(
        _run_generation,
        job_id=job_id,
        spec=spec.model_dump(),
    )

    logger.info(f"Job {job_id} queued for lab {spec.lab_id}")

    return {
        "job_id": job_id,
        "lab_id": spec.lab_id,
        "status": "pending",
        "message": "Lab generation started. Poll /jobs/{job_id} for status.",
        "poll_url": f"/jobs/{job_id}",
    }


@app.post("/generate/sync")
def generate_lab_sync(spec: LabSpec):
    """
    Synchronous version of /generate.
    Blocks until lab is ready or fails.
    Use this for testing — not for production with a frontend.
    """
    if not spec.lab_id:
        spec.lab_id = f"lab_{uuid.uuid4().hex[:8]}"

    logger.info(f"Starting SYNC generation for {spec.lab_id}")
    result = orchestrator.generate_lab(
        spec=spec.model_dump(),
        user_id=spec.user_id or "anonymous",
    )
    return result


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """Poll this to check if your lab is ready"""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/lab/{lab_id}")
def get_lab(lab_id: str):
    """Get details for a registered lab"""
    lab = registry.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    # Don't expose the flag in this endpoint
    lab_safe = {k: v for k, v in lab.items() if k != "challenge" or True}
    challenge_safe = {
        k: v
        for k, v in lab.get("challenge", {}).items()
        if k != "flag"  # Never expose flag via GET
    }
    return {**lab, "challenge": challenge_safe}


@app.get("/lab/{lab_id}/hints")
def get_hints(lab_id: str):
    """Get progressive hints for a lab"""
    hints = registry.get_hints(lab_id)
    if not hints:
        raise HTTPException(status_code=404, detail="Hints not found for this lab")
    return {"lab_id": lab_id, "hints": hints}


@app.post("/lab/{lab_id}/flag")
def submit_flag(lab_id: str, submission: FlagSubmission):
    """Submit a flag attempt"""
    result = registry.submit_flag(lab_id, submission.flag)
    return {"lab_id": lab_id, **result}


@app.get("/lab/{lab_id}/solution")
def get_solution(lab_id: str):
    """
    Get the full solution walkthrough.
    In production: require authentication / solve-first verification.
    """
    solution = registry.get_solution(lab_id)
    if not solution:
        raise HTTPException(status_code=404, detail="Solution not found")
    return {"lab_id": lab_id, "solution": solution}


@app.get("/jobs")
def list_jobs():
    """List all jobs (useful for debugging)"""
    return {
        "total": len(jobs),
        "jobs": [
            {"job_id": jid, "status": j["status"], "lab_id": j["lab_id"]}
            for jid, j in jobs.items()
        ],
    }


# ── Background task ──

async def _run_generation(job_id: str, spec: dict):
    """Runs in background — calls orchestrator and updates job status"""
    jobs[job_id]["status"] = "running"
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: orchestrator.generate_lab(
                spec=spec,
                user_id=spec.get("user_id", "anonymous"),
            ),
        )
        jobs[job_id]["status"] = "done" if result["status"] == "success" else "failed"
        jobs[job_id]["result"] = result
    except Exception as e:
        logger.error(f"Generation job {job_id} crashed: {e}", exc_info=True)
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["result"] = {"error": str(e)}


# ── Entry point ──

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=ENGINE_HOST,
        port=ENGINE_PORT,
        reload=False,
        log_level="info",
    )

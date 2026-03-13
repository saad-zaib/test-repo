"""
tools/register_lab.py

Tool 5: register_lab

Saves the completed, verified lab to a registry (JSON file for now,
easy to swap to a real database later).
Returns the lab URL and session token.
"""

import json
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from config import LAB_SESSION_HOURS, WORKSPACE_DIR

logger = logging.getLogger(__name__)

REGISTRY_FILE = Path(WORKSPACE_DIR) / "registry.json"


class RegisterLabTool:

    def register(
        self,
        lab_dir: str,
        service_urls: dict,
        par_time: float,
        user_id: str = "anonymous",
    ) -> dict:
        """
        Register a completed, verified lab.

        Returns lab_url and session_token for the user.
        """
        lab_path = Path(lab_dir)
        meta_file = lab_path / "meta" / "challenge.json"

        challenge = {}
        if meta_file.exists():
            challenge = json.loads(meta_file.read_text())

        lab_id = challenge.get("lab_id", lab_path.name)
        session_token = str(uuid.uuid4())
        expires_at = (datetime.utcnow() + timedelta(hours=LAB_SESSION_HOURS)).isoformat()

        registry_entry = {
            "lab_id": lab_id,
            "user_id": user_id,
            "session_token": session_token,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at,
            "service_urls": service_urls,
            "par_time": par_time,
            "lab_dir": lab_dir,
            "status": "active",
            "challenge": {
                "title": challenge.get("title", "Security Challenge"),
                "description": challenge.get("description", ""),
                "category": challenge.get("category", "web"),
                "difficulty": challenge.get("difficulty", "medium"),
                "flag": challenge.get("flag", ""),
                "ports": challenge.get("ports", {}),
            },
        }

        # Load or create registry
        registry = self._load_registry()
        registry[lab_id] = registry_entry
        self._save_registry(registry)

        logger.info(f"[Tool5] ✅ Lab {lab_id} registered for user {user_id}")
        logger.info(f"[Tool5] Expires at: {expires_at}")

        return {
            "status": "registered",
            "lab_id": lab_id,
            "session_token": session_token,
            "expires_at": expires_at,
            "service_urls": service_urls,
            "par_time": par_time,
            "challenge_title": challenge.get("title", "Security Challenge"),
            "challenge_description": challenge.get("description", ""),
        }

    def get_lab(self, lab_id: str) -> dict:
        registry = self._load_registry()
        return registry.get(lab_id, {})

    def get_hints(self, lab_id: str) -> list:
        registry = self._load_registry()
        entry = registry.get(lab_id, {})
        lab_dir = entry.get("lab_dir", "")
        hints_file = Path(lab_dir) / "meta" / "hints.json"
        if hints_file.exists():
            data = json.loads(hints_file.read_text())
            return data.get("hints", [])
        return []

    def get_solution(self, lab_id: str) -> dict:
        registry = self._load_registry()
        entry = registry.get(lab_id, {})
        lab_dir = entry.get("lab_dir", "")
        solution_file = Path(lab_dir) / "meta" / "solution.json"
        if solution_file.exists():
            return json.loads(solution_file.read_text())
        return {}

    def submit_flag(self, lab_id: str, submitted_flag: str) -> dict:
        registry = self._load_registry()
        entry = registry.get(lab_id, {})

        if not entry:
            return {"correct": False, "reason": "Lab not found"}

        correct_flag = entry.get("challenge", {}).get("flag", "")

        if submitted_flag.strip() == correct_flag.strip():
            # Mark as solved
            entry["solved"] = True
            entry["solved_at"] = datetime.utcnow().isoformat()
            registry[lab_id] = entry
            self._save_registry(registry)
            return {"correct": True, "message": "🎉 Correct! Well done."}

        return {"correct": False, "message": "Incorrect flag. Keep trying!"}

    def _load_registry(self) -> dict:
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if REGISTRY_FILE.exists():
            return json.loads(REGISTRY_FILE.read_text())
        return {}

    def _save_registry(self, registry: dict):
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        REGISTRY_FILE.write_text(json.dumps(registry, indent=2))

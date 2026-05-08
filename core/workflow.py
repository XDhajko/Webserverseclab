import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.storage import RUNS_DIR

_WORKFLOW_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_path(run_id: str) -> str:
    return os.path.join(RUNS_DIR, run_id)


def workflow_path(run_id: str) -> str:
    return os.path.join(_run_path(run_id), "workflow.json")


def ensure_run_path(run_id: str) -> None:
    os.makedirs(_run_path(run_id), exist_ok=True)


def load_workflow(run_id: str) -> Dict[str, Any]:
    path = workflow_path(run_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_workflow(run_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    ensure_run_path(run_id)
    payload = dict(data or {})
    payload["run_id"] = run_id
    payload["updated_at"] = _now_iso()
    with _WORKFLOW_LOCK:
        with open(workflow_path(run_id), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    return payload


def update_workflow(run_id: str, mutator) -> Dict[str, Any]:
    with _WORKFLOW_LOCK:
        current = load_workflow(run_id)
        updated = mutator(dict(current or {})) or current or {}
        updated["run_id"] = run_id
        updated["updated_at"] = _now_iso()
        ensure_run_path(run_id)
        with open(workflow_path(run_id), "w", encoding="utf-8") as fh:
            json.dump(updated, fh, indent=2)
    return updated


def init_scan_workflow(
    run_id: str,
    targets: List[Dict[str, Any]],
    scan_profile: str,
    agent_mode: str,
    rescan_of: Optional[str] = None,
) -> Dict[str, Any]:
    return save_workflow(run_id, {
        "created_at": _now_iso(),
        "targets": targets,
        "rescan_of": rescan_of,
        "scan": {
            "status": "queued",
            "scan_profile": scan_profile,
            "agent_mode": agent_mode,
            "progress": {"completed": 0, "total": 0, "label": "Queued"},
            "logs": [],
            "error": "",
            "started_at": None,
            "finished_at": None,
        },
        "hardening": {
            "status": "idle",
            "progress": {"completed": 0, "total": 0, "label": ""},
            "logs": [],
            "error": "",
            "started_at": None,
            "finished_at": None,
            "source_run_id": run_id,
            "rescan_run_id": None,
        },
    })


def set_scan_status(
    run_id: str,
    status: str,
    *,
    label: Optional[str] = None,
    completed: Optional[int] = None,
    total: Optional[int] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    def mutate(data: Dict[str, Any]) -> Dict[str, Any]:
        scan = data.setdefault("scan", {})
        progress = scan.setdefault("progress", {"completed": 0, "total": 0, "label": ""})
        scan["status"] = status
        if label is not None:
            progress["label"] = label
        if completed is not None:
            progress["completed"] = int(completed)
        if total is not None:
            progress["total"] = int(total)
        if error is not None:
            scan["error"] = error
        if status == "running" and not scan.get("started_at"):
            scan["started_at"] = _now_iso()
        if status in {"done", "error"}:
            scan["finished_at"] = _now_iso()
        return data

    return update_workflow(run_id, mutate)


def append_scan_log(run_id: str, message: str, *, level: str = "info") -> Dict[str, Any]:
    def mutate(data: Dict[str, Any]) -> Dict[str, Any]:
        scan = data.setdefault("scan", {})
        logs = scan.setdefault("logs", [])
        logs.append({"ts": _now_iso(), "level": level, "message": message})
        scan["logs"] = logs[-400:]
        return data

    return update_workflow(run_id, mutate)


def set_hardening_status(
    run_id: str,
    status: str,
    *,
    label: Optional[str] = None,
    completed: Optional[int] = None,
    total: Optional[int] = None,
    error: Optional[str] = None,
    rescan_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    def mutate(data: Dict[str, Any]) -> Dict[str, Any]:
        hardening = data.setdefault("hardening", {})
        progress = hardening.setdefault("progress", {"completed": 0, "total": 0, "label": ""})
        hardening["status"] = status
        if label is not None:
            progress["label"] = label
        if completed is not None:
            progress["completed"] = int(completed)
        if total is not None:
            progress["total"] = int(total)
        if error is not None:
            hardening["error"] = error
        if rescan_run_id is not None:
            hardening["rescan_run_id"] = rescan_run_id
        if status == "running" and not hardening.get("started_at"):
            hardening["started_at"] = _now_iso()
        if status in {"done", "error"}:
            hardening["finished_at"] = _now_iso()
        return data

    return update_workflow(run_id, mutate)


def append_hardening_log(run_id: str, message: str, *, level: str = "info") -> Dict[str, Any]:
    def mutate(data: Dict[str, Any]) -> Dict[str, Any]:
        hardening = data.setdefault("hardening", {})
        logs = hardening.setdefault("logs", [])
        logs.append({"ts": _now_iso(), "level": level, "message": message})
        hardening["logs"] = logs[-400:]
        return data

    return update_workflow(run_id, mutate)


def list_workflows() -> List[Dict[str, Any]]:
    if not os.path.exists(RUNS_DIR):
        return []

    items: List[Dict[str, Any]] = []
    for name in os.listdir(RUNS_DIR):
        run_dir = os.path.join(RUNS_DIR, name)
        if not os.path.isdir(run_dir):
            continue
        data = load_workflow(name)
        if not data:
            continue
        items.append(data)

    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return items


def find_active_run(section: str) -> Optional[Dict[str, Any]]:
    for item in list_workflows():
        status = ((item.get(section) or {}).get("status") or "").lower()
        if status in {"queued", "running"}:
            return item
    return None


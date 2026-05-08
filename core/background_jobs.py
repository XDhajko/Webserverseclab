import concurrent.futures
import json
import os
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.agent_runner import AgentRunner
from core.hardening import (
    build_hardening_report,
    build_playbook,
    classify_findings,
    deduplicate_tags,
    execute_remediation,
    export_hardening_report,
    save_playbook,
)
from core.normalize import Normalizer
from core.ssh_manager import SSHConnectionManager
from core.storage import RUNS_DIR, StorageManager
from core.workflow import (
    append_hardening_log,
    append_scan_log,
    find_active_run,
    init_scan_workflow,
    load_workflow,
    set_hardening_status,
    set_scan_status,
)
from scanners.base import BaseScanner
from scanners.gobuster_scanner import GobusterScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nmap_scanner import NmapScanner
from scanners.testssl_scanner import TestsslScanner

_JOB_THREADS: Dict[Tuple[str, str], threading.Thread] = {}
_JOB_LOCK = threading.Lock()


def _register_job(kind: str, run_id: str, thread: threading.Thread) -> None:
    with _JOB_LOCK:
        _JOB_THREADS[(kind, run_id)] = thread


def _unregister_job(kind: str, run_id: str) -> None:
    with _JOB_LOCK:
        _JOB_THREADS.pop((kind, run_id), None)


def _is_job_alive(kind: str, run_id: str) -> bool:
    with _JOB_LOCK:
        thread = _JOB_THREADS.get((kind, run_id))
    return bool(thread and thread.is_alive())


def _load_findings(run_id: str) -> List[dict]:
    summary_file = os.path.join(RUNS_DIR, run_id, "summary.json")
    if not os.path.exists(summary_file):
        return []
    try:
        with open(summary_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("findings", []) if isinstance(data, dict) else []
    except Exception:
        return []


def _run_scanner(scanner_cls, sc_target: Dict[str, Any], sc_run_id: str) -> Dict[str, Any]:
    return scanner_cls(sc_target, sc_run_id).scan()


def _scan_worker(
    run_id: str,
    targets: List[Dict[str, Any]],
    scan_profile: str,
    agent_mode: str,
    runtime_passwords: Optional[Dict[str, str]] = None,
) -> None:
    runtime_passwords = dict(runtime_passwords or {})
    total_steps = len(targets) * 5
    completed = 0

    try:
        set_scan_status(run_id, "running", label="Initializing scan pipeline", completed=0, total=total_steps)
        append_scan_log(run_id, f"Initialized scan session {run_id}")
        agent_runner = AgentRunner(run_id, mode=agent_mode)

        for target in targets:
            StorageManager.init_target_dir(run_id, target["name"])
            append_scan_log(run_id, f"### Target: {target['name']} ({target['ip']})")
            set_scan_status(
                run_id,
                "running",
                label=f"{target['name']} ({target['ip']}) - starting parallel scanners",
                completed=completed,
                total=total_steps,
            )

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(_run_scanner, NmapScanner, target, run_id): "Nmap",
                    executor.submit(_run_scanner, NiktoScanner, target, run_id): "Nikto",
                    executor.submit(_run_scanner, TestsslScanner, target, run_id): "TestSSL",
                    executor.submit(_run_scanner, GobusterScanner, target, run_id): "Gobuster",
                }

                for future in concurrent.futures.as_completed(futures):
                    scanner_name = futures[future]
                    try:
                        result = future.result()
                        if isinstance(result, dict) and result.get("status") == "error":
                            err = result.get("stderr") or result.get("error") or "Unknown scanner error"
                            append_scan_log(run_id, f"[{scanner_name}] scan failed: {err}", level="error")
                            label = f"{target['name']} | [{scanner_name}] scan failed"
                        else:
                            append_scan_log(run_id, f"[{scanner_name}] scan completed.")
                            label = f"{target['name']} | [{scanner_name}] scan completed"
                    except Exception as exc:
                        append_scan_log(run_id, f"[{scanner_name}] scan failed: {exc}", level="error")
                        label = f"{target['name']} | [{scanner_name}] scan failed"

                    completed += 1
                    set_scan_status(run_id, "running", label=label, completed=completed, total=total_steps)

            append_scan_log(run_id, f"All scans completed for {target['name']}")

            runtime_password = runtime_passwords.get(target["name"])
            append_scan_log(run_id, f"Running internal agent for {target['name']}...")
            set_scan_status(
                run_id,
                "running",
                label=f"{target['name']} | Running internal agent",
                completed=completed,
                total=total_steps,
            )
            agent_result = agent_runner.run_for_target(target, runtime_password=runtime_password)
            if agent_result.get("status") == "success":
                append_scan_log(run_id, "[agent] completed.")
            else:
                append_scan_log(
                    run_id,
                    f"[agent] failed: {agent_result.get('error', 'Unknown error')}",
                    level="error",
                )

            completed += 1
            set_scan_status(run_id, "running", completed=completed, total=total_steps, label=f"{target['name']} | Agent finished")

        append_scan_log(run_id, "Normalizing and mapping finding data to internal templates...")
        set_scan_status(run_id, "running", label="Normalizing and mapping finding data", completed=completed, total=total_steps)
        normalizer = Normalizer(run_id, scan_profile=scan_profile)
        normalizer.normalize_all()
        set_scan_status(run_id, "done", label="Scan completed", completed=total_steps, total=total_steps)
        append_scan_log(run_id, "Scan completed successfully.")
    except Exception as exc:
        append_scan_log(run_id, f"Scan pipeline failed: {exc}", level="error")
        append_scan_log(run_id, traceback.format_exc(), level="error")
        set_scan_status(run_id, "error", label="Scan failed", completed=completed, total=total_steps, error=str(exc))
    finally:
        BaseScanner.cleanup_run_containers(run_id)
        _unregister_job("scan", run_id)


def start_scan_job(
    run_id: str,
    targets: List[Dict[str, Any]],
    scan_profile: str,
    agent_mode: str,
    runtime_passwords: Optional[Dict[str, str]] = None,
    *,
    rescan_of: Optional[str] = None,
) -> str:
    init_scan_workflow(run_id, targets, scan_profile, agent_mode, rescan_of=rescan_of)
    if _is_job_alive("scan", run_id):
        return run_id

    worker = threading.Thread(
        target=_scan_worker,
        args=(run_id, targets, scan_profile, agent_mode, dict(runtime_passwords or {})),
        daemon=True,
        name=f"scan-{run_id}",
    )
    _register_job("scan", run_id, worker)
    worker.start()
    return run_id


def start_scan_job_if_idle(
    run_id: str,
    targets: List[Dict[str, Any]],
    scan_profile: str,
    agent_mode: str,
    runtime_passwords: Optional[Dict[str, str]] = None,
    *,
    rescan_of: Optional[str] = None,
) -> str:
    active = find_active_run("scan")
    if active and (active.get("run_id") != run_id):
        return str(active.get("run_id"))
    return start_scan_job(run_id, targets, scan_profile, agent_mode, runtime_passwords, rescan_of=rescan_of)


def _resolve_target_from_findings(findings: List[dict], target_name: str) -> Optional[dict]:
    for finding in findings:
        target = finding.get("target") or {}
        if target.get("name") == target_name:
            return target
    return None


def _hardening_worker(run_id: str) -> None:
    completed = 0
    total_tasks = 0

    try:
        findings = _load_findings(run_id)
        if not findings:
            raise RuntimeError("No findings available for hardening.")

        classified = classify_findings(findings)
        auto_tags_per_target: Dict[str, List[str]] = {}
        for tname, buckets in classified.items():
            tags = deduplicate_tags(buckets["auto"])
            if tags:
                auto_tags_per_target[tname] = tags

        total_tasks = sum(len(tags) for tags in auto_tags_per_target.values()) + (len(auto_tags_per_target) * 2)
        set_hardening_status(run_id, "running", label="Preparing hardening plan", completed=0, total=total_tasks)
        append_hardening_log(run_id, f"Preparing hardening for run {run_id}")

        ssh_mgr = SSHConnectionManager()
        results_by_target: Dict[str, List[dict]] = {}

        for tname, tags in auto_tags_per_target.items():
            target_info = _resolve_target_from_findings(findings, tname)
            if target_info is None:
                append_hardening_log(run_id, f"Skipping {tname}: target metadata missing", level="error")
                continue

            last_completed_tag: set = set()

            def _progress_cb(tag: str, step: str, status: str) -> None:
                nonlocal completed
                label = f"{tname} | {tag} | {step} - {status}"
                append_hardening_log(run_id, label, level="error" if status == "failed" else "info")
                if status in {"ok", "failed"} and tag not in last_completed_tag:
                    last_completed_tag.add(tag)
                    completed += 1
                set_hardening_status(run_id, "running", label=label, completed=completed, total=total_tasks)

            append_hardening_log(run_id, f"Connecting to {tname} ({target_info.get('platform', 'unknown')})")
            results = execute_remediation(target_info, tags, ssh_mgr, progress_cb=_progress_cb)
            results_by_target[tname] = results

            run_dir = Path(RUNS_DIR) / run_id / "hardening"
            playbook = build_playbook(tname, target_info.get("platform", "unknown"), tags)
            save_playbook(playbook, run_dir, tname)

            completed += 2
            set_hardening_status(
                run_id,
                "running",
                label=f"{tname} | Verification and reload finished",
                completed=completed,
                total=total_tasks,
            )

        manual_tags: Dict[str, List[str]] = {}
        for tname, buckets in classified.items():
            mt = deduplicate_tags(buckets.get("manual", []))
            if mt:
                manual_tags[tname] = mt

        report = build_hardening_report(run_id, results_by_target, manual_tags)
        run_dir = Path(RUNS_DIR) / run_id / "hardening"
        export_hardening_report(report, run_dir)

        total_failed = int(((report.get("summary") or {}).get("total_failed")) or 0)
        if total_failed:
            append_hardening_log(run_id, f"Hardening completed with {total_failed} failed remediation task(s).", level="error")
            set_hardening_status(
                run_id,
                "done",
                label=f"Hardening completed with {total_failed} failure(s)",
                completed=total_tasks,
                total=total_tasks,
            )
        else:
            append_hardening_log(run_id, "Hardening completed successfully.")
            set_hardening_status(run_id, "done", label="Hardening completed", completed=total_tasks, total=total_tasks)
    except Exception as exc:
        append_hardening_log(run_id, f"Hardening failed: {exc}", level="error")
        append_hardening_log(run_id, traceback.format_exc(), level="error")
        set_hardening_status(run_id, "error", label="Hardening failed", completed=completed, total=total_tasks, error=str(exc))
    finally:
        _unregister_job("hardening", run_id)


def start_hardening_job(run_id: str) -> str:
    workflow = load_workflow(run_id)
    hardening_status = ((workflow.get("hardening") or {}).get("status") or "").lower()
    if hardening_status in {"queued", "running"} and _is_job_alive("hardening", run_id):
        return run_id

    set_hardening_status(run_id, "queued", label="Queued for execution", completed=0, total=0)
    worker = threading.Thread(target=_hardening_worker, args=(run_id,), daemon=True, name=f"hardening-{run_id}")
    _register_job("hardening", run_id, worker)
    worker.start()
    return run_id

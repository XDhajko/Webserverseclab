import json
import os
from typing import Dict, List

import pandas as pd
import streamlit as st

from core.background_jobs import start_scan_job_if_idle
from core.storage import StorageManager
from core.workflow import find_active_run, load_workflow
from ui.navigation import go_to

TARGETS_FILE = "config/targets.json"
SETTINGS_FILE = "config/app_settings.json"


def load_targets() -> List[Dict]:
    if not os.path.exists(TARGETS_FILE):
        return []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_settings() -> Dict:
    if not os.path.exists(SETTINGS_FILE):
        return {"scan_profile": "standards_mode"}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {"scan_profile": "standards_mode"}
    except Exception:
        return {"scan_profile": "standards_mode"}


def _ensure_selection_state(targets: List[Dict], scan_profile: str) -> None:
    if "audit_available" not in st.session_state:
        st.session_state.audit_available = targets
    if "audit_selected" not in st.session_state:
        st.session_state.audit_selected = []
    if "agent_scan_mode" not in st.session_state:
        st.session_state.agent_scan_mode = "deep" if scan_profile == "standards_mode" else "quick"
    if "runtime_passwords" not in st.session_state:
        st.session_state.runtime_passwords = {}
    if "audit_focus_run_id" not in st.session_state:
        st.session_state.audit_focus_run_id = None
    if "audit_rescan_notice" not in st.session_state:
        st.session_state.audit_rescan_notice = None

    current_by_name = {t.get("name"): t for t in targets}
    selected_names = {t.get("name") for t in st.session_state.audit_selected}
    st.session_state.audit_selected = [current_by_name[n] for n in selected_names if n in current_by_name]
    st.session_state.audit_available = [t for t in targets if t.get("name") not in selected_names]


def _resolve_requested_targets(request: Dict, configured_targets: List[Dict]) -> List[Dict]:
    by_name = {t.get("name"): t for t in configured_targets}
    names = request.get("target_names") or []
    return [by_name[name] for name in names if name in by_name]


def _scan_summary_path(run_id: str) -> str:
    return os.path.join("runs", run_id, "summary.json")


def _load_summary(run_id: str) -> Dict:
    path = _scan_summary_path(run_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _start_requested_scan(request: Dict, configured_targets: List[Dict], scan_profile: str) -> None:
    targets = _resolve_requested_targets(request, configured_targets)
    if not targets:
        st.warning("The requested rescan could not be started because none of the original targets are configured anymore.")
        return

    runtime_passwords = dict(request.get("runtime_passwords") or {})
    password_targets = [
        target for target in targets
        if target.get("ssh_auth_type") == "password"
        and not target.get("ssh_password")
        and not runtime_passwords.get(target.get("name"))
    ]
    if password_targets:
        selected_names = {target.get("name") for target in targets}
        st.session_state.audit_selected = [target for target in configured_targets if target.get("name") in selected_names]
        st.session_state.audit_available = [target for target in configured_targets if target.get("name") not in selected_names]
        st.session_state.runtime_passwords = runtime_passwords
        st.session_state.audit_focus_run_id = None
        st.session_state.audit_rescan_notice = request.get("rescan_of")
        return

    run_id = StorageManager.create_run()
    actual_run_id = start_scan_job_if_idle(
        run_id,
        targets,
        scan_profile,
        "deep" if scan_profile == "standards_mode" else "quick",
        runtime_passwords=runtime_passwords,
        rescan_of=request.get("rescan_of"),
    )
    st.session_state.audit_focus_run_id = actual_run_id
    st.session_state.audit_rescan_notice = request.get("rescan_of")


def _render_active_scan(workflow: Dict) -> None:
    _render_active_scan_fragment(workflow.get("run_id", ""))


@st.fragment(run_every=2.0)
def _render_active_scan_fragment(run_id: str) -> None:
    workflow = load_workflow(run_id)
    run_id = workflow.get("run_id", "")
    scan = workflow.get("scan") or {}
    status = (scan.get("status") or "").lower()
    if status in {"done", "error"}:
        st.rerun()
        return

    progress = scan.get("progress") or {}
    completed = int(progress.get("completed", 0) or 0)
    total = int(progress.get("total", 0) or 0)
    label = progress.get("label") or "Running scan pipeline"
    rescan_of = workflow.get("rescan_of")
    fraction = min((completed / total), 1.0) if total else 0.0

    st.info(f"Pipeline session `{run_id}` is running in the background.")
    if rescan_of:
        st.caption(f"Rescan of `{rescan_of}`")

    st.progress(fraction)
    st.markdown(f"**Status:** {label}")
    st.caption(f"Completed steps: {completed} / {total if total else '?'}")

    logs = scan.get("logs") or []
    with st.expander("Audit Pipeline Execution Logs", expanded=True):
        for item in logs[-120:]:
            st.write(item.get("message", ""))

    st.caption("This scan keeps running even if you switch pages. The progress panel refreshes automatically while it is active.")


def _render_finished_scan(run_id: str, workflow: Dict) -> None:
    scan = workflow.get("scan") or {}
    status = (scan.get("status") or "").lower()
    summary = _load_summary(run_id)
    findings = summary.get("findings", []) if isinstance(summary, dict) else []
    rescan_of = workflow.get("rescan_of")

    if status == "done":
        st.success("Log and results generated successfully!")
        st.markdown(f"Pipeline execution completed. Results mapped into normalized format for session `{run_id}`.")
    else:
        st.error(scan.get("error") or f"Pipeline execution failed for session `{run_id}`.")

    if rescan_of:
        st.caption(f"Rescan of `{rescan_of}`")

    st.caption(f"Total findings: {len(findings)}")

    with st.expander("Audit Pipeline Execution Logs", expanded=False):
        for item in (scan.get("logs") or [])[-200:]:
            st.write(item.get("message", ""))

    if status == "done" and findings:
        st.write("")
        st.markdown("### Next Step")
        next_caption = (
            "This is a post-hardening rescan. Review its findings before moving into comparison."
            if rescan_of else
            "This is the initial scan result. Review the findings before opening the hardening plan."
        )
        st.caption(next_caption)
        button_label = "View Rescan Findings" if rescan_of else "View Findings"
        if st.button(button_label, icon=":material/search:", use_container_width=True, type="primary"):
            go_to("Findings", selected_report=run_id)

    st.write("")
    if st.button("Start Another Scan", icon=":material/refresh:", use_container_width=True):
        st.session_state.audit_focus_run_id = None
        st.session_state.audit_selected = []
        st.session_state.audit_available = load_targets()
        st.session_state.runtime_passwords = {}
        st.session_state.audit_rescan_notice = None
        st.rerun()


def _render_selection(configured_targets: List[Dict], scan_profile: str) -> None:
    avail_targets = st.session_state.audit_available
    sel_targets = st.session_state.audit_selected

    if st.session_state.get("audit_rescan_notice"):
        st.info(
            f"Rescan mode is preloaded from `{st.session_state.audit_rescan_notice}`. "
            "The original targets are already selected below."
        )

    df_avail = pd.DataFrame(avail_targets) if avail_targets else pd.DataFrame(columns=["name", "ip", "platform"])
    df_sel = pd.DataFrame(sel_targets) if sel_targets else pd.DataFrame(columns=["name", "ip", "platform"])
    if not df_avail.empty:
        df_avail = df_avail[["name", "ip", "platform"]]
    if not df_sel.empty:
        df_sel = df_sel[["name", "ip", "platform"]]

    col_avail, col_btns, col_sel = st.columns([4.5, 1, 4.5])

    with col_avail:
        st.markdown("**Available options**")
        if df_avail.empty:
            st.markdown(
                '<div style="height:350px; display:flex; align-items:center; justify-content:center; border:1px solid #333; border-radius:5px; color:#888;">Empty</div>',
                unsafe_allow_html=True,
            )
            avail_idx = []
        else:
            event_avail = st.dataframe(
                df_avail,
                hide_index=True,
                on_select="rerun",
                selection_mode="multi-row",
                key="avail_df",
                height=350,
                width="stretch",
            )
            avail_idx = event_avail.selection.rows if hasattr(event_avail, "selection") else []
        st.caption(f"{len(avail_idx)} of {len(avail_targets)} items selected")

    with col_sel:
        st.markdown("**Chosen options**")
        if df_sel.empty:
            st.markdown(
                '<div style="height:350px; display:flex; align-items:center; justify-content:center; border:1px solid #333; border-radius:5px; color:#888;">Empty</div>',
                unsafe_allow_html=True,
            )
            sel_idx = []
        else:
            event_sel = st.dataframe(
                df_sel,
                hide_index=True,
                on_select="rerun",
                selection_mode="multi-row",
                key="sel_df",
                height=350,
                width="stretch",
            )
            sel_idx = event_sel.selection.rows if hasattr(event_sel, "selection") else []
        st.caption(f"{len(sel_idx)} of {len(sel_targets)} items selected")

    with col_btns:
        st.markdown("<div style='height: 70px;'></div>", unsafe_allow_html=True)
        if st.button("Add", icon=":material/chevron_right:", key="add_btn", help="Add target", use_container_width=True, disabled=len(avail_idx) == 0):
            st.session_state.audit_selected.extend([avail_targets[i] for i in avail_idx])
            for i in sorted(avail_idx, reverse=True):
                st.session_state.audit_available.pop(i)
            st.rerun()

        if st.button("Rem", icon=":material/chevron_left:", key="remove_btn", help="Remove target", use_container_width=True, disabled=len(sel_idx) == 0):
            st.session_state.audit_available.extend([sel_targets[i] for i in sel_idx])
            for i in sorted(sel_idx, reverse=True):
                st.session_state.audit_selected.pop(i)
            st.rerun()

    st.write("")
    st.caption(f"Scan profile: {scan_profile} | Internal agent mode: {st.session_state.agent_scan_mode}")

    password_targets = [
        t for t in sel_targets
        if t.get("ssh_auth_type") == "password" and not t.get("ssh_password")
    ]
    if password_targets:
        st.markdown("**Per-run SSH Passwords (not stored)**")
        for pt in password_targets:
            st.session_state.runtime_passwords[pt["name"]] = st.text_input(
                f"Password for {pt['name']} ({pt['ip']})",
                value=st.session_state.runtime_passwords.get(pt["name"], ""),
                type="password",
            )

    if st.button("Initiate Audit Pipeline", type="primary", disabled=(len(sel_targets) == 0), use_container_width=True):
        run_id = StorageManager.create_run()
        actual_run_id = start_scan_job_if_idle(
            run_id,
            sel_targets,
            scan_profile,
            st.session_state.agent_scan_mode,
            runtime_passwords=st.session_state.runtime_passwords,
            rescan_of=st.session_state.get("audit_rescan_notice"),
        )
        st.session_state.audit_focus_run_id = actual_run_id
        st.session_state.audit_rescan_notice = None
        st.rerun()


def render() -> None:
    st.title("Run Audit Pipeline")
    st.markdown(
        "Execute security finding checks against configured infrastructure endpoints. First select and move available "
        "endpoints to the Chosen options list, then execute the pipeline."
    )

    targets = load_targets()
    app_settings = load_settings()
    scan_profile = app_settings.get("scan_profile", "standards_mode")

    if not targets:
        st.warning("No targets configured. Please add targets in the Target Management menu.")
        return

    _ensure_selection_state(targets, scan_profile)

    pending_request = st.session_state.pop("scan_request", None)
    if pending_request:
        _start_requested_scan(pending_request, targets, scan_profile)
        st.rerun()

    active = find_active_run("scan")
    if active:
        st.session_state.audit_focus_run_id = active.get("run_id")
        _render_active_scan(active)
        return

    focus_run_id = st.session_state.get("audit_focus_run_id")
    if focus_run_id:
        workflow = load_workflow(focus_run_id)
        scan_status = ((workflow.get("scan") or {}).get("status") or "").lower()
        if scan_status in {"done", "error"}:
            _render_finished_scan(focus_run_id, workflow)
            return

    _render_selection(targets, scan_profile)

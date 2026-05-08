"""
Hardening workflow page backed by persisted run workflow state.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
import yaml
from st_aggrid import AgGrid, DataReturnMode, GridOptionsBuilder, GridUpdateMode, JsCode

from core.background_jobs import start_hardening_job
from core.hardening import REGISTRY, _is_meta_result, classify_findings, deduplicate_tags
from core.workflow import find_active_run, list_workflows, load_workflow
from ui.navigation import go_to
from ui.report_utils import coerce_grid_dataframe

_SEVERITY_ORDER = {"HIGH": 0, "CRITICAL": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rules.yaml")

_rules_cache: list | None = None


def _load_rules() -> list:
    global _rules_cache
    if _rules_cache is None:
        try:
            with open(RULES_PATH, encoding="utf-8") as fh:
                _rules_cache = yaml.safe_load(fh) or []
        except Exception:
            _rules_cache = []
    return _rules_cache


def _directive_for_rule(rule_id: str) -> str:
    for rule in _load_rules():
        if rule.get("rule_id") == rule_id:
            return rule.get("remediation", {}).get("directive", "")
    return ""


def _get_available_runs() -> List[str]:
    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        return []
    runs = [name for name in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, name))]
    runs.sort(key=lambda item: os.path.getmtime(os.path.join(runs_dir, item)), reverse=True)
    return runs


def _parse_run_date(run_id: str) -> str:
    try:
        if run_id.startswith("run_"):
            parts = run_id.split("_")
            if len(parts) >= 3:
                dt = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
                return dt.strftime("%a %b %d %H:%M:%S %Y")
    except Exception:
        pass
    run_path = os.path.join("runs", run_id)
    if os.path.exists(run_path):
        return datetime.fromtimestamp(os.path.getmtime(run_path)).strftime("%a %b %d %H:%M:%S %Y")
    return "Unknown"


def _load_summary(run_id: str) -> Dict[str, Any]:
    summary_path = os.path.join("runs", run_id, "summary.json")
    if not os.path.exists(summary_path):
        return {}
    try:
        with open(summary_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_findings(run_id: str) -> List[dict]:
    return _load_summary(run_id).get("findings", [])


def _load_hardening_report(run_id: str) -> Optional[dict]:
    report_path = os.path.join("runs", run_id, "hardening", "hardening_report.json")
    if not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _run_target_names(run_id: str) -> List[str]:
    workflow = load_workflow(run_id)
    workflow_targets = workflow.get("targets") or []
    names = [target.get("name") for target in workflow_targets if target.get("name")]
    if names:
        return names

    findings = _load_findings(run_id)
    seen = set()
    resolved: List[str] = []
    for finding in findings:
        target = finding.get("target") or {}
        name = target.get("name")
        if name and name not in seen:
            seen.add(name)
            resolved.append(name)
    return resolved


def _scan_status_for_run(run_id: str, workflow: Dict[str, Any]) -> str:
    status = ((workflow.get("scan") or {}).get("status") or "").lower()
    if status:
        return status
    return "done" if _load_findings(run_id) else "unknown"


def _hardening_status_for_run(run_id: str, workflow: Dict[str, Any]) -> str:
    status = ((workflow.get("hardening") or {}).get("status") or "").lower()
    if status:
        return status
    return "done" if _load_hardening_report(run_id) else "idle"


def _latest_completed_rescan(run_id: str) -> Optional[str]:
    matches: List[Dict[str, Any]] = []
    for workflow in list_workflows():
        if workflow.get("rescan_of") != run_id:
            continue
        scan = workflow.get("scan") or {}
        if (scan.get("status") or "").lower() != "done":
            continue
        matches.append(workflow)
    if not matches:
        return None
    matches.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return matches[0].get("run_id")


def _queue_rescan(run_id: str) -> None:
    target_names = _run_target_names(run_id)
    if not target_names:
        st.warning("This run does not contain enough target metadata to start a rescan.")
        return
    st.session_state.scan_request = {"target_names": target_names, "rescan_of": run_id}
    go_to("Scan")


def _report_rows(report: dict) -> pd.DataFrame:
    rows: List[dict] = []
    for target_name, target_data in (report.get("targets") or {}).items():
        for result in target_data.get("results", []):
            if _is_meta_result(str(result.get("tag", ""))):
                continue
            details = []
            for step in result.get("steps", []):
                details.append(f"[{step.get('status', '').upper()}] {step.get('step', '')}")
                if step.get("stderr"):
                    details.append(f"stderr: {step['stderr']}")
            rows.append({
                "Target": target_name,
                "Task": result.get("name", ""),
                "Tag": result.get("tag", ""),
                "Status": str(result.get("status", "")).upper(),
                "details": "\n".join(details).strip(),
            })
    return pd.DataFrame(rows)


def _build_grid_rows(classified: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    rows: List[dict] = []

    for target_name, buckets in classified.items():
        platform = buckets["platform"]

        for item in buckets["auto"]:
            finding = item["finding"]
            tag = item["tag"]
            entry = item.get("entry") or REGISTRY.get(tag, {})
            rule_id = finding.get("rule_id", "")
            steps_text = "\n".join(f"$ {step['cmd']}" for step in entry.get("steps", []))
            rows.append({
                "Target": target_name,
                "Platform": platform,
                "Severity": (finding.get("severity") or "INFO").upper(),
                "Type": "AUTO",
                "Task": entry.get("name", tag),
                "Rule": rule_id,
                "Tag": tag,
                "directive": _directive_for_rule(rule_id) or entry.get("name", ""),
                "steps": steps_text or "No commands",
                "note": "",
                "title": finding.get("title", ""),
                "sev_order": _SEVERITY_ORDER.get((finding.get("severity") or "INFO").upper(), 3),
            })

        for item in buckets["manual"]:
            finding = item["finding"]
            tag = item["tag"]
            entry = item.get("entry") or REGISTRY.get(tag, {})
            rule_id = finding.get("rule_id", "")
            rows.append({
                "Target": target_name,
                "Platform": platform,
                "Severity": (finding.get("severity") or "INFO").upper(),
                "Type": "MANUAL",
                "Task": entry.get("name", tag),
                "Rule": rule_id,
                "Tag": tag,
                "directive": _directive_for_rule(rule_id) or entry.get("name", ""),
                "steps": "",
                "note": entry.get("note", item.get("note", "")),
                "title": finding.get("title", ""),
                "sev_order": _SEVERITY_ORDER.get((finding.get("severity") or "INFO").upper(), 3),
            })

        for item in buckets["pass"]:
            finding = item["finding"]
            rule_id = finding.get("rule_id", "")
            rows.append({
                "Target": target_name,
                "Platform": platform,
                "Severity": (finding.get("severity") or "INFO").upper(),
                "Type": "PASS",
                "Task": finding.get("title", rule_id),
                "Rule": rule_id,
                "Tag": item.get("tag", ""),
                "directive": _directive_for_rule(rule_id) or "Already compliant",
                "steps": "",
                "note": "This check is already passing. No action required.",
                "title": finding.get("title", ""),
                "sev_order": _SEVERITY_ORDER.get((finding.get("severity") or "INFO").upper(), 3),
            })

        for item in buckets["info"]:
            finding = item["finding"]
            rule_id = finding.get("rule_id", "")
            rows.append({
                "Target": target_name,
                "Platform": platform,
                "Severity": "INFO",
                "Type": "INFO",
                "Task": finding.get("title", rule_id),
                "Rule": rule_id,
                "Tag": item.get("tag", ""),
                "directive": _directive_for_rule(rule_id) or item.get("reason", "Informational"),
                "steps": "",
                "note": item.get("reason", "Informational finding, no automated remediation."),
                "title": finding.get("title", ""),
                "sev_order": 3,
            })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df.sort_values(by=["sev_order", "Target", "Type", "Task"], inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def _render_cards(auto: int, manual: int, passing: int, info: int) -> None:
    card_style = (
        "flex:1;padding:22px 14px;border-radius:6px;color:#fff;text-align:center;"
        "box-shadow:0 3px 8px rgba(0,0,0,.35);"
    )
    num_style = "font-size:36px;font-weight:700;line-height:1;text-shadow:1px 1px 2px rgba(0,0,0,.4);margin:0;"
    label_style = "font-size:14px;text-transform:uppercase;letter-spacing:.8px;padding-top:8px;margin:0;"
    st.markdown(
        f"""
        <div style="display:flex;gap:14px;margin-bottom:8px;">
          <div style="{card_style}background:#0d9488;"><p style="{num_style}">{auto}</p><p style="{label_style}">Auto-fixable</p></div>
          <div style="{card_style}background:#d97706;"><p style="{num_style}">{manual}</p><p style="{label_style}">Manual</p></div>
          <div style="{card_style}background:#6366f1;"><p style="{num_style}">{passing}</p><p style="{label_style}">Passing</p></div>
          <div style="{card_style}background:#64748b;"><p style="{num_style}">{info}</p><p style="{label_style}">Info Only</p></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


_detail_renderer = JsCode(
    """
    class DetailCellRenderer {
      init(params) {
        this.eGui = document.createElement('div');
        this.eGui.style.padding = '20px';
        this.eGui.style.maxHeight = '280px';
        this.eGui.style.overflowY = 'auto';
        this.eGui.style.backgroundColor = '#1e1e1e';
        this.eGui.style.border = '1px solid #333';
        this.eGui.style.borderRadius = '5px';
        this.eGui.style.margin = '10px';
        this.eGui.style.fontFamily = 'sans-serif';
        this.eGui.style.color = '#e0e0e0';

        var d = params.data;
        var type = d.Type || '';
        var directive = d.directive || '';
        var steps = d.steps || '';
        var note = d.note || '';
        var tag = d.Tag || '';
        var rule = d.Rule || '';

        var leftHtml = '';
        var rightHtml = '';

        leftHtml += '<h4 style="margin-top:0;color:#fff;font-size:15px;">Remediation Directive</h4>';
        leftHtml += '<div style="background:rgba(124,58,237,0.12);padding:10px;border-radius:4px;border-left:3px solid #7c3aed;color:#c4b5fd;font-size:14px;">' + directive + '</div>';

        if (rule) {
          leftHtml += '<p style="font-size:12px;color:#888;margin-top:8px;">Rule: <span style="color:#a5b4fc;">' + rule + '</span></p>';
        }
        if (tag) {
          leftHtml += '<p style="font-size:12px;color:#888;margin-top:2px;">Ansible tag: <code style="color:#a5b4fc;">' + tag + '</code></p>';
        }

        if (type === 'AUTO' && steps) {
          rightHtml += '<h4 style="margin-top:0;color:#fff;font-size:15px;">Commands</h4>';
          rightHtml += '<pre style="background:#0e1117;padding:10px;border-radius:4px;font-size:12px;color:#ccc;max-height:180px;overflow:auto;white-space:pre-wrap;">' + steps + '</pre>';
        } else if (type === 'MANUAL' && note) {
          rightHtml += '<h4 style="margin-top:0;color:#fff;font-size:15px;">Manual Steps</h4>';
          rightHtml += '<div style="background:#0e1117;padding:10px;border-radius:4px;font-size:13px;color:#ccc;max-height:180px;overflow:auto;white-space:pre-wrap;">' + note + '</div>';
        } else if (type === 'PASS') {
          rightHtml += '<h4 style="margin-top:0;color:#fff;font-size:15px;">Status</h4>';
          rightHtml += '<div style="background:rgba(99,102,241,0.12);padding:10px;border-radius:4px;border-left:3px solid #6366f1;color:#a5b4fc;font-size:14px;">This check is already passing. No remediation needed.</div>';
        } else {
          rightHtml += '<h4 style="margin-top:0;color:#fff;font-size:15px;">Details</h4>';
          rightHtml += '<p style="font-size:13px;color:#aaa;">' + (note || 'No additional information available.') + '</p>';
        }

        this.eGui.innerHTML = '<div style="display:flex;gap:20px;"><div style="flex:1;">' + leftHtml + '</div><div style="flex:1;">' + rightHtml + '</div></div>';
      }
      getGui() { return this.eGui; }
    }
    """
)

_severity_style = JsCode(
    """
    function(params) {
        var sev = params.value;
        if (sev === 'CRITICAL' || sev === 'HIGH') {
            return {'color':'#ff6b6b','backgroundColor':'rgba(217,83,79,0.2)','fontWeight':'bold','whiteSpace':'nowrap'};
        } else if (sev === 'MEDIUM') {
            return {'color':'#f0ad4e','backgroundColor':'rgba(240,173,78,0.2)','fontWeight':'bold','whiteSpace':'nowrap'};
        } else if (sev === 'LOW') {
            return {'color':'#77dd77','backgroundColor':'rgba(119,221,119,0.2)','fontWeight':'bold','whiteSpace':'nowrap'};
        }
        return {'color':'#5bc0de','backgroundColor':'rgba(91,192,222,0.1)','whiteSpace':'nowrap'};
    }
    """
)

_type_style = JsCode(
    """
    function(params) {
        var t = params.value;
        if (t === 'AUTO')   return {'color':'#a78bfa','fontWeight':'600','whiteSpace':'nowrap'};
        if (t === 'MANUAL') return {'color':'#c084fc','whiteSpace':'nowrap'};
        if (t === 'PASS')   return {'color':'#818cf8','whiteSpace':'nowrap'};
        return {'color':'#94a3b8','whiteSpace':'nowrap'};
    }
    """
)

_severity_comparator = JsCode(
    """
    function(valA, valB) {
        var order = {CRITICAL:0, HIGH:0, MEDIUM:1, LOW:2, INFO:3};
        var a = order[valA] !== undefined ? order[valA] : 4;
        var b = order[valB] !== undefined ? order[valB] : 4;
        return a - b;
    }
    """
)

_result_status_style = JsCode(
    """
    function(params) {
        if (params.value === 'OK') return {'color':'#22c55e','fontWeight':'bold','whiteSpace':'nowrap'};
        if (params.value === 'FAILED') return {'color':'#ef4444','fontWeight':'bold','whiteSpace':'nowrap'};
        return {'color':'#94a3b8','fontWeight':'bold','whiteSpace':'nowrap'};
    }
    """
)

_result_detail_renderer = JsCode(
    """
    class DetailCellRenderer {
      init(params) {
        this.eGui = document.createElement('div');
        this.eGui.style.padding = '16px';
        this.eGui.style.backgroundColor = '#1e1e1e';
        this.eGui.style.border = '1px solid #333';
        this.eGui.style.borderRadius = '5px';
        this.eGui.style.margin = '8px';
        this.eGui.style.color = '#e0e0e0';
        this.eGui.innerHTML = '<h4 style="margin-top:0;color:#fff;">Step Details</h4>'
          + '<pre style="background:#0e1117;padding:10px;border-radius:4px;font-size:12px;color:#ccc;white-space:pre-wrap;">'
          + (params.data.details || 'No details') + '</pre>';
      }
      getGui() { return this.eGui; }
    }
    """
)


def _render_plan_grid(df: pd.DataFrame, *, key: str) -> pd.DataFrame:
    visible_cols = ["Severity", "Type", "Target", "Platform", "Task", "Rule"]
    gb = GridOptionsBuilder.from_dataframe(df[visible_cols])
    gb.configure_default_column(
        flex=1,
        wrapText=False,
        autoHeight=False,
        sortable=True,
        filter=True,
        resizable=True,
    )
    gb.configure_grid_options(
        rowHeight=42,
        domLayout="normal",
        masterDetail=True,
        detailRowHeight=300,
        detailCellRenderer=_detail_renderer,
        suppressCellFocus=True,
        suppressRowHoverHighlight=False,
    )
    gb.configure_column(
        "Severity",
        cellRenderer="agGroupCellRenderer",
        cellStyle=_severity_style,
        minWidth=110,
        maxWidth=130,
        sort="asc",
        comparator=_severity_comparator,
    )
    gb.configure_column("Type", cellStyle=_type_style, minWidth=90, maxWidth=110)
    gb.configure_column("Target", minWidth=100, maxWidth=160)
    gb.configure_column("Platform", minWidth=80, maxWidth=120)
    gb.configure_column("Task", minWidth=220, flex=3)
    gb.configure_column("Rule", minWidth=120, maxWidth=200)

    for col in ("directive", "steps", "note", "Tag", "title", "sev_order"):
        gb.configure_column(col, hide=True)

    response = AgGrid(
        df,
        gridOptions=gb.build(),
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        theme="streamlit",
        height=560,
        key=key,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        update_mode=GridUpdateMode.MODEL_CHANGED,
        custom_css={
            ".ag-root-wrapper": {"border": "1px solid #333", "border-radius": "8px"},
            ".ag-header": {"background-color": "#1e1e1e", "border-bottom": "1px solid #333"},
            ".ag-row": {"border-bottom": "1px solid #282828"},
        },
    )
    return coerce_grid_dataframe(response, df)


def _render_results_grid(df: pd.DataFrame, *, key: str) -> None:
    gb = GridOptionsBuilder.from_dataframe(df[["Target", "Task", "Tag", "Status"]])
    gb.configure_default_column(flex=1, wrapText=False, sortable=True, filter=True, resizable=True)
    gb.configure_grid_options(
        rowHeight=42,
        domLayout="normal",
        masterDetail=True,
        detailRowHeight=220,
        detailCellRenderer=_result_detail_renderer,
        suppressCellFocus=True,
    )
    gb.configure_column("Status", cellRenderer="agGroupCellRenderer", cellStyle=_result_status_style, minWidth=90, maxWidth=120)
    gb.configure_column("Task", minWidth=220, flex=3)
    gb.configure_column("Tag", minWidth=140, maxWidth=220)
    gb.configure_column("Target", minWidth=100, maxWidth=160)
    gb.configure_column("details", hide=True)

    AgGrid(
        df,
        gridOptions=gb.build(),
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        theme="streamlit",
        height=440,
        key=key,
        custom_css={
            ".ag-root-wrapper": {"border": "1px solid #333", "border-radius": "8px"},
            ".ag-header": {"background-color": "#1e1e1e", "border-bottom": "1px solid #333"},
            ".ag-row": {"border-bottom": "1px solid #282828"},
        },
    )


def _render_landing() -> None:
    st.title("Hardening")
    st.markdown("Pick a scan session to review the remediation plan, resume an in-flight hardening job, or revisit a completed hardening report.")

    runs = _get_available_runs()
    if not runs:
        st.info("No scan runs found. Execute a scan first.")
        return

    records: List[dict] = []
    for run_id in runs:
        workflow = load_workflow(run_id)
        report = _load_hardening_report(run_id)
        summary = _load_summary(run_id)
        findings = summary.get("findings", [])
        report_summary = (report or {}).get("summary", {})
        records.append({
            "Run Session ID": run_id,
            "Execution Time": _parse_run_date(run_id),
            "Findings": len(findings),
            "Scan": _scan_status_for_run(run_id, workflow).upper(),
            "Hardening": _hardening_status_for_run(run_id, workflow).upper(),
            "Applied": report_summary.get("total_applied", 0),
            "Failed": report_summary.get("total_failed", 0),
            "Manual": report_summary.get("total_manual", 0),
        })

    df_runs = pd.DataFrame(records)
    table_col, action_col = st.columns([7, 3])
    with table_col:
        event = st.dataframe(
            df_runs,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            width="stretch",
        )

    with action_col:
        st.markdown("**Action**")
        if event.selection.rows:
            selected_idx = event.selection.rows[0]
            selected_run_id = df_runs.iloc[selected_idx]["Run Session ID"]
            st.info(f"Selected: **{selected_run_id}**")
            report = _load_hardening_report(selected_run_id)
            primary_label = "View Hardening Report" if report else "Open Hardening Plan"
            if st.button(primary_label, type="primary", use_container_width=True):
                st.session_state.harden_focus_run_id = selected_run_id
                st.rerun()
        else:
            st.warning("Select a run to review or execute hardening.")


def _render_plan(run_id: str, findings: List[dict]) -> None:
    if st.button("Back to All Runs", icon=":material/arrow_back:"):
        st.session_state.harden_focus_run_id = None
        st.rerun()

    st.title("Hardening Plan")
    st.markdown(f"**Scan run:** {run_id}")

    classified = classify_findings(findings)
    total_auto = sum(len(bucket["auto"]) for bucket in classified.values())
    total_manual = sum(len(bucket["manual"]) for bucket in classified.values())
    total_pass = sum(len(bucket["pass"]) for bucket in classified.values())
    total_info = sum(len(bucket["info"]) for bucket in classified.values())

    df = _build_grid_rows(classified)
    if df.empty:
        st.info("No findings are available for this run.")
        return

    cards_placeholder = st.container()
    summary_placeholder = st.container()
    filtered_df = _render_plan_grid(df, key=f"harden_plan_grid_{run_id}")
    visible_df = filtered_df if isinstance(filtered_df, pd.DataFrame) else df

    filtered_auto = int((visible_df["Type"] == "AUTO").sum()) if "Type" in visible_df.columns else 0
    filtered_manual = int((visible_df["Type"] == "MANUAL").sum()) if "Type" in visible_df.columns else 0
    filtered_pass = int((visible_df["Type"] == "PASS").sum()) if "Type" in visible_df.columns else 0
    filtered_info = int((visible_df["Type"] == "INFO").sum()) if "Type" in visible_df.columns else 0
    filtered_targets = int(visible_df["Target"].nunique()) if not visible_df.empty and "Target" in visible_df.columns else 0
    filtered_unique_auto = (
        int(visible_df.loc[visible_df["Type"] == "AUTO"].groupby("Target")["Tag"].nunique().sum())
        if not visible_df.empty and {"Type", "Target", "Tag"}.issubset(visible_df.columns)
        else 0
    )

    with cards_placeholder:
        _render_cards(filtered_auto, filtered_manual, filtered_pass, filtered_info)
        if len(visible_df) != len(df):
            st.caption(f"Cards reflect the current grid filter: {len(visible_df)} of {len(df)} findings visible.")
        else:
            st.caption(f"Cards reflect all {len(df)} findings in this plan.")

    with summary_placeholder:
        st.write("")
        st.markdown(
            f"**{len(visible_df)} findings** across **{filtered_targets} targets** are currently visible in the filtered table. Expand a row to inspect the mapped remediation details."
        )

    auto_tags_per_target: Dict[str, List[str]] = {}
    for target_name, buckets in classified.items():
        tags = deduplicate_tags(buckets["auto"])
        if tags:
            auto_tags_per_target[target_name] = tags
    unique_task_count = sum(len(tags) for tags in auto_tags_per_target.values())

    st.write("")
    st.markdown("### Next Step")
    action_label = "Execute Auto-Remediation" if total_auto > 0 else "Generate Hardening Report"
    if st.button(action_label, type="primary", use_container_width=True):
        start_hardening_job(run_id)
        st.session_state.harden_focus_run_id = run_id
        st.rerun()

    if total_auto > 0:
        st.caption(
            f"Full plan: {total_auto} auto-fixable findings map to {unique_task_count} unique remediation tasks across "
            f"{len(auto_tags_per_target)} targets. Current filter shows {filtered_auto} auto findings mapped to {filtered_unique_auto} tasks."
        )
    if total_manual > 0:
        st.info(
            f"{total_manual} findings still require manual remediation. The MANUAL rows above keep the guidance with the finding."
        )


def _render_active_hardening(workflow: Dict[str, Any]) -> None:
    _render_active_hardening_fragment(workflow.get("run_id", ""))


@st.fragment(run_every=2.0)
def _render_active_hardening_fragment(run_id: str) -> None:
    workflow = load_workflow(run_id)
    run_id = workflow.get("run_id", "")
    hardening = workflow.get("hardening") or {}
    status = (hardening.get("status") or "").lower()
    if status in {"done", "error"}:
        st.rerun()
        return

    progress = hardening.get("progress") or {}
    completed = int(progress.get("completed", 0) or 0)
    total = int(progress.get("total", 0) or 0)
    label = progress.get("label") or "Running hardening"
    fraction = min(completed / total, 1.0) if total else 0.0

    st.title("Executing Hardening")
    st.markdown(f"**Run:** {run_id}")
    st.info("This hardening job is running in the background and will keep going even if you change pages or refresh.")
    st.progress(fraction)
    st.markdown(f"**Status:** {label}")
    st.caption(f"Completed steps: {completed} / {total if total else '?'}")

    findings = _load_findings(run_id)
    if findings:
        classified = classify_findings(findings)
        total_auto = sum(len(bucket["auto"]) for bucket in classified.values())
        total_manual = sum(len(bucket["manual"]) for bucket in classified.values())
        st.caption(f"Plan context: {total_auto} auto-fixable findings and {total_manual} manual findings in this run.")

    with st.expander("Hardening Execution Logs", expanded=True):
        for item in (hardening.get("logs") or [])[-120:]:
            st.write(item.get("message", ""))

    if st.button("Back to All Runs", icon=":material/list:", use_container_width=True):
        st.session_state.harden_focus_run_id = None
        st.rerun()


def _render_report(run_id: str, workflow: Dict[str, Any], report: Optional[dict]) -> None:
    hardening = workflow.get("hardening") or {}
    status = ((hardening.get("status") or "") or ("done" if report else "idle")).lower()
    latest_rescan = _latest_completed_rescan(run_id)

    if st.button("Back to All Runs", icon=":material/arrow_back:"):
        st.session_state.harden_focus_run_id = None
        st.rerun()

    st.title("Hardening Results")
    st.markdown(f"**Run:** {run_id}")

    if status == "error":
        st.error(hardening.get("error") or "Hardening failed for this run.")
    elif report:
        st.success("Hardening report generated successfully.")
    else:
        st.warning("No hardening report is available for this run yet.")

    if report:
        summary = report.get("summary", {})
        col1, col2, col3 = st.columns(3)
        col1.metric("Applied", summary.get("total_applied", 0))
        col2.metric("Failed", summary.get("total_failed", 0))
        col3.metric("Manual", summary.get("total_manual", 0))

    st.write("")
    st.markdown("### Next Step")
    if status == "error" and not report:
        st.caption("Hardening did not complete successfully, so the next step is to retry the hardening run.")
        if st.button("Retry Hardening", icon=":material/play_arrow:", type="primary", use_container_width=True):
            start_hardening_job(run_id)
            st.rerun()
    elif latest_rescan:
        st.caption("A rescan already exists for this hardening session, so the next step is to compare the before and after scans.")
        if st.button("Compare Runs", icon=":material/compare_arrows:", type="primary", use_container_width=True):
            go_to("Compare", compare_left_run=run_id, compare_right_run=latest_rescan)
    else:
        st.caption("The next step after hardening is to rescan the same targets and validate what changed.")
        if st.button("Rescan Same Targets", icon=":material/refresh:", type="primary", use_container_width=True):
            _queue_rescan(run_id)

    if latest_rescan:
        st.caption(f"Latest completed rescan: {latest_rescan}")

    logs = hardening.get("logs") or []
    if logs:
        with st.expander("Hardening Execution Logs", expanded=(status == "error")):
            for item in logs[-160:]:
                st.write(item.get("message", ""))

    if report:
        results_df = _report_rows(report)
        if not results_df.empty:
            _render_results_grid(results_df, key=f"harden_results_grid_{run_id}")

        hardening_dir = Path("runs") / run_id / "hardening"
        json_path = hardening_dir / "hardening_report.json"
        html_path = hardening_dir / "hardening_report.html"
        down_col1, down_col2 = st.columns(2)
        if json_path.exists():
            with open(json_path, "rb") as fh:
                down_col1.download_button(
                    "Download JSON Report",
                    fh.read(),
                    file_name=f"{run_id}_hardening_report.json",
                    mime="application/json",
                    use_container_width=True,
                )
        if html_path.exists():
            with open(html_path, "rb") as fh:
                down_col2.download_button(
                    "Download HTML Report",
                    fh.read(),
                    file_name=f"{run_id}_hardening_report.html",
                    mime="text/html",
                    use_container_width=True,
                )


def render() -> None:
    requested_run_id = st.session_state.pop("harden_open_run", None)
    if requested_run_id:
        st.session_state.harden_focus_run_id = requested_run_id

    active = find_active_run("hardening")
    if active:
        st.session_state.harden_focus_run_id = active.get("run_id")
        _render_active_hardening(active)
        return

    focus_run_id = st.session_state.get("harden_focus_run_id")
    if focus_run_id:
        workflow = load_workflow(focus_run_id)
        report = _load_hardening_report(focus_run_id)
        hardening_status = _hardening_status_for_run(focus_run_id, workflow)
        findings = _load_findings(focus_run_id)

        if hardening_status in {"done", "error"} or report:
            _render_report(focus_run_id, workflow, report)
            return

        if findings:
            _render_plan(focus_run_id, findings)
            return

        st.title("Hardening")
        st.warning("This run does not contain normalized findings yet, so no hardening plan can be built from it.")
        if st.button("Back to All Runs", icon=":material/arrow_back:"):
            st.session_state.harden_focus_run_id = None
            st.rerun()
        return

    _render_landing()

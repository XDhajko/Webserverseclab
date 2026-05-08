import json
import os
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from st_aggrid import AgGrid, DataReturnMode, GridOptionsBuilder, GridUpdateMode, JsCode

from core.hardening import classify_findings
from core.workflow import list_workflows, load_workflow

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _append_unique(values: List[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _step_commands(entry: Dict[str, Any]) -> str:
    lines: List[str] = []
    for step in entry.get("steps", []) or []:
        cmd = str(step.get("cmd", "")).strip()
        if cmd:
            lines.append(f"$ {cmd}")
    return "\n\n".join(lines)


def _remediation_lookup(findings: List[dict]) -> Dict[int, Dict[str, str]]:
    lookup: Dict[int, Dict[str, str]] = {}
    if not findings:
        return lookup

    classified = classify_findings(findings)
    for buckets in classified.values():
        for item in buckets.get("auto", []):
            finding = item.get("finding")
            if not isinstance(finding, dict):
                continue
            info = lookup.setdefault(id(finding), {
                "type": "AUTO",
                "tasks": [],
                "tags": [],
                "manual_guidance": [],
                "auto_steps": [],
                "note": "This finding is mapped to the automated hardening workflow.",
            })
            _append_unique(info["tasks"], str((item.get("entry") or {}).get("name") or item.get("tag") or "Automated remediation"))
            _append_unique(info["tags"], str(item.get("tag") or ""))
            commands = _step_commands(item.get("entry") or {})
            if commands:
                _append_unique(info["auto_steps"], commands)

        for item in buckets.get("manual", []):
            finding = item.get("finding")
            if not isinstance(finding, dict):
                continue
            info = lookup.setdefault(id(finding), {
                "type": "MANUAL",
                "tasks": [],
                "tags": [],
                "manual_guidance": [],
                "auto_steps": [],
                "note": "This finding requires a manual remediation step.",
            })
            info["type"] = "MANUAL"
            _append_unique(info["tasks"], str((item.get("entry") or {}).get("name") or item.get("tag") or "Manual remediation"))
            _append_unique(info["tags"], str(item.get("tag") or ""))
            note = str(item.get("note") or (item.get("entry") or {}).get("note") or "").strip()
            if note:
                _append_unique(info["manual_guidance"], note)

        for item in buckets.get("pass", []):
            finding = item.get("finding")
            if not isinstance(finding, dict):
                continue
            lookup.setdefault(id(finding), {
                "type": "PASS",
                "tasks": ["Already compliant"],
                "tags": [],
                "manual_guidance": [],
                "auto_steps": [],
                "note": "This check is already passing. No remediation is required.",
            })

        for item in buckets.get("info", []):
            finding = item.get("finding")
            if not isinstance(finding, dict):
                continue
            reason = str(item.get("reason") or "Informational finding with no mapped remediation.").strip()
            lookup.setdefault(id(finding), {
                "type": "INFO",
                "tasks": ["Informational only"],
                "tags": [],
                "manual_guidance": [],
                "auto_steps": [],
                "note": reason,
            })

    return {
        key: {
            "type": value["type"],
            "label": ", ".join(value["tasks"]) if value["tasks"] else value["type"].title(),
            "tags": ", ".join(value["tags"]),
            "manual_guidance": "\n\n".join(value["manual_guidance"]),
            "auto_steps": "\n\n".join(value["auto_steps"]),
            "note": value["note"],
        }
        for key, value in lookup.items()
    }


def get_available_runs() -> List[str]:
    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        return []
    runs = [name for name in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, name))]
    runs.sort(key=lambda item: os.path.getmtime(os.path.join(runs_dir, item)), reverse=True)
    return runs


def load_run_summary(run_id: str) -> Dict[str, Any]:
    summary_path = os.path.join("runs", run_id, "summary.json")
    if not os.path.exists(summary_path):
        return {}
    try:
        with open(summary_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_run_findings(run_id: str) -> List[dict]:
    return load_run_summary(run_id).get("findings", [])


def parse_run_date(run_id: str) -> str:
    try:
        if run_id.startswith("run_"):
            parts = run_id.split("_")
            if len(parts) >= 3:
                date_str = parts[1]
                time_str = parts[2]
                dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                return dt.strftime("%a %b %d %H:%M:%S %Y")
        if run_id.startswith("RUN-"):
            ts = int(run_id.split("-")[1])
            return datetime.fromtimestamp(ts).strftime("%a %b %d %H:%M:%S %Y")
    except Exception:
        pass

    run_path = os.path.join("runs", run_id)
    if os.path.exists(run_path):
        return datetime.fromtimestamp(os.path.getmtime(run_path)).strftime("%a %b %d %H:%M:%S %Y")
    return "Unknown"


def recommended_compare_pair(run_id: str) -> Tuple[Optional[str], Optional[str]]:
    workflow = load_workflow(run_id)
    rescan_of = workflow.get("rescan_of")
    if rescan_of:
        return rescan_of, run_id

    matches: List[Dict[str, Any]] = []
    for item in list_workflows():
        if item.get("rescan_of") != run_id:
            continue
        scan = item.get("scan") or {}
        if (scan.get("status") or "").lower() != "done":
            continue
        matches.append(item)
    if not matches:
        return None, None
    matches.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return run_id, matches[0].get("run_id")


def build_findings_dataframe(findings: List[dict]) -> pd.DataFrame:
    if not findings:
        return pd.DataFrame()

    remediation_lookup = _remediation_lookup(findings)
    df = pd.DataFrame(findings)
    df["target_name"] = df["target"].apply(lambda x: x.get("name", "Unknown") if isinstance(x, dict) else "Unknown")
    df["server_type"] = df.get("server_type", pd.Series(index=df.index)).fillna(
        df["target"].apply(lambda x: x.get("platform", "unknown") if isinstance(x, dict) else "unknown")
    )
    df["severity"] = df["severity"].fillna("INFO").str.upper()

    if "wstg_id" not in df.columns:
        df["wstg_id"] = None
    if "cwe_id" not in df.columns:
        df["cwe_id"] = None
    if "cvss" not in df.columns:
        df["cvss"] = None
    if "cve_list" not in df.columns:
        df["cve_list"] = [[] for _ in range(len(df))]
    if "recommendation" not in df.columns:
        df["recommendation"] = ""
    if "description" not in df.columns:
        df["description"] = ""
    if "category" not in df.columns:
        df["category"] = ""
    if "source" not in df.columns:
        df["source"] = ""
    if "rule_id" not in df.columns:
        df["rule_id"] = ""
    if "ansible" not in df.columns:
        df["ansible"] = [{} for _ in range(len(df))]
    if "evidence" not in df.columns:
        df["evidence"] = [{} for _ in range(len(df))]

    detail_df = df.copy()
    detail_df["remediation"] = detail_df.apply(
        lambda row: remediation_lookup.get(
            id(findings[row.name]),
            {"type": "INFO", "label": "Informational only", "tags": "", "manual_guidance": "", "auto_steps": "", "note": "No remediation mapping available."},
        ),
        axis=1,
    )
    detail_df["observed"] = detail_df["evidence"].apply(
        lambda x: x.get("observed", "No explicit trace captured.") if isinstance(x, dict) else "No explicit trace captured."
    )
    detail_df["raw_path"] = detail_df["evidence"].apply(
        lambda x: os.path.basename(x.get("raw_path", "unknown")) if isinstance(x, dict) else "unknown"
    )
    detail_df["tags"] = detail_df["ansible"].apply(
        lambda x: ", ".join(x.get("tags", [])) if isinstance(x, dict) else ""
    )
    detail_df["CVEs"] = detail_df["cve_list"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) and x else "N/A"
    )
    detail_df["WSTG"] = detail_df["wstg_id"].fillna("N/A")
    detail_df["CWE"] = detail_df["cwe_id"].fillna("N/A")
    detail_df["Fix"] = detail_df["remediation"].apply(lambda value: value.get("type", "INFO"))
    detail_df["remediation_label"] = detail_df["remediation"].apply(lambda value: value.get("label", "Informational only"))
    detail_df["remediation_tags"] = detail_df["remediation"].apply(lambda value: value.get("tags", ""))
    detail_df["manual_guidance"] = detail_df["remediation"].apply(lambda value: value.get("manual_guidance", ""))
    detail_df["auto_steps"] = detail_df["remediation"].apply(lambda value: value.get("auto_steps", ""))
    detail_df["remediation_note"] = detail_df["remediation"].apply(lambda value: value.get("note", ""))
    detail_df["CVSS"] = pd.to_numeric(detail_df["cvss"], errors="coerce")
    detail_df["CVSS_display"] = detail_df["CVSS"].apply(lambda value: "" if pd.isna(value) else f"{value:.1f}")
    detail_df["sev_order"] = detail_df["severity"].apply(lambda sev: SEVERITY_ORDER.get(str(sev).upper(), 4))

    display_df = pd.DataFrame({
        "Severity": detail_df["severity"],
        "Host": detail_df["target_name"],
        "Server": detail_df["server_type"].fillna("unknown"),
        "Finding": detail_df["title"].fillna(""),
        "Category": detail_df["category"].fillna(""),
        "Rule ID": detail_df["rule_id"].fillna(""),
        "Source": detail_df["source"].fillna(""),
        "Fix": detail_df["Fix"],
        "WSTG": detail_df["WSTG"],
        "CWE": detail_df["CWE"],
        "CVSS": detail_df["CVSS_display"],
        "description": detail_df["description"].fillna(""),
        "observed": detail_df["observed"].fillna(""),
        "recommendation": detail_df["recommendation"].fillna("Apply standard hardening rules."),
        "raw_path": detail_df["raw_path"].fillna("unknown"),
        "tags": detail_df["tags"].fillna(""),
        "remediation_label": detail_df["remediation_label"].fillna("Informational only"),
        "remediation_tags": detail_df["remediation_tags"].fillna(""),
        "manual_guidance": detail_df["manual_guidance"].fillna(""),
        "auto_steps": detail_df["auto_steps"].fillna(""),
        "remediation_note": detail_df["remediation_note"].fillna(""),
        "CVEs": detail_df["CVEs"],
        "cvss_numeric": detail_df["CVSS"],
        "sev_order": detail_df["sev_order"],
    })

    display_df.sort_values(by=["sev_order", "Host", "Rule ID", "Finding"], inplace=True)
    display_df.reset_index(drop=True, inplace=True)
    return display_df


def findings_summary(display_df: pd.DataFrame) -> Dict[str, int]:
    counts = display_df["Severity"].value_counts() if not display_df.empty else {}
    return {
        "high": int(counts.get("CRITICAL", 0) + counts.get("HIGH", 0)),
        "medium": int(counts.get("MEDIUM", 0)),
        "low": int(counts.get("LOW", 0)),
        "info": int(counts.get("INFO", 0)),
    }


def build_host_summary(display_df: pd.DataFrame) -> pd.DataFrame:
    if display_df.empty:
        return pd.DataFrame(columns=["Host", "High", "Medium", "Low", "Info", "Total Logs"])

    host_summary = pd.crosstab(display_df["Host"], display_df["Severity"]).reset_index()
    for col in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if col not in host_summary.columns:
            host_summary[col] = 0
    host_summary["High"] = host_summary["CRITICAL"] + host_summary["HIGH"]
    display = host_summary[["Host", "High", "MEDIUM", "LOW", "INFO"]].copy()
    display.columns = ["Host", "High", "Medium", "Low", "Info"]
    display["Total Logs"] = display["High"] + display["Medium"] + display["Low"] + display["Info"]
    display.sort_values(by=["High", "Medium", "Low", "Info", "Host"], ascending=[False, False, False, False, True], inplace=True)
    display.reset_index(drop=True, inplace=True)
    return display


def coerce_grid_dataframe(grid_response: Any, fallback_df: pd.DataFrame) -> pd.DataFrame:
    data = None
    if isinstance(grid_response, Mapping):
        data = grid_response.get("data")
    elif hasattr(grid_response, "data"):
        data = getattr(grid_response, "data")

    if isinstance(data, pd.DataFrame):
        result = data.copy()
    elif isinstance(data, list):
        result = pd.DataFrame(data)
    else:
        return fallback_df.copy()

    if result.empty:
        return fallback_df.iloc[0:0].copy()

    for col in fallback_df.columns:
        if col not in result.columns:
            result[col] = None
    result = result.reindex(columns=fallback_df.columns)
    return result.reset_index(drop=True)


def compare_findings(base_df: pd.DataFrame, other_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    def key_for_row(row: pd.Series) -> Tuple[str, str]:
        rule = row.get("Rule ID") or row.get("Finding") or ""
        return str(row.get("Host", "")), str(rule)

    base_map = {key_for_row(row): row for _, row in base_df.iterrows()}
    other_map = {key_for_row(row): row for _, row in other_df.iterrows()}

    resolved_keys = [key for key in base_map if key not in other_map]
    remaining_keys = [key for key in base_map if key in other_map]
    new_keys = [key for key in other_map if key not in base_map]

    def frame_from_keys(keys: List[Tuple[str, str]], source: Dict[Tuple[str, str], pd.Series]) -> pd.DataFrame:
        if not keys:
            return pd.DataFrame(columns=["Severity", "Host", "Finding", "Rule ID", "Source"])
        rows = [source[key] for key in keys]
        df = pd.DataFrame(rows)
        cols = [col for col in ["Severity", "Host", "Finding", "Rule ID", "Source"] if col in df.columns]
        return df[cols].reset_index(drop=True)

    return {
        "resolved": frame_from_keys(resolved_keys, base_map),
        "remaining": frame_from_keys(remaining_keys, base_map),
        "new": frame_from_keys(new_keys, other_map),
    }


_DETAIL_RENDERER = JsCode(
    """
    class DetailCellRenderer {
      init(params) {
        this.eGui = document.createElement('div');
        this.eGui.style.padding = '20px';
        this.eGui.style.maxHeight = '320px';
        this.eGui.style.overflowY = 'auto';
        this.eGui.style.backgroundColor = '#1e1e1e';
        this.eGui.style.border = '1px solid #333';
        this.eGui.style.borderRadius = '5px';
        this.eGui.style.margin = '10px';
        this.eGui.style.fontFamily = 'sans-serif';
        this.eGui.style.color = '#e0e0e0';

        var data = params.data;
        var fixType = data.Fix || 'INFO';
        var remediationLabel = data.remediation_label || '';
        var remediationTags = data.remediation_tags || '';
        var manualGuidance = data.manual_guidance || '';
        var autoSteps = data.auto_steps || '';
        var remediationNote = data.remediation_note || '';
        var html = `
          <div style="display:flex; flex-direction: row; gap: 20px;">
              <div style="flex:1;">
                  <h4 style="margin-top:0; color:#fff; font-size:16px;">Description</h4>
                  <p style="font-size:14px; color:#aaa;">${data.description || ''}</p>

                  <h4 style="margin-top:10px; color:#fff; font-size:16px;">Observed Evidence</h4>
                  <pre style="background:#0e1117; padding:10px; border-radius:4px; font-size:13px; color:#ccc; max-height:120px; overflow:auto; white-space:pre-wrap;">${data.observed || ''}</pre>
                  <p style="font-size:12px; color:#888;">Extracted from: ${data.raw_path || 'unknown'}</p>
              </div>
              <div style="flex:1;">
                  <h4 style="margin-top:0; color:#fff; font-size:16px;">Remediation Path</h4>
                  <div style="background:rgba(91, 192, 222, 0.1); padding:10px; border-radius:4px; border-left:3px solid #5bc0de; color:#5bc0de;">
                      <strong>${fixType}</strong>${remediationLabel ? ' - ' + remediationLabel : ''}
                  </div>
                  <p style="font-size:13px; color:#aaa; margin-top:10px;">${data.recommendation || remediationNote || ''}</p>
                  ${manualGuidance ? `
                    <h4 style="margin-top:10px; color:#fff; font-size:16px;">Manual Guidance</h4>
                    <div style="background:#0e1117; padding:10px; border-radius:4px; font-size:13px; color:#ccc; max-height:120px; overflow:auto; white-space:pre-wrap;">${manualGuidance}</div>
                  ` : ''}
                  ${autoSteps ? `
                    <h4 style="margin-top:10px; color:#fff; font-size:16px;">Automation Plan</h4>
                    <pre style="background:#0e1117; padding:10px; border-radius:4px; font-size:12px; color:#ccc; max-height:120px; overflow:auto; white-space:pre-wrap;">${autoSteps}</pre>
                  ` : ''}
                  <br/>
                  <h4 style="margin-top:10px; color:#fff; font-size:16px;">Standards Mapping</h4>
                  <p style="font-size:14px; color:#aaa;">WSTG: ${data.WSTG || 'N/A'}<br/>CWE: ${data.CWE || 'N/A'}<br/>CVSS: ${data.CVSS || 'N/A'}<br/>CVEs: ${data.CVEs || 'N/A'}</p>
                  <h4 style="margin-top:10px; color:#fff; font-size:16px;">Target Configuration Tags</h4>
                  <p style="font-size:14px; color:#aaa;">${data.tags ? data.tags : 'None'}</p>
                  <h4 style="margin-top:10px; color:#fff; font-size:16px;">Remediation Tags</h4>
                  <p style="font-size:14px; color:#aaa;">${remediationTags ? remediationTags : 'None'}</p>
              </div>
          </div>
        `;
        this.eGui.innerHTML = html;
      }
      getGui() {
        return this.eGui;
      }
    }
    """
)

_SEVERITY_STYLE = JsCode(
    """
    function(params) {
        var sev = params.value;
        if (sev === 'CRITICAL' || sev === 'HIGH') {
            return {'color': '#ff6b6b', 'backgroundColor': 'rgba(217, 83, 79, 0.2)', 'fontWeight': 'bold'};
        } else if (sev === 'MEDIUM') {
            return {'color': '#f0ad4e', 'backgroundColor': 'rgba(240, 173, 78, 0.2)', 'fontWeight': 'bold'};
        } else if (sev === 'LOW') {
            return {'color': '#77dd77', 'backgroundColor': 'rgba(119, 221, 119, 0.2)', 'fontWeight': 'bold'};
        }
        return {'color': '#5bc0de', 'backgroundColor': 'rgba(91, 192, 222, 0.1)'};
    }
    """
)

_SEVERITY_COMPARATOR = JsCode(
    """
    function(valA, valB) {
        var order = {CRITICAL:0, HIGH:0, MEDIUM:1, LOW:2, INFO:3};
        var a = order[valA] !== undefined ? order[valA] : 4;
        var b = order[valB] !== undefined ? order[valB] : 4;
        return a - b;
    }
    """
)

_FIX_STYLE = JsCode(
    """
    function(params) {
        var value = params.value;
        if (value === 'MANUAL') {
            return {'color': '#f0ad4e', 'backgroundColor': 'rgba(240, 173, 78, 0.18)', 'fontWeight': 'bold'};
        } else if (value === 'AUTO') {
            return {'color': '#4fd1c5', 'backgroundColor': 'rgba(79, 209, 197, 0.16)', 'fontWeight': 'bold'};
        } else if (value === 'PASS') {
            return {'color': '#8b5cf6', 'backgroundColor': 'rgba(139, 92, 246, 0.16)', 'fontWeight': 'bold'};
        }
        return {'color': '#94a3b8', 'backgroundColor': 'rgba(148, 163, 184, 0.12)', 'fontWeight': 'bold'};
    }
    """
)


def render_findings_grid(display_df: pd.DataFrame, *, key: str, height: int = 600) -> pd.DataFrame:
    visible_cols = ["Severity", "Host", "Server", "Finding", "Category", "Rule ID", "Source", "Fix", "WSTG", "CWE", "CVSS"]
    gb = GridOptionsBuilder.from_dataframe(display_df)
    gb.configure_default_column(flex=1, wrapText=True, autoHeight=True, sortable=True, filter=True, resizable=True)
    gb.configure_grid_options(
        rowHeight=45,
        domLayout="normal",
        masterDetail=True,
        detailRowHeight=340,
        detailCellRenderer=_DETAIL_RENDERER,
        suppressCellFocus=True,
        suppressRowHoverHighlight=False,
    )
    gb.configure_column("Severity", cellRenderer="agGroupCellRenderer", cellStyle=_SEVERITY_STYLE, sort="asc", comparator=_SEVERITY_COMPARATOR, minWidth=110, maxWidth=130)
    gb.configure_column("Fix", minWidth=110, maxWidth=130, cellStyle=_FIX_STYLE)
    gb.configure_column("CVSS", minWidth=100, maxWidth=120)
    gb.configure_column("Finding", minWidth=260, flex=3)
    gb.configure_column("Host", minWidth=110, maxWidth=150)
    gb.configure_column("Server", minWidth=110, maxWidth=140)
    gb.configure_column("Category", minWidth=110, maxWidth=160)
    gb.configure_column("Rule ID", minWidth=130, maxWidth=180)
    gb.configure_column("Source", minWidth=110, maxWidth=140)
    gb.configure_column("WSTG", minWidth=110, maxWidth=150)
    gb.configure_column("CWE", minWidth=110, maxWidth=150)

    for col in display_df.columns:
        if col not in visible_cols:
            gb.configure_column(col, hide=True)

    grid_options = gb.build()
    grid_options["columnDefs"] = [col_def for col_def in grid_options.get("columnDefs", []) if col_def.get("field") in display_df.columns]

    response = AgGrid(
        display_df,
        gridOptions=grid_options,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        theme="streamlit",
        height=height,
        key=key,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        update_mode=GridUpdateMode.MODEL_CHANGED,
        custom_css={
            ".ag-root-wrapper": {"border": "1px solid #333333", "border-radius": "8px"},
            ".ag-header": {"background-color": "#1e1e1e", "border-bottom": "1px solid #333333"},
            ".ag-row": {"border-bottom": "1px solid #282828"},
        },
    )
    return coerce_grid_dataframe(response, display_df)

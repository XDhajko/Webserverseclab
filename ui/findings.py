import os

import pandas as pd
import streamlit as st

from core.workflow import load_workflow
from ui.navigation import go_to
from ui.report_utils import (
    build_findings_dataframe,
    findings_summary,
    get_available_runs,
    load_run_summary,
    parse_run_date,
    recommended_compare_pair,
    render_findings_grid,
)


def _render_next_step(run_id: str, workflow: dict, compare_left: str | None, compare_right: str | None) -> None:
    st.write("")
    st.markdown("### Next Step")

    if workflow.get("rescan_of"):
        if compare_left and compare_right:
            st.caption("This is a post-hardening rescan, so the next step is to compare it with the earlier scan.")
            if st.button("Compare With Baseline", icon=":material/compare_arrows:", type="primary", use_container_width=True):
                go_to("Compare", compare_left_run=compare_left, compare_right_run=compare_right)
        else:
            st.info("This run is a rescan. Once a valid baseline pairing is available, the comparison step will appear here.")
        return

    st.caption("This is the initial scan report, so the next step is to open the hardening plan for this run.")
    if st.button("Open Hardening", icon=":material/shield_lock:", type="primary", use_container_width=True):
        go_to("Harden", harden_open_run=run_id)


def render() -> None:
    if "selected_report" not in st.session_state:
        st.session_state.selected_report = None

    if st.session_state.selected_report is None:
        _render_selection_screen()
    else:
        _render_report_screen(st.session_state.selected_report)


def _render_selection_screen() -> None:
    st.title("Findings Reports")
    st.markdown("Select an executed scan session to inspect the normalized findings and move directly into the next hardening step.")

    runs = get_available_runs()
    if not runs:
        st.info("No audit runs discovered. Execute a pipeline first.")
        return

    run_records = []
    for run_id in runs:
        summary = load_run_summary(run_id)
        findings = summary.get("findings", [])
        high_count = sum(1 for item in findings if str(item.get("severity", "")).lower() in {"critical", "high"})
        run_records.append({
            "Run Session ID": run_id,
            "Date Execution": parse_run_date(run_id),
            "Findings": len(findings),
            "High Severity": high_count,
        })

    df_runs = pd.DataFrame(run_records)
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

            if st.button("View Report Details", type="primary", use_container_width=True):
                st.session_state.selected_report = selected_run_id
                st.rerun()
        else:
            st.warning("Select a row in the table to inspect a full findings report.")


def _render_report_screen(run_id: str) -> None:
    if st.button("Back to All Scans", icon=":material/arrow_back:"):
        st.session_state.selected_report = None
        st.rerun()

    summary = load_run_summary(run_id)
    findings = summary.get("findings", []) if isinstance(summary, dict) else []
    workflow = load_workflow(run_id)
    run_date = parse_run_date(run_id)
    compare_left, compare_right = recommended_compare_pair(run_id)
    rescan_of = workflow.get("rescan_of")

    st.title("Audit Findings Report")
    st.markdown(f"**Scan Session:** {run_id}  |  **Execution Timeline:** {run_date}")
    if rescan_of:
        st.caption(f"Rescan of `{rescan_of}`")

    exports = summary.get("exports", {}) if isinstance(summary, dict) else {}
    csv_rel = exports.get("findings_csv")
    html_rel = exports.get("report_print_html")
    report_rel = exports.get("report_json")
    run_dir = os.path.join("runs", run_id)

    if not findings:
        st.success("No findings were recorded for this scan session.")
        return

    display_df = build_findings_dataframe(findings)
    summary_placeholder = st.container()

    st.write("")
    st.markdown("### Findings Detail")
    st.markdown("Use the table column filters and sorting controls directly in the grid. Expand a row to inspect evidence and remediation context.")
    filtered_df = render_findings_grid(display_df, key=f"findings_grid_{run_id}", height=620)
    visible_df = filtered_df if isinstance(filtered_df, pd.DataFrame) else display_df
    summary_counts = findings_summary(visible_df)

    with summary_placeholder:
        st.markdown(
            """
            <style>
               .sev-box { padding: 25px 15px; border-radius: 4px; color: white; text-align: center; height: 100%; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
               .sev-high { background-color: #d9534f; }
               .sev-med { background-color: #f0ad4e; }
               .sev-low { background-color: #77dd77; }
               .sev-info { background-color: #5bc0de; }
               .sev-num { font-size: 40px; font-weight: bold; margin: 0; padding: 0; line-height: 1; text-shadow: 1px 1px 2px rgba(0,0,0,0.5); }
               .sev-label { font-size: 16px; font-weight: 500; text-transform: uppercase; margin: 0; padding-top: 10px; letter-spacing: 1px; }
               .sev-desc { font-size: 14px; color: #bbb; padding: 20px 10px; border-left: 3px solid #555; background: #1e1e1e; border-radius: 0 4px 4px 0; }
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.write("")
        st.markdown("### Summary")
        col1, col2, col3, col4, col5 = st.columns([1.5, 1.5, 1.5, 1.5, 4])
        with col1:
            st.markdown(f'<div class="sev-box sev-high"><p class="sev-num">{summary_counts["high"]}</p><p class="sev-label">High</p></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="sev-box sev-med"><p class="sev-num">{summary_counts["medium"]}</p><p class="sev-label">Medium</p></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="sev-box sev-low"><p class="sev-num">{summary_counts["low"]}</p><p class="sev-label">Low</p></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="sev-box sev-info"><p class="sev-num">{summary_counts["info"]}</p><p class="sev-label">Info</p></div>', unsafe_allow_html=True)
        with col5:
            st.markdown(
                """<div class="sev-desc">
                    Any <span style="color:#d9534f;font-weight:bold;">HIGH</span> and <span style="color:#f0ad4e;font-weight:bold;">MEDIUM</span> severity findings indicate immediate risks from the misconfiguration criteria and should be remediated. <span style="color:#77dd77;font-weight:bold;">LOW</span> and <span style="color:#5bc0de;font-weight:bold;">INFO</span> items are posture warnings that still matter for chaining.
                </div>""",
                unsafe_allow_html=True,
            )

    if csv_rel or html_rel or report_rel:
        st.write("")
        st.markdown("### Report Exports")
        d1, d2, d3 = st.columns(3)
        if csv_rel:
            csv_path = os.path.join(run_dir, csv_rel)
            if os.path.exists(csv_path):
                with open(csv_path, "rb") as fh:
                    d1.download_button("Download CSV", data=fh.read(), file_name=f"{run_id}_findings.csv", mime="text/csv", use_container_width=True)
        if html_rel:
            html_path = os.path.join(run_dir, html_rel)
            if os.path.exists(html_path):
                with open(html_path, "rb") as fh:
                    d2.download_button("Download Print HTML", data=fh.read(), file_name=f"{run_id}_report_print.html", mime="text/html", use_container_width=True)
        if report_rel:
            report_path = os.path.join(run_dir, report_rel)
            if os.path.exists(report_path):
                with open(report_path, "rb") as fh:
                    d3.download_button("Download Report JSON", data=fh.read(), file_name=f"{run_id}_report.json", mime="application/json", use_container_width=True)

    _render_next_step(run_id, workflow, compare_left, compare_right)

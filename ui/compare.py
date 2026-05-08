import streamlit as st

from ui.navigation import go_to
from ui.report_utils import (
    build_findings_dataframe,
    compare_findings,
    findings_summary,
    get_available_runs,
    load_run_findings,
    parse_run_date,
    render_findings_grid,
)


def _default_run(runs, requested, fallback_index):
    if requested in runs:
        return requested
    if not runs:
        return None
    return runs[min(fallback_index, len(runs) - 1)]


def _swap_compare_runs() -> None:
    left = st.session_state.get("compare_left_select")
    right = st.session_state.get("compare_right_select")
    st.session_state.compare_left_select = right
    st.session_state.compare_right_select = left
    st.session_state.compare_left_run = right
    st.session_state.compare_right_run = left


def _render_severity_cards(counts: dict, *, prefix: str) -> None:
    st.markdown(
        f"""
        <style>
           .{prefix}-sev-box {{ padding: 18px 12px; border-radius: 6px; color: white; text-align: center; height: 100%; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
           .{prefix}-sev-high {{ background-color: #d9534f; }}
           .{prefix}-sev-med {{ background-color: #f0ad4e; }}
           .{prefix}-sev-low {{ background-color: #77dd77; }}
           .{prefix}-sev-info {{ background-color: #5bc0de; }}
           .{prefix}-sev-num {{ font-size: 28px; font-weight: bold; margin: 0; line-height: 1; text-shadow: 1px 1px 2px rgba(0,0,0,0.4); }}
           .{prefix}-sev-label {{ font-size: 13px; font-weight: 600; text-transform: uppercase; margin: 0; padding-top: 8px; letter-spacing: 0.8px; }}
        </style>
        """,
        unsafe_allow_html=True,
    )
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f'<div class="{prefix}-sev-box {prefix}-sev-high"><p class="{prefix}-sev-num">{counts["high"]}</p><p class="{prefix}-sev-label">High</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="{prefix}-sev-box {prefix}-sev-med"><p class="{prefix}-sev-num">{counts["medium"]}</p><p class="{prefix}-sev-label">Medium</p></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="{prefix}-sev-box {prefix}-sev-low"><p class="{prefix}-sev-num">{counts["low"]}</p><p class="{prefix}-sev-label">Low</p></div>', unsafe_allow_html=True)
    with col4:
        st.markdown(f'<div class="{prefix}-sev-box {prefix}-sev-info"><p class="{prefix}-sev-num">{counts["info"]}</p><p class="{prefix}-sev-label">Info</p></div>', unsafe_allow_html=True)


def render() -> None:
    st.title("Compare Runs")
    st.markdown("Review two scan sessions side by side, inspect the full finding tables, and expand a row to see auto or manual remediation guidance.")

    runs = get_available_runs()
    if len(runs) < 2:
        st.info("You need at least two scan runs before a comparison can be shown.")
        return

    requested_left = st.session_state.get("compare_left_run")
    requested_right = st.session_state.get("compare_right_run")
    default_left = _default_run(runs, requested_left, 1)
    default_right = _default_run(runs, requested_right, 0)

    selector_col1, selector_col2, selector_col3 = st.columns([4, 4, 1])
    with selector_col1:
        left_run = st.selectbox("Baseline run", runs, index=runs.index(default_left), key="compare_left_select")
    with selector_col2:
        right_run = st.selectbox("Comparison run", runs, index=runs.index(default_right), key="compare_right_select")
    with selector_col3:
        st.write("")
        st.write("")
        st.button("Swap", use_container_width=True, on_click=_swap_compare_runs)

    st.session_state.compare_left_run = left_run
    st.session_state.compare_right_run = right_run

    if left_run == right_run:
        st.warning("Choose two different runs to compare.")
        return

    left_findings = load_run_findings(left_run)
    right_findings = load_run_findings(right_run)
    left_df = build_findings_dataframe(left_findings)
    right_df = build_findings_dataframe(right_findings)

    if left_df.empty and right_df.empty:
        st.info("Neither selected run contains normalized findings yet.")
        return

    delta = compare_findings(left_df, right_df)
    resolved_df = delta["resolved"]
    remaining_df = delta["remaining"]
    new_df = delta["new"]

    st.write("")
    st.markdown("### Comparison Summary")
    st.markdown(
        f"Compared with the baseline run, **{len(resolved_df)}** findings were resolved, "
        f"**{len(remaining_df)}** are still present, and **{len(new_df)}** appeared newly in the later run. "
        "Use the expanded rows in either table to review evidence and any manual remediation guidance that still remains."
    )

    st.write("")
    detail_col1, detail_col2 = st.columns(2)
    with detail_col1:
        st.markdown(f"### {left_run}")
        st.caption(f"Baseline  |  {parse_run_date(left_run)}")
        _render_severity_cards(findings_summary(left_df), prefix="compare-left")
        st.write("")
        render_findings_grid(left_df, key=f"compare_left_grid_{left_run}", height=520)
    with detail_col2:
        st.markdown(f"### {right_run}")
        st.caption(f"Comparison  |  {parse_run_date(right_run)}")
        _render_severity_cards(findings_summary(right_df), prefix="compare-right")
        st.write("")
        render_findings_grid(right_df, key=f"compare_right_grid_{right_run}", height=520)

    action_col1, action_col2 = st.columns(2)
    with action_col1:
        if st.button("Open Baseline Findings", icon=":material/search:", use_container_width=True):
            go_to("Findings", selected_report=left_run)
    with action_col2:
        if st.button("Open Comparison Findings", icon=":material/search:", use_container_width=True):
            go_to("Findings", selected_report=right_run)

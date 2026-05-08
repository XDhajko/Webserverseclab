import streamlit as st
import os
import json
import pandas as pd
import plotly.express as px

def _list_runs():
    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        return []
    runs = [d for d in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, d))]
    runs.sort(key=lambda x: os.path.getmtime(os.path.join(runs_dir, x)), reverse=True)
    return runs


def _load_summary(run_id):
    summary_path = os.path.join("runs", run_id, "summary.json")
    if not os.path.exists(summary_path):
        return {"findings": []}
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"findings": []}


def get_latest_metrics():
    runs = _list_runs()
    if not runs:
        return {
            "targets": 0,
            "high": 0,
            "medium": 0,
            "status": "No runs yet",
            "latest_findings": [],
            "history": [],
        }

    latest_run = runs[0]
    latest_summary = _load_summary(latest_run)
    findings = latest_summary.get("findings", [])

    high_count = 0
    med_count = 0
    targets = set()
    history_rows = []

    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in ["high", "critical"]:
            high_count += 1
        elif sev == "medium":
            med_count += 1
        tgt = f.get("target", {}).get("name")
        if tgt:
            targets.add(tgt)

    for run_id in runs[:12]:
        s = _load_summary(run_id)
        fs = s.get("findings", [])
        history_targets = {x.get("target", {}).get("name") for x in fs if isinstance(x, dict)}
        history_rows.append(
            {
                "Run ID": run_id,
                "Targets": len([t for t in history_targets if t]),
                "Findings": len(fs),
                "Status": "Completed" if fs else "Empty",
            }
        )

    return {
        "targets": len(targets),
        "high": high_count,
        "medium": med_count,
        "status": f"Completed ({latest_run})",
        "latest_findings": findings,
        "history": history_rows,
    }

def render():
    st.title("Security Dashboard")
    st.markdown("Overview of the WebServerSecLab compliance environment.")
    st.write("")

    # High-Level Metrics
    metrics = get_latest_metrics()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        with st.container(border=True, height=130):
            st.metric("Monitored Targets", f"{metrics['targets']}")
    with col2:
        with st.container(border=True, height=130):
            st.metric("High Findings", f"{metrics['high']}")
    with col3:
        with st.container(border=True, height=130):
            st.metric("Medium Findings", f"{metrics['medium']}")
    with col4:
        with st.container(border=True, height=130):
            st.metric("Last Scan Status", metrics['status'])
        
    st.write("")
    
    # Main Content Split inside borders
    main_col1, main_col2 = st.columns([1, 1])
    
    with main_col1:
        with st.container(border=True, height=450):
            st.subheader("Severity Distribution")
            sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in metrics["latest_findings"]:
                sev = str(f.get("severity", "")).lower()
                if sev in ["critical", "high"]:
                    sev_counts["High"] += 1
                elif sev == "medium":
                    sev_counts["Medium"] += 1
                elif sev == "low":
                    sev_counts["Low"] += 1
                else:
                    sev_counts["Info"] += 1

            data = {
                "Severity": ["High", "Medium", "Low", "Info"],
                "Count": [sev_counts["High"], sev_counts["Medium"], sev_counts["Low"], sev_counts["Info"]],
            }
            df_sev = pd.DataFrame(data)
            fig = px.pie(df_sev, names='Severity', values='Count', hole=0.4, 
                         color='Severity', 
                         color_discrete_map={'High':'red', 'Medium':'orange', 'Low':'green', 'Info':'lightblue'})
            # Give margin to the plotly chart so it sits nicely in the container
            fig.update_layout(margin=dict(t=20, b=20, l=10, r=10), height=300)
            st.plotly_chart(fig)

    with main_col2:
        with st.container(border=True, height=450):
            st.subheader("Historical Scans")
            df = pd.DataFrame(metrics["history"])
            # Extra layout spacing for alignment
            st.markdown("<br>", unsafe_allow_html=True)
            st.dataframe(df, hide_index=True, width="stretch")
            st.markdown("<br><br><br><br>", unsafe_allow_html=True)



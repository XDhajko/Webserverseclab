import streamlit as st
import pandas as pd
from core.rules_db import load_rules, RulesDBError
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode


TAB_CATEGORIES = [
    "Information Disclosure",
    "HTTP Behavior",
    "TLS & Transport",
    "Access Control",
    "Logging & Monitoring",
    "Components & Dependencies",
    "Admin Interfaces",
]


def _to_row(rule):
    sev = rule.get("severity", {}) if isinstance(rule.get("severity"), dict) else {}
    detection = rule.get("detection", {}) if isinstance(rule.get("detection"), dict) else {}
    return {
        "Rule ID": rule.get("rule_id", ""),
        "Title": rule.get("title", ""),
        "Server": ", ".join(rule.get("affects", [])),
        "WSTG": rule.get("wstg_id", ""),
        "CWE": rule.get("cwe_id", ""),
        "CVSS Base": sev.get("base_score", "N/A"),
        "Severity": sev.get("rating", ""),
        "Detectable": bool(detection),
        "CVE Dependent": bool(rule.get("cve_dependent", False)),
        "Detection": str(rule.get("detection", {})),
        "Remediation": str(rule.get("remediation", {})),
        "References": "\n".join([str(x) for x in rule.get("references", [])]),
    }


def render():
    st.title("Security Control Catalog")
    st.markdown("Standards-mapped scanning inventory used by the engine.")

    try:
        rules = load_rules("data/rules.yaml")
    except RulesDBError as exc:
        st.error(f"Failed to load rule catalog: {exc}")
        return

    tabs = st.tabs(TAB_CATEGORIES)
    for idx, category in enumerate(TAB_CATEGORIES):
        with tabs[idx]:
            cat_rules = [r for r in rules if r.get("category") == category]
            if not cat_rules:
                st.info("No rules in this category.")
                continue

            df = pd.DataFrame([_to_row(r) for r in cat_rules])

            gb = GridOptionsBuilder.from_dataframe(df[[
                "Rule ID", "Title", "Server", "WSTG", "CWE", "CVSS Base", "Severity", "Detectable", "CVE Dependent"
            ]])
            gb.configure_default_column(flex=1, wrapText=True, autoHeight=True)
            gb.configure_grid_options(
                rowHeight=44,
                domLayout="normal",
                masterDetail=True,
                detailRowHeight=220,
                suppressCellFocus=True,
            )

            detail_cell_renderer = JsCode("""
            class DetailCellRenderer {
              init(params) {
                this.eGui = document.createElement('div');
                this.eGui.style.padding = '16px';
                this.eGui.style.maxHeight = '200px';
                this.eGui.style.overflowY = 'auto';
                this.eGui.style.backgroundColor = '#1e1e1e';
                this.eGui.style.border = '1px solid #333';
                this.eGui.style.borderRadius = '5px';
                this.eGui.style.margin = '8px';
                this.eGui.style.fontFamily = 'sans-serif';
                this.eGui.style.color = '#e0e0e0';

                var data = params.data;
                var html = `
                  <div style="display:flex; gap:18px;">
                    <div style="flex:1;">
                      <h4 style="margin-top:0; color:#fff; font-size:15px;">Detection</h4>
                      <pre style="background:#0e1117; padding:10px; border-radius:4px; font-size:12px; color:#ccc; white-space:pre-wrap;">${data.Detection || ''}</pre>
                      <h4 style="margin-top:10px; color:#fff; font-size:15px;">Remediation</h4>
                      <pre style="background:#0e1117; padding:10px; border-radius:4px; font-size:12px; color:#ccc; white-space:pre-wrap;">${data.Remediation || ''}</pre>
                    </div>
                    <div style="flex:1;">
                      <h4 style="margin-top:0; color:#fff; font-size:15px;">Standards</h4>
                      <p style="font-size:13px; color:#aaa;">WSTG: ${data.WSTG || 'N/A'}<br/>CWE: ${data.CWE || 'N/A'}<br/>CVSS Base: ${data['CVSS Base'] || 'N/A'}</p>
                      <h4 style="margin-top:10px; color:#fff; font-size:15px;">References</h4>
                      <pre style="background:#0e1117; padding:10px; border-radius:4px; font-size:12px; color:#ccc; white-space:pre-wrap;">${data.References || ''}</pre>
                    </div>
                  </div>
                `;
                this.eGui.innerHTML = html;
              }
              getGui() {
                return this.eGui;
              }
            }
            """)

            gb.configure_grid_options(detailCellRenderer=detail_cell_renderer)
            gb.configure_column("Detection", hide=True)
            gb.configure_column("Remediation", hide=True)
            gb.configure_column("References", hide=True)
            gb.configure_column("Rule ID", cellRenderer="agGroupCellRenderer")

            grid_options = gb.build()

            AgGrid(
                df,
                gridOptions=grid_options,
                allow_unsafe_jscode=True,
                enable_enterprise_modules=True,
                theme="streamlit",
                height=520,
            )
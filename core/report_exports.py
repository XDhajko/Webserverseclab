import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List


REPORT_SCHEMA_VERSION = "2.0"


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for finding in findings:
        sev = str(finding.get("severity", "unknown")).lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1
    return counts


def _target_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
        target_name = str(target.get("name", "unknown"))
        counts[target_name] = counts.get(target_name, 0) + 1
    return counts


def build_report_document(
    run_id: str,
    scan_profile: str,
    findings: List[Dict[str, Any]],
    coverage: Dict[str, Any],
) -> Dict[str, Any]:
    generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "security-audit-run",
        "run_id": run_id,
        "scan_id": run_id,
        "scan_profile": scan_profile,
        "generated_at": generated_at,
        "metrics": {
            "total_findings": len(findings),
            "severity": _severity_counts(findings),
            "targets": _target_counts(findings),
        },
        "coverage": coverage,
        "findings": findings,
    }


def _flatten_finding_row(finding: Dict[str, Any]) -> Dict[str, Any]:
    target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
    evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}

    cve_list = finding.get("cve_list")
    if isinstance(cve_list, list):
        cves = ", ".join([str(x) for x in cve_list])
    else:
        cves = ""

    return {
        "run_id": finding.get("run_id", ""),
        "scan_id": finding.get("scan_id", ""),
        "target": target.get("name", ""),
        "target_ip": target.get("ip", ""),
        "server_type": finding.get("server_type", ""),
        "source": finding.get("source", ""),
        "rule_id": finding.get("rule_id", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", ""),
        "status": finding.get("status", ""),
        "check_status": finding.get("check_status", ""),
        "title": finding.get("title", ""),
        "description": finding.get("description", ""),
        "recommendation": finding.get("recommendation", ""),
        "wstg_id": finding.get("wstg_id", ""),
        "cwe_id": finding.get("cwe_id", ""),
        "cvss": finding.get("cvss", ""),
        "cves": cves,
        "evidence_observed": evidence.get("observed", ""),
        "evidence_raw_path": evidence.get("raw_path", ""),
    }


def _write_findings_csv(findings: List[Dict[str, Any]], output_path: str) -> None:
    rows = [_flatten_finding_row(f) for f in findings]
    fieldnames = [
        "run_id",
        "scan_id",
        "target",
        "target_ip",
        "server_type",
        "source",
        "rule_id",
        "category",
        "severity",
        "status",
        "check_status",
        "title",
        "description",
        "recommendation",
        "wstg_id",
        "cwe_id",
        "cvss",
        "cves",
        "evidence_observed",
        "evidence_raw_path",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_print_html(report_doc: Dict[str, Any], output_path: str) -> None:
    run_id = report_doc.get("run_id", "")
    generated_at = report_doc.get("generated_at", "")
    scan_profile = report_doc.get("scan_profile", "")
    total = report_doc.get("metrics", {}).get("total_findings", 0)
    sev = report_doc.get("metrics", {}).get("severity", {})

    html = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>Security Audit Report - {run_id}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #1f2937; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #4b5563; margin-bottom: 18px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 6px; padding: 10px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 6px; vertical-align: top; text-align: left; }}
    th {{ background: #f3f4f6; }}
    .small {{ font-size: 11px; color: #6b7280; }}
    @media print {{ body {{ margin: 10mm; }} }}
  </style>
</head>
<body>
  <h1>Security Audit Report</h1>
  <div class=\"meta\">Run: {run_id} | Profile: {scan_profile} | Generated: {generated_at}</div>

  <div class=\"grid\">
    <div class=\"card\"><strong>Total Findings</strong><div>{total}</div></div>
    <div class=\"card\"><strong>High</strong><div>{sev.get("high", 0)}</div></div>
    <div class=\"card\"><strong>Medium</strong><div>{sev.get("medium", 0)}</div></div>
    <div class=\"card\"><strong>Low</strong><div>{sev.get("low", 0)}</div></div>
    <div class=\"card\"><strong>Info</strong><div>{sev.get("info", 0)}</div></div>
    <div class=\"card\"><strong>Unknown</strong><div>{sev.get("unknown", 0)}</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Target</th>
        <th>Rule</th>
        <th>Title</th>
        <th>WSTG</th>
        <th>CWE</th>
        <th>CVSS</th>
      </tr>
    </thead>
    <tbody>
"""

    for finding in report_doc.get("findings", []):
        target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
        sev_value = str(finding.get("severity", "")).upper()
        html += (
            "      <tr>"
            f"<td>{sev_value}</td>"
            f"<td>{target.get('name', '')}</td>"
            f"<td>{finding.get('rule_id', '')}</td>"
            f"<td>{finding.get('title', '')}</td>"
            f"<td>{finding.get('wstg_id') or ''}</td>"
            f"<td>{finding.get('cwe_id') or ''}</td>"
            f"<td>{finding.get('cvss') or ''}</td>"
            "</tr>\n"
        )

    html += """
    </tbody>
  </table>
  <p class=\"small\">This HTML file is optimized for Print to PDF export.</p>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def write_report_exports(run_path: str, report_doc: Dict[str, Any]) -> Dict[str, str]:
    exports_dir = os.path.join(run_path, "exports")
    os.makedirs(exports_dir, exist_ok=True)

    report_json = os.path.join(exports_dir, "report.json")
    findings_csv = os.path.join(exports_dir, "findings.csv")
    print_html = os.path.join(exports_dir, "report_print.html")

    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(report_doc, f, indent=2)

    _write_findings_csv(report_doc.get("findings", []), findings_csv)
    _write_print_html(report_doc, print_html)

    return {
        "report_json": report_json,
        "findings_csv": findings_csv,
        "report_print_html": print_html,
    }

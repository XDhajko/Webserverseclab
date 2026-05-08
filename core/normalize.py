import os
import json
import xml.etree.ElementTree as ET
import glob
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any
from core.cve_cache import CVECache
from core.rules_db import load_rules, rules_to_map, RulesDBError
from core.report_exports import build_report_document, write_report_exports

class Normalizer:
    """Normalizes raw scanner outputs into a consistent JSON schema."""
    
    def __init__(self, run_id: str, runs_dir: str = "runs", scan_profile: str = "standards_mode"):
        self.run_id = run_id
        self.run_path = os.path.join(runs_dir, run_id)
        self.scan_profile = scan_profile
        self.rule_catalog = self._load_rule_catalog()
        self.cve_cache = CVECache()

    def _load_rule_catalog(self) -> Dict[str, Dict[str, Any]]:
        try:
            return rules_to_map(load_rules("data/rules.yaml"))
        except RulesDBError:
            pass

        catalog_path = os.path.join("config", "rule_catalog.json")
        if not os.path.exists(catalog_path):
            return {}
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules", []) if isinstance(data, dict) else []
            return {r.get("rule_id", ""): r for r in rules if isinstance(r, dict) and r.get("rule_id")}
        except Exception:
            return {}

    def _get_rule_meta(self, rule_id: str) -> Dict[str, Any]:
        return self.rule_catalog.get(rule_id, {})

    def _find_catalog_cve_rule(self, product: str, version: str, fallback_rule_id: str) -> str:
        for rid, meta in self.rule_catalog.items():
            if not isinstance(meta, dict):
                continue
            if not meta.get("cve_dependent", False):
                continue
            detection = meta.get("detection", {}) if isinstance(meta.get("detection"), dict) else {}
            if str(detection.get("product", "")).lower() == str(product).lower() and str(detection.get("version", "")) == str(version):
                return rid
        return fallback_rule_id

    def _resolve_meta_rule_id(self, finding: Dict[str, Any]) -> str:
        rule_id = finding.get("rule_id", "")
        platform = finding.get("target", {}).get("platform", "unknown")

        platform_aliases = {
            "apache": {
                "G1": "G1-Apache-ServerTokens",
                "G2": "G2-Directory-Listing",
                "G3": "G3-HTTP-Methods",
                "G4": "G4-TLS-Posture",
                "G5": "G5-Security-Headers",
                "G6": "G6-Logging-Hygiene",
                "G9": "G9-Sensitive-Files",
                "M1": "M1-Status-Page-Exposure",
                "AP-A5-G8": "AP-A5-G8-AllowOverride",
            },
            "nginx": {
                "G1": "G1-Nginx-ServerTokens",
                "G2": "NG-N2-G2-Autoindex",
                "G3": "NG-N5-G3-Methods-Limits",
                "G4": "G4-TLS-Posture",
                "G5": "G5-Security-Headers",
                "G6": "G6-Logging-Hygiene",
                "G9": "G9-Sensitive-Files",
                "M1": "M1-Status-Page-Exposure",
                "NG-N2-G2": "NG-N2-G2-Autoindex",
                "NG-N5-G3": "NG-N5-G3-Methods-Limits",
            },
            "ols": {
                "G1": "G1",
                "G2": "G2-Directory-Listing",
                "G5": "G5-Security-Headers",
                "G6": "G6-Logging-Hygiene",
                "G9": "G9-Sensitive-Files",
                "OLS-O1-ADMIN": "OLS-O1-Admin-Exposure",
                "OLS-O2-ADMIN-PASSWORD": "OLS-O2-Admin-Password",
            },
        }

        platform_map = platform_aliases.get(platform, {})
        candidate = platform_map.get(rule_id)
        if candidate and candidate in self.rule_catalog:
            return candidate
        return rule_id

    def _enrich_with_catalog(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        meta_rule_id = self._resolve_meta_rule_id(finding)
        meta = self._get_rule_meta(meta_rule_id)
        if not meta:
            return finding

        platform = finding.get("target", {}).get("platform", "unknown")
        finding["rule_meta"] = {
            "catalog_rule_id": meta_rule_id,
            "title": meta.get("title", ""),
            "applies_to": meta.get("applies_to", meta.get("affects", [])),
            "expected": meta.get("expected", False),
        }

        finding["wstg_id"] = meta.get("wstg_id")
        finding["cwe_id"] = meta.get("cwe_id")
        if finding.get("cvss") is None:
            sev_meta = meta.get("severity", {}) if isinstance(meta.get("severity"), dict) else {}
            base_score = sev_meta.get("base_score")
            if isinstance(base_score, (int, float)):
                finding["cvss"] = float(base_score)
        if not finding.get("references"):
            finding["references"] = meta.get("references", [])

        if not finding.get("category") and meta.get("category"):
            finding["category"] = meta.get("category")

        if finding.get("severity", "") not in ["info", "low", "medium", "high"]:
            finding["severity"] = meta.get("severity", "low")

        tag_map = meta.get("tags", {}) if isinstance(meta.get("tags", {}), dict) else {}
        platform_tags = tag_map.get(platform, [])
        if platform_tags and not finding.get("ansible", {}).get("tags"):
            finding["ansible"]["tags"] = platform_tags

        return finding

    def _load_target_map(self) -> Dict[str, Dict[str, Any]]:
        targets_file = os.path.join("config", "targets.json")
        if not os.path.exists(targets_file):
            return {}
        try:
            with open(targets_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return {}
            return {t.get("name", ""): t for t in data if isinstance(t, dict) and t.get("name")}
        except Exception:
            return {}

    @staticmethod
    def _severity_rank(severity: str) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        return order.get(str(severity).lower(), 0)

    @staticmethod
    def _preferred_source(source: str) -> bool:
        return source in ["nmap", "nikto", "testssl", "trivy", "gobuster", "curl"]

    @staticmethod
    def _is_private_or_local_target(target: Dict[str, Any]) -> bool:
        ip = str(target.get("ip", "")).strip()
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return bool(addr.is_private or addr.is_loopback or addr.is_link_local)
        except ValueError:
            return False

    def _merge_findings_by_rule(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[Any, Dict[str, Any]] = {}

        for finding in findings:
            key = (
                finding.get("target", {}).get("name", "unknown"),
                finding.get("rule_id", "unknown"),
            )
            evidence = finding.get("evidence", {})
            observed = evidence.get("observed", "") if isinstance(evidence, dict) else str(evidence)
            entry = {
                "source": finding.get("source", "unknown"),
                "observed": observed,
                "raw_path": evidence.get("raw_path", "") if isinstance(evidence, dict) else "",
            }

            if key not in merged:
                new_item = dict(finding)
                new_item["evidence_entries"] = [entry]
                merged[key] = new_item
                continue

            current = merged[key]
            current["evidence_entries"].append(entry)

            if self._severity_rank(finding.get("severity", "info")) > self._severity_rank(current.get("severity", "info")):
                current["severity"] = finding.get("severity", "info")

            c_status = current.get("check_status")
            f_status = finding.get("check_status")
            if c_status and f_status and c_status != f_status:
                current["check_status"] = "conflict"
            elif not c_status and f_status:
                current["check_status"] = f_status

            if self._preferred_source(finding.get("source", "")) and not self._preferred_source(current.get("source", "")):
                current["source"] = finding.get("source")
                current["category"] = finding.get("category", current.get("category"))
                current["title"] = finding.get("title", current.get("title"))
                current["description"] = finding.get("description", current.get("description"))
                current["evidence"] = finding.get("evidence", current.get("evidence"))

        for item in merged.values():
            deduped = []
            seen = set()
            for ev in item.get("evidence_entries", []):
                fp = (ev.get("source", ""), ev.get("observed", ""), ev.get("raw_path", ""))
                if fp in seen:
                    continue
                seen.add(fp)
                deduped.append(ev)
            item["evidence_entries"] = deduped

        return list(merged.values())

    def _generate_coverage_report(self, findings_by_target: Dict[str, List[Dict[str, Any]]], target_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        report = {"run_id": self.run_id, "targets": {}}

        for target_name, findings in findings_by_target.items():
            platform = target_map.get(target_name, {}).get("platform", "unknown")
            expected = []
            for rid, meta in self.rule_catalog.items():
                applies = meta.get("applies_to", meta.get("affects", []))
                applies = applies if isinstance(applies, list) else []
                if meta.get("expected") and (platform in applies or "any" in applies):
                    expected.append(rid)

            found = {f.get("rule_id", "") for f in findings}
            unknown = {
                f.get("rule_id", "") for f in findings
                if f.get("source") == "agent" and f.get("check_status") == "unknown"
            }

            report["targets"][target_name] = {
                "platform": platform,
                "expected_rules": sorted(expected),
                "found_rules": sorted([r for r in found if r]),
                "missing_rules": sorted([r for r in expected if r not in found]),
                "unknown_rules": sorted([r for r in unknown if r]),
            }

        return report
        
    def normalize_all(self):
        """Iterate through all targets in the run and normalize their results."""
        if not os.path.exists(self.run_path):
            return

        all_findings = []
        target_map = self._load_target_map()
        findings_by_target: Dict[str, List[Dict[str, Any]]] = {}
        
        # Iterate over targets (subdirectories in run_path that aren't 'logs' or 'summary.json')
        for target_name in os.listdir(self.run_path):
            target_path = os.path.join(self.run_path, target_name)
            if not os.path.isdir(target_path) or target_name == "logs":
                continue
                
            raw_path = os.path.join(target_path, "raw")
            if not os.path.exists(raw_path):
                continue
                
            target_cfg = target_map.get(target_name, {})
            target_info = {
                "name": target_name,
                "ip": target_cfg.get("ip", "unknown"),
                "platform": target_cfg.get("platform", "unknown"),
            }
            
            target_findings = []
            target_findings.extend(self._normalize_nmap(raw_path, target_info))
            target_findings.extend(self._normalize_nikto(raw_path, target_info))
            target_findings.extend(self._normalize_testssl(raw_path, target_info))
            target_findings.extend(self._normalize_gobuster(raw_path, target_info))
            target_findings.extend(self._normalize_curl(raw_path, target_info))
            target_findings.extend(self._normalize_agent(target_path, target_info))

            enriched = [self._enrich_with_catalog(f) for f in target_findings]
            target_findings = self._merge_findings_by_rule(enriched)
            findings_by_target[target_name] = target_findings

            # Save target-specific normalized findings
            out_file = os.path.join(target_path, "normalized.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(target_findings, f, indent=2)
                
            all_findings.extend(target_findings)
            
        summary_file = os.path.join(self.run_path, "summary.json")

        scans_dir = os.path.join(os.path.dirname(os.path.dirname(self.run_path)), "scans")
        os.makedirs(scans_dir, exist_ok=True)
        scan_file = os.path.join(scans_dir, f"{self.run_id}.json")
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "schema_version": "2.0",
                    "report_type": "scan-findings-export",
                    "scan_id": self.run_id,
                    "run_id": self.run_id,
                    "scan_profile": self.scan_profile,
                    "findings": all_findings,
                },
                f,
                indent=2,
            )

        # Remove stale legacy export path used by older builds.
        legacy_scans_dir = os.path.join(os.path.dirname(self.run_path), "scans")
        legacy_scan_file = os.path.join(legacy_scans_dir, f"{self.run_id}.json")
        if os.path.exists(legacy_scan_file):
            try:
                os.remove(legacy_scan_file)
            except OSError:
                pass

        coverage = self._generate_coverage_report(findings_by_target, target_map)
        coverage_file = os.path.join(self.run_path, "coverage.json")
        with open(coverage_file, "w", encoding="utf-8") as f:
            json.dump(coverage, f, indent=2)

        report_doc = build_report_document(
            run_id=self.run_id,
            scan_profile=self.scan_profile,
            findings=all_findings,
            coverage=coverage,
        )
        export_paths = write_report_exports(self.run_path, report_doc)

        summary_payload = {
            "schema_version": report_doc.get("schema_version", "2.0"),
            "run_id": self.run_id,
            "scan_id": self.run_id,
            "scan_profile": self.scan_profile,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": report_doc.get("metrics", {}),
            "exports": {
                "report_json": os.path.relpath(export_paths.get("report_json", ""), self.run_path).replace("\\", "/"),
                "findings_csv": os.path.relpath(export_paths.get("findings_csv", ""), self.run_path).replace("\\", "/"),
                "report_print_html": os.path.relpath(export_paths.get("report_print_html", ""), self.run_path).replace("\\", "/"),
            },
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2)

    def _normalize_agent(self, target_path: str, target: Dict) -> List[Dict]:
        findings = []
        agent_file = os.path.join(target_path, "agent.json")
        if not os.path.exists(agent_file):
            return findings

        try:
            with open(agent_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            checks = data.get("checks", []) if isinstance(data, dict) else []
            alias_map = {
                "AG-FP-01": "G1",
                "AG-DIR-01": "G2",
                "AG-METHODS-01": "G3",
                "AG-HEADERS-01": "G5",
                "AG-LOG-01": "G6",
                "AG-EXPOSED-01": "G9",
            }
            for check in checks:
                if not isinstance(check, dict):
                    continue

                original_rule_id = check.get("rule_id", "AGENT-GEN")
                rule_id = alias_map.get(original_rule_id, original_rule_id)
                category = check.get("category", "agent")
                status = check.get("status", "unknown")
                sev = str(check.get("severity", "low")).lower()
                if sev not in ["info", "low", "medium", "high"]:
                    sev = "low"

                # Passing checks are health evidence, not findings.
                if status == "pass":
                    continue
                if status == "unknown" and sev in ["high", "medium"]:
                    sev = "low"
                if rule_id == "AG-TLS-KEY-PERMS" and status == "unknown":
                    unknown_ev = str(check.get("evidence", "")).strip()
                    if unknown_ev in ["", "[]", "{}"]:
                        continue

                findings.append(self._create_finding(
                    target,
                    "agent",
                    rule_id,
                    category,
                    sev,
                    check.get("title", "Agent Check"),
                    check.get("evidence", check.get("recommendation", "Review host-level hardening setting.")),
                    {
                        "observed": check.get("evidence", ""),
                        "raw_path": agent_file,
                        "recommendation": check.get("recommendation", ""),
                    },
                    [f"{target['name']}_agent_check"]
                ))
                findings[-1]["check_status"] = status
                findings[-1]["original_rule_id"] = original_rule_id

            package_state = data.get("package_state", {}) if isinstance(data, dict) else {}
            upgradable = package_state.get("upgradable", []) if isinstance(package_state, dict) else []
            upgradable = [
                u for u in upgradable
                if not any(
                    u.startswith(prefix)
                    for prefix in [
                        "linux-headers-generic/",
                        "linux-headers-virtual/",
                        "linux-image-virtual/",
                        "linux-virtual/",
                    ]
                )
            ]
            if upgradable:
                sample = upgradable[:8]
                findings.append(self._create_finding(
                    target,
                    "agent",
                    "AG-PATCH-STATE",
                    "updates",
                    "low",
                    "System packages pending update",
                    "Host has pending package updates. Apply OS updates and security patches.",
                    {"observed": "\n".join(sample), "raw_path": agent_file},
                    ["apply_security_updates"]
                ))

            trivy = package_state.get("trivy", {}) if isinstance(package_state, dict) else {}
            if isinstance(trivy, dict) and trivy.get("status") == "ok":
                findings.append(self._create_finding(
                    target,
                    "trivy",
                    "TRIVY-ROOTFS",
                    "packages",
                    "medium",
                    "Trivy deep scan summary",
                    "Optional deep scan produced a Trivy rootfs summary.",
                    {"observed": str(trivy.get("summary", ""))[:800], "raw_path": agent_file},
                    ["review_trivy_findings"]
                ))
        except Exception as e:
            print(f"Error parsing agent output: {e}")

        return findings

    def _create_finding(self, target: Dict, source: str, rule_id: str, category: str, 
                        severity: str, title: str, description: str, evidence: Any, 
                        tags: List[str] = None) -> Dict:
        return {
            "run_id": self.run_id,
            "scan_id": self.run_id,
            "target": target,
            "server_type": target.get("platform", "unknown"),
            "source": source,
            "rule_id": rule_id,
            "category": category,
            "severity": severity.lower(),
            "title": title,
            "description": description,
            "wstg_id": None,
            "cwe_id": None,
            "cve_list": [],
            "cvss": None,
            "evidence": evidence,
            "status": "open",
            "recommendation": "Review and apply hardening via Ansible.",
            "ansible": {
                "tags": tags or [],
                "requires_reboot": False
            }
        }

    def _normalize_nmap(self, raw_path: str, target: Dict) -> List[Dict]:
        findings = []
        nmap_files = glob.glob(os.path.join(raw_path, "nmap.xml"))
        if not nmap_files:
            return findings
            
        try:
            tree = ET.parse(nmap_files[0])
            root = tree.getroot()
            for host in root.findall('host'):
                # Extract IP if available to update target info
                address = host.find('address')
                if address is not None and address.get('addr'):
                    target['ip'] = address.get('addr')

                ports = host.find('ports')
                if ports is None: continue
                
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('service')
                        
                        svc_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        svc_product = service.get('product', '') if service is not None else ''
                        svc_version = service.get('version', '') if service is not None else ''
                        
                        title = f"Open Port: {port_id}/{svc_name}"
                        desc = f"Service {svc_product} {svc_version} is running."
                        
                        # Very basic heuristic for version disclosure (A1/N1/G1)
                        if svc_version:
                            product_norm = "apache" if "apache" in svc_product.lower() else ("nginx" if "nginx" in svc_product.lower() else "")
                            findings.append(self._create_finding(
                                target, "nmap", "G1", "fingerprinting", "medium",
                                f"Service Version Disclosure: {svc_product} {svc_version}",
                                f"Nmap identified explicit version: {svc_product} {svc_version} on port {port_id}",
                                {"observed": f"{svc_product} {svc_version} (port {port_id})", "raw_path": nmap_files[0]},
                                [f"{target['name']}_hide_version"]
                            ))

                            if self.scan_profile == "standards_mode" and product_norm:
                                cve_hits = self.cve_cache.lookup(product_norm, svc_version)
                                if cve_hits:
                                    cve_rule_id = self._find_catalog_cve_rule(
                                        product_norm,
                                        svc_version,
                                        f"CVE-{product_norm}-{svc_version}",
                                    )
                                    findings.append(self._create_finding(
                                        target,
                                        "nmap",
                                        cve_rule_id,
                                        "components",
                                        "high",
                                        f"Known vulnerable version detected: {svc_product} {svc_version}",
                                        "Detected service version matches local CVE intelligence cache entries.",
                                        {"observed": f"{svc_product} {svc_version}", "raw_path": nmap_files[0]},
                                        [f"{target['name']}_upgrade"],
                                    ))
                                    findings[-1]["cve_list"] = [x.get("cve") for x in cve_hits if isinstance(x, dict) and x.get("cve")]
                                    scores = [x.get("cvss") for x in cve_hits if isinstance(x, dict) and isinstance(x.get("cvss"), (int, float))]
                                    findings[-1]["cvss"] = max(scores) if scores else None
                                    cwes = [x.get("cwe") for x in cve_hits if isinstance(x, dict) and x.get("cwe")]
                                    findings[-1]["cwe_id"] = cwes[0] if cwes else None
                        else:
                            if self.scan_profile != "standards_mode":
                                findings.append(self._create_finding(
                                    target, "nmap", "INFO-01", "network", "info", title, desc,
                                    {"observed": f"Port {port_id} open", "raw_path": nmap_files[0]}
                                ))

                        if target.get("platform") == "ols" and str(port_id) == "7080":
                            findings.append(self._create_finding(
                                target,
                                "nmap",
                                "OLS-O1-ADMIN",
                                "admin_surface",
                                "medium",
                                "OpenLiteSpeed WebAdmin port exposed",
                                "Port 7080 is externally reachable, indicating potential WebAdmin exposure.",
                                {"observed": "Port 7080 open", "raw_path": nmap_files[0]},
                                ["ols_restrict_admin"],
                            ))

                        # --- Parse NSE script outputs ---
                        for script in port.findall('script'):
                            script_id = script.get('id', '')
                            script_output = script.get('output', '')

                            if script_id == 'http-methods':
                                if 'TRACE' in script_output:
                                    findings.append(self._create_finding(
                                        target, "nmap", "G3", "methods", "medium",
                                        "TRACE Method Detected via Nmap",
                                        "Nmap http-methods script detected TRACE as a supported HTTP method. "
                                        "TRACE enables Cross-Site Tracing (XST) attacks and should be disabled.",
                                        {"observed": script_output.strip(), "raw_path": nmap_files[0]},
                                        [f"{target['name']}_disable_trace"]
                                    ))

                            elif script_id == 'ssl-cert':
                                subject_cn = ''
                                issuer_cn = ''
                                for table in script.findall('table'):
                                    tkey = table.get('key', '')
                                    if tkey == 'subject':
                                        for elem in table.findall('elem'):
                                            if elem.get('key') == 'commonName':
                                                subject_cn = (elem.text or '').strip()
                                    elif tkey == 'issuer':
                                        for elem in table.findall('elem'):
                                            if elem.get('key') == 'commonName':
                                                issuer_cn = (elem.text or '').strip()
                                if (
                                    subject_cn
                                    and issuer_cn
                                    and subject_cn == issuer_cn
                                    and not self._is_ols_admin_port(target, port_id)
                                ):
                                    findings.append(self._create_finding(
                                        target, "nmap", "G4-CERT", "tls", "high",
                                        "Self-Signed TLS Certificate Detected",
                                        f"The TLS certificate on port {port_id} is self-signed "
                                        f"(subject and issuer both '{subject_cn}'). Self-signed certificates "
                                        "are not trusted by browsers and indicate missing CA-signed deployment.",
                                        {"observed": f"Subject CN={subject_cn}, Issuer CN={issuer_cn}",
                                         "raw_path": nmap_files[0]},
                                        [f"{target['name']}_tls_certificate"]
                                    ))

        except Exception as e:
            print(f"Error parsing Nmap: {e}")

        return findings

    @staticmethod
    def _is_nikto_positive_header(msg: str) -> bool:
        """Return True when Nikto reports a header that is actually present and
        correctly configured (i.e. NOT a vulnerability)."""
        ml = msg.lower()
        # "Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN"
        if "found, with contents:" in ml:
            for good in ["sameorigin", "deny", "nosniff", "1; mode=block",
                         "no-referrer", "strict-origin", "same-origin",
                         "max-age=", "geolocation=()", "camera=()", "microphone=()"]:
                if good in ml:
                    return True
        return False

    def _normalize_nikto(self, raw_path: str, target: Dict) -> List[Dict]:
        findings = []
        nikto_files = glob.glob(os.path.join(raw_path, "nikto_stdout.txt"))
        if not nikto_files:
            return findings

        try:
            agent_headers_pass = False
            agent_file = os.path.join(os.path.dirname(raw_path), "agent.json")
            if os.path.exists(agent_file):
                try:
                    with open(agent_file, "r", encoding="utf-8") as af:
                        agent_data = json.load(af)
                    for chk in agent_data.get("checks", []) if isinstance(agent_data, dict) else []:
                        if not isinstance(chk, dict):
                            continue
                        if chk.get("rule_id") == "AG-HEADERS-01" and chk.get("status") == "pass":
                            agent_headers_pass = True
                            break
                except Exception:
                    agent_headers_pass = False

            with open(nikto_files[0], "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or not line.startswith("+ "):
                    continue

                msg = line[2:].strip()
                # Skip metadata / informational lines
                if any(k in msg for k in ["Target IP", "Target Hostname", "Target Port",
                                           "Start Time", "End Time", "items checked:",
                                           "host(s) tested", "No CGI Directories",
                                           "Allowed HTTP Methods"]):
                    continue
                if "Server:" in msg and "leaks" not in msg:
                    continue

                # Skip positive security configurations (false positives)
                if self._is_nikto_positive_header(msg):
                    continue

                sev = "medium"
                ml = msg.lower()

                if "directory indexing found" in ml:
                    rule = "G2"
                    cat = "files"
                    tags = [f"{target['name']}_no_autoindex"]
                elif "etag" in ml and ("leak" in ml or "inode" in ml):
                    rule = "G7-ETAG-LEAK"
                    cat = "fingerprinting"
                    sev = "low"
                    tags = [f"{target['name']}_fix_etag"]
                elif "is not set" in ml and any(h in ml for h in [
                    "x-frame-options", "x-content-type-options",
                    "content-security-policy", "strict-transport-security",
                    "x-xss-protection", "permissions-policy", "referrer-policy"
                ]):
                    rule = "G5"
                    cat = "headers"
                    tags = [f"{target['name']}_security_headers"]
                elif any(h in ml for h in ["x-frame-options", "x-content-type-options",
                                            "content-security-policy",
                                            "strict-transport-security"]):
                    # Header mentioned but not as "found with correct value" (those
                    # were filtered above) — treat as a header misconfiguration
                    rule = "G5"
                    cat = "headers"
                    tags = [f"{target['name']}_security_headers"]
                elif "leaks " in ml or "server leaks" in ml:
                    rule = "G1"
                    cat = "fingerprinting"
                    tags = [f"{target['name']}_hide_version"]
                elif "trace" in ml:
                    rule = "G3"
                    cat = "methods"
                    tags = [f"{target['name']}_disable_trace"]
                else:
                    if self.scan_profile == "standards_mode":
                        continue
                    rule = "NIKTO-GEN"
                    cat = "web"
                    tags = []

                if rule == "G5" and agent_headers_pass:
                    sev = "info"
                    msg = f"{msg} (Agent check reports security headers configured in active server config.)"

                findings.append(self._create_finding(
                    target, "nikto", rule, cat, sev,
                    "Web Vulnerability Detected", msg,
                    {"observed": msg, "raw_path": nikto_files[0]},
                    tags
                ))
        except Exception as e:
            print(f"Error parsing Nikto: {e}")

        return findings

    # TestSSL check-ID → rule-ID mapping
    _TESTSSL_RULE_MAP = {
        # Certificate trust & validity → G4-CERT
        "cert_trust": "G4-CERT", "cert_chain_of_trust": "G4-CERT",
        "cert_notAfter": "G4-CERT", "cert_notBefore": "G4-CERT",
        "cert_extlifeSpan": "G4-CERT", "cert_expiration": "G4-CERT",
        "cert_revocation": "G4-CERT", "cert_signatureAlgorithm": "G4-CERT",
        "cert_keySize": "G4-CERT", "cert_caIssuers": "G4-CERT",
        "cert_commonName": "G4-CERT", "cert_subjectAltName": "G4-CERT",
        "cert_validityPeriod": "G4-CERT",
        # Deprecated protocols → G4-PROTO
        "SSLv2": "G4-PROTO", "SSLv3": "G4-PROTO",
        "TLS1": "G4-PROTO", "TLS1_1": "G4-PROTO",
        "NPN": "G4-PROTO", "ALPN": "G4-PROTO",
        # Cipher issues → G4-CIPHER
        "sweet32": "G4-CIPHER", "RC4": "G4-CIPHER",
        "strong_encryption": "G4-CIPHER", "FS_KEMs": "G4-CIPHER",
        "FS_TLS12_sig_algs": "G4-CIPHER",
        "cipher_order": "G4-CIPHER",
        # HSTS → G4-HSTS
        "HSTS": "G4-HSTS", "HSTS_time": "G4-HSTS",
        "HSTS_subdomains": "G4-HSTS", "HSTS_preload": "G4-HSTS",
        # DNS CAA → G4-CAA
        "DNS_CAArecord": "G4-CAA",
        # Known vulnerabilities → G4-VULN
        "BREACH": "G4-VULN", "POODLE_SSL": "G4-VULN",
        "LUCKY13": "G4-VULN", "ROBOT": "G4-VULN",
        "CRIME_TLS": "G4-VULN", "DROWN": "G4-VULN",
        "Heartbleed": "G4-VULN", "CCS": "G4-VULN",
        "ticketbleed": "G4-VULN", "LOGJAM": "G4-VULN",
        "FREAK": "G4-VULN", "BEAST": "G4-VULN",
        # Security headers detected at TLS layer → G5
        "security_headers": "G5", "X-Frame-Options": "G5",
        "X-Content-Type-Options": "G5", "X-XSS-Protection": "G5",
        "Content-Security-Policy": "G5", "Referrer-Policy": "G5",
        "Permissions-Policy": "G5",
        # General TLS posture → G4 (catch-all)
        "overall_grade": "G4", "secure_renego": "G4",
        "secure_client_renego": "G4", "fallback_SCSV": "G4",
    }

    _TESTSSL_DESC_MAP = {
        "overall_grade": "The server's overall TLS rating is poor (Grade: {}). This indicates weak ciphers, outdated protocols, or missing security headers.",
        "DNS_CAArecord": "No DNS CAA record found. A CAA record specifies which certificate authorities are allowed to issue certificates for a domain.",
        "cert_trust": "Certificate trust issue. The certificate may be self-signed, expired, or not trusted by common trust stores.",
        "cert_chain_of_trust": "The certificate chain could not be validated. Intermediate or root CA certificates may be missing or untrusted.",
        "cert_extlifeSpan": "The certificate has an excessively long validity period, which increases exposure to key compromise.",
        "cert_expiration": "The SSL/TLS certificate is expired or expiring soon.",
        "cert_revocation": "Certificate revocation information is missing or inaccessible (no OCSP/CRL).",
        "cert_signatureAlgorithm": "The certificate uses a weak or deprecated signature algorithm.",
        "cert_keySize": "The certificate key size is below recommended minimums.",
        "fallback_SCSV": "TLS Fallback Signaling Cipher Suite Value (SCSV) is not supported, making the server vulnerable to protocol downgrade attacks.",
        "HSTS": "HTTP Strict Transport Security (HSTS) is either not configured or configured improperly.",
        "secure_renego": "Secure Client-Initiated Renegotiation is not supported or vulnerable.",
        "POODLE_SSL": "The server is vulnerable to the POODLE attack via SSLv3.",
        "sweet32": "The server is vulnerable to the SWEET32 attack (weak 64-bit block ciphers).",
        "BREACH": "The server is vulnerable to the BREACH attack; HTTP compression on HTTPS responses can leak secret tokens.",
        "LUCKY13": "The server may be vulnerable to the LUCKY13 timing attack on CBC-mode ciphers.",
        "ROBOT": "The server may be vulnerable to the ROBOT attack (Return Of Bleichenbacher's Oracle Threat).",
        "CRIME_TLS": "The server is vulnerable to the CRIME attack via TLS-level compression.",
        "DROWN": "The server is vulnerable to DROWN; SSLv2 support exposes TLS sessions to cross-protocol attacks.",
        "Heartbleed": "The server is vulnerable to Heartbleed (CVE-2014-0160), allowing remote memory disclosure.",
        "BEAST": "The server may be susceptible to the BEAST attack on TLS 1.0 CBC ciphers.",
        "LOGJAM": "The server is vulnerable to LOGJAM; weak DHE key exchange parameters are offered.",
        "FREAK": "The server is vulnerable to FREAK; export-grade RSA keys are offered.",
        "RC4": "The server offers RC4 ciphers, which are cryptographically broken.",
        "FS_KEMs": "Forward Secrecy key exchange mechanisms are weak or not offered.",
        "cipher_order": "The server does not enforce its own cipher suite preference order. Without server-side ordering, clients may negotiate weaker ciphers.",
        "cipherlist_AVERAGE": "The offered cipher suite list is rated AVERAGE overall; weak ciphers should be removed.",
        "cipherlist_STRONG": "The cipher suite list is strong overall but may still contain unnecessary entries.",
        "cipherlist_WEAK": "The offered cipher suite list contains WEAK ciphers that should be disabled.",
    }

    @staticmethod
    def _is_individual_cipher_id(id_name: str) -> bool:
        """Return True for per-cipher check IDs like cipher-tls1_2_xc028."""
        return id_name.startswith("cipher-") or id_name.startswith("cipher_x")

    def _resolve_testssl_rule(self, id_name: str) -> str:
        # Direct lookup first
        if id_name in self._TESTSSL_RULE_MAP:
            return self._TESTSSL_RULE_MAP[id_name]
        # Try base ID (strip per-protocol suffix like cipher_order-tls1_2 → cipher_order)
        base = id_name.rsplit("-", 1)[0] if "-" in id_name else id_name
        if base in self._TESTSSL_RULE_MAP:
            return self._TESTSSL_RULE_MAP[base]
        # Prefix-based fallbacks
        if (id_name.startswith("cipher_") or id_name.startswith("cipherlist_")
                or id_name.startswith("cipher-")):
            return "G4-CIPHER"
        if id_name.startswith("cert_"):
            return "G4-CERT"
        if id_name.startswith("HSTS"):
            return "G4-HSTS"
        return "G4"

    @staticmethod
    def _resolve_testssl_tags(rule: str, target: Dict[str, Any]) -> List[str]:
        platform = str(target.get("platform") or target.get("name") or "").strip().lower()
        if not platform:
            return []

        if rule == "G4-HSTS" or rule == "G5":
            return [f"{platform}_security_headers"]
        if rule == "G4-CERT":
            return [f"{platform}_tls_certificate"]
        if rule == "G4-CAA":
            return ["fix_dns_caa"]
        return [f"{platform}_tls_hardening"]

    @staticmethod
    def _is_testssl_rollup_cert_duplicate(id_name: str, finding_msg: Any) -> bool:
        """
        TestSSL uses overall_grade=T when the grade is dragged down by trust or
        certificate validity problems. Those issues are already captured by the
        dedicated cert_* checks and should not be surfaced as auto TLS hardening.
        """
        return id_name == "overall_grade" and str(finding_msg).strip().upper() == "T"

    @staticmethod
    def _is_testssl_low_signal_noise(id_name: str, finding_msg: Any) -> bool:
        """
        FS_KEMs with "No KEMs offered" is a low-signal TestSSL check in this lab:
        it does not map cleanly to the conventional TLS fixes this project applies,
        and it kept surfacing after otherwise successful hardening.
        """
        return id_name == "FS_KEMs" and str(finding_msg).strip().lower() == "no kems offered"

    @staticmethod
    def _is_ols_tls_limit_noise(target: Dict[str, Any], id_name: str) -> bool:
        """
        OpenLiteSpeed's public docs expose listener/vhost ciphers, but do not
        document a server-side knob for TLS 1.2 signature_algorithms. In this
        lab that check kept surviving after the documented OLS TLS hardening
        had already been applied, so do not keep surfacing it as auto-remediable
        transport debt for OLS.
        """
        return (
            str(target.get("platform", "")).strip().lower() == "ols"
            and id_name == "FS_TLS12_sig_algs"
        )

    @staticmethod
    def _is_ols_admin_port(target: Dict[str, Any], port: Any) -> bool:
        if str(target.get("platform", "")).strip().lower() != "ols":
            return False
        try:
            return int(str(port).strip()) == 7080
        except (TypeError, ValueError):
            return False

    def _normalize_testssl(self, raw_path: str, target: Dict) -> List[Dict]:
        findings = []
        testssl_files = glob.glob(os.path.join(raw_path, "testssl.json"))
        if not testssl_files:
            return findings

        try:
            with open(testssl_files[0], "r") as f:
                data = json.load(f)

            # Collect individual cipher IDs for aggregation instead of emitting one finding per cipher
            individual_ciphers: List[str] = []
            certificate_checks: List[str] = []
            cert_self_signed = False
            cert_max_rank = self._severity_rank("low")

            if isinstance(data, list):
                for item in data:
                    sev = item.get("severity", "INFO").lower()
                    if sev in ["info", "ok"]:
                        continue

                    id_name = item.get("id", "TLS_GEN")
                    finding_msg = item.get("finding", "")
                    item_port = item.get("port")

                    if id_name in ["scanProblem", "scanTime"]:
                        continue
                    if self._is_ols_admin_port(target, item_port):
                        # OLS port 7080 is the WebAdmin TLS surface. Those findings do
                        # not reflect the public site hardening the remediation module
                        # manages, so do not count them as ordinary post-hardening
                        # transport debt.
                        continue
                    if "not vulnerable" in finding_msg.lower():
                        continue
                    if self._is_testssl_rollup_cert_duplicate(id_name, finding_msg):
                        continue
                    if self._is_testssl_low_signal_noise(id_name, finding_msg):
                        continue
                    if self._is_ols_tls_limit_noise(target, id_name):
                        continue

                    # Aggregate individual cipher IDs rather than emitting dozens of low findings
                    if self._is_individual_cipher_id(id_name):
                        individual_ciphers.append(f"{id_name}: {finding_msg}")
                        continue

                    if sev in ["critical", "fatal"]:
                        sev = "high"
                    elif sev == "warn":
                        sev = "low"

                    # overall_grade is a roll-up indicator; keep it as low-signal context.
                    if id_name == "overall_grade":
                        sev = "low"

                    # Aggregate certificate-related checks under one certificate finding per target.
                    if id_name.startswith("cert_"):
                        cert_line = f"{id_name}: {finding_msg}"
                        certificate_checks.append(cert_line)
                        cert_max_rank = max(cert_max_rank, self._severity_rank(sev))
                        if "self signed" in str(finding_msg).lower():
                            cert_self_signed = True
                        continue

                    rule = self._resolve_testssl_rule(id_name)
                    tags = self._resolve_testssl_tags(rule, target)

                    desc = self._TESTSSL_DESC_MAP.get(
                        id_name,
                        self._TESTSSL_DESC_MAP.get(
                            id_name.rsplit("-", 1)[0] if "-" in id_name else id_name,
                            f"TLS misconfiguration detected: {id_name}."
                        )
                    )
                    if "{}" in desc:
                        desc = desc.format(finding_msg)

                    if finding_msg in ["--", "", "T", "F", "0", "t"]:
                        if id_name == "DNS_CAArecord":
                            desc = "No DNS CAA record is configured. This does not expose data directly, but allows any CA to issue certificates for the domain unless restricted."
                        elif id_name == "overall_grade":
                            desc = "The TLS configuration grade is weak. Review supported protocols, key exchange, and cipher configuration to improve transport security posture."

                    evidence = str(finding_msg).strip()
                    if evidence in ["--", "T", "0", "", "F", "t"]:
                        evidence = f"TestSSL performed check '{id_name}' and returned vague value: '{finding_msg}'"

                    # Map rule category for UI grouping
                    cat = "tls"
                    if rule == "G5":
                        cat = "headers"

                    findings.append(self._create_finding(
                        target, "testssl", rule, cat, sev,
                        f"TLS Issue: {id_name}", desc,
                        {"observed": evidence, "raw_path": testssl_files[0]},
                        tags
                    ))

            if certificate_checks:
                cert_sev_by_rank = {0: "info", 1: "low", 2: "medium", 3: "high"}
                cert_sev = cert_sev_by_rank.get(cert_max_rank, "high")
                cert_title = "Self-Signed TLS Certificate Detected" if cert_self_signed else f"TLS Certificate Validation Issues ({len(certificate_checks)} checks)"
                cert_desc = (
                    "Multiple TLS certificate checks failed. "
                    "Deploy a CA-signed certificate with valid chain/SAN and enforce certificate lifecycle controls."
                )
                findings.append(self._create_finding(
                    target,
                    "testssl",
                    "G4-CERT",
                    "tls",
                    cert_sev,
                    cert_title,
                    cert_desc,
                    {
                        "observed": "\n".join(certificate_checks[:20]),
                        "raw_path": testssl_files[0],
                    },
                    self._resolve_testssl_tags("G4-CERT", target),
                ))

            # Emit a single aggregated G4-CIPHER finding for all individual cipher issues
            if individual_ciphers:
                findings.append(self._create_finding(
                    target, "testssl", "G4-CIPHER", "tls", "low",
                    f"Weak Individual Ciphers Offered ({len(individual_ciphers)} ciphers)",
                    f"{len(individual_ciphers)} individual cipher suites were flagged by TestSSL. "
                    "Review and remove weak or unnecessary cipher suites from the TLS configuration.",
                    {"observed": "\n".join(individual_ciphers[:20]),
                     "raw_path": testssl_files[0]},
                    self._resolve_testssl_tags("G4-CIPHER", target)
                ))
        except Exception as e:
            print(f"Error parsing Testssl: {e}")

        return findings

    def _normalize_gobuster(self, raw_path: str, target: Dict) -> List[Dict]:
        findings = []
        gobuster_files = glob.glob(os.path.join(raw_path, "gobuster.json"))
        if not gobuster_files:
            return findings
            
        try:
            with open(gobuster_files[0], "r") as f:
                paths = json.load(f)
                
            for entry in paths:
                path = entry.get("path") if isinstance(entry, dict) else str(entry)
                status_code = entry.get("status") if isinstance(entry, dict) else None

                sensitive_patterns = [
                    '.git', '.env', 'backup', 'info.php', 'phpinfo',
                    '.htpasswd', '.htaccess', '.DS_Store', 'wp-config',
                    'config.php', 'database', '.sql', 'credentials',
                    'secret', '.pem', '.key', '.bak',
                ]
                metafile_patterns = [
                    'robots.txt', 'sitemap.xml', 'security.txt',
                    'crossdomain.xml', 'clientaccesspolicy.xml',
                ]
                if any(x in path.lower() for x in sensitive_patterns):
                    rule = "G9"
                    cat = "files"
                    severity = "info"
                    title = f"Sensitive File Candidate: {path}"
                    desc = "Potentially sensitive web path discovered by directory brute-force."
                    if status_code == 200:
                        severity = "high"
                        title = f"Sensitive File Exposed: {path}"
                        desc = "Sensitive path appears reachable over HTTP and may expose secrets or internal data."
                    elif status_code in [301, 302, 307, 308]:
                        severity = "medium"
                        title = f"Sensitive File Redirected: {path}"
                        desc = "Sensitive path redirects and may still be reachable indirectly."
                    elif status_code in [401, 403]:
                        severity = "info"
                        title = f"Sensitive File Restricted: {path}"
                        desc = "Sensitive path exists but is access-controlled. Verify that access controls cannot be bypassed."

                    findings.append(self._create_finding(
                        target, "gobuster", rule, cat, severity,
                        title, desc,
                        {"observed": f"{path} (status {status_code})" if status_code else path, "raw_path": gobuster_files[0]},
                        ["remove_sensitive_files"]
                    ))
                elif any(x in path.lower() for x in metafile_patterns):
                    rule = "G8"
                    cat = "information"
                    findings.append(self._create_finding(
                        target, "gobuster", rule, cat, "low",
                        f"Metafile Exposed: {path}",
                        "Web server metafile discovered. May reveal internal paths or site structure to attackers.",
                        {"observed": f"{path} (status {status_code})" if status_code else path, "raw_path": gobuster_files[0]},
                        ["review_metafiles"]
                    ))
                elif "status" in path.lower():
                    rule = "M1"
                    cat = "information"
                    severity = "info"
                    title = f"Status Page Candidate: {path}"
                    desc = "A status-like path exists, but public exposure was not confirmed."
                    if status_code in [200, 301, 302, 307, 308]:
                        severity = "medium"
                        title = f"Status Page Exposed: {path}"
                        desc = "Server administrative status page is publicly accessible."
                    elif status_code in [401, 403]:
                        severity = "info"
                        title = f"Status Page Restricted: {path}"
                        desc = "Status endpoint exists but is access-restricted."

                    findings.append(self._create_finding(
                        target, "gobuster", rule, cat, severity,
                        title, desc,
                        {"observed": f"{path} (status {status_code})" if status_code else path, "raw_path": gobuster_files[0]},
                        ["restrict_status_page"]
                    ))
        except Exception as e:
            print(f"Error parsing Gobuster: {e}")
            
        return findings

    def _normalize_curl(self, raw_path: str, target: Dict) -> List[Dict]:
        findings = []
        curl_files = glob.glob(os.path.join(raw_path, "curl.json"))
        if not curl_files:
            return findings
            
        try:
            with open(curl_files[0], "r") as f:
                data = json.load(f)
                
            if data.get("trace_enabled"):
                findings.append(self._create_finding(
                    target, "curl", "G3", "methods", "medium",
                    "TRACE Method Enabled", "HTTP TRACE method is permitted, increasing risk of XST.",
                    {"observed": "TRACE / HTTP/1.1 200 OK", "raw_path": curl_files[0]},
                    ["disable_trace"]
                ))
                
            if data.get("server_header"):
                server_ident = data["server_header"]
                if any(char.isdigit() for char in server_ident):
                    findings.append(self._create_finding(
                        target, "curl", "G1", "fingerprinting", "low",
                        "Server Version Disclosure", "HTTP Server header explicitly reveals software version.",
                        {"observed": f"Server: {server_ident}", "raw_path": curl_files[0]},
                        [f"{target['name']}_hide_version"]
                    ))
        except Exception as e:
            print(f"Error parsing cURL: {e}")
            
        return findings





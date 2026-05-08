# WebServerSecLab

WebServerSecLab is a Python-based security auditing framework for lab web servers. It combines automated external scanning, remote host-level agent checks, rule-driven normalization, and SSH-executed remediation into a single Streamlit web application. The tool targets Apache, NGINX, and OpenLiteSpeed deployments running in local lab or Vagrant-based environments.

Supported platforms:

- Apache 2.4
- NGINX 1.x
- OpenLiteSpeed

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [End-to-End Workflow](#end-to-end-workflow)
4. [Scanning Subsystem](#scanning-subsystem)
5. [Agent-Based Host Checks](#agent-based-host-checks)
6. [Normalization and Enrichment](#normalization-and-enrichment)
7. [Hardening Subsystem](#hardening-subsystem)
8. [Module Reference](#module-reference)
9. [UI Pages](#ui-pages)
10. [Data Contracts](#data-contracts)
11. [Setup](#setup)
12. [Full Rule Catalog](#full-rule-catalog)

---

## Features

- Network and web scanning via Nmap, Nikto, testssl.sh, and Gobuster
- SSH-based remote agent for host-level checks (package state, TLS key permissions, runtime user, web root permissions, loaded modules)
- Unified normalization layer mapping all scanner and agent evidence to canonical rule IDs from a YAML-driven catalog
- WSTG, CWE, and CVSS enrichment on every finding
- CVE version-matching against a local cache for Apache and NGINX
- Automated SSH remediation playbook execution with per-step result capture, service verification, and live OLS post-checks
- Exportable findings in JSON, CSV, and print-ready HTML
- Cross-run scan history and basic trend tracking
- Docker-preferred scanner execution with per-run container reuse across multiple targets
- Persistent background scan and hardening jobs that survive page reloads and navigation
- Streamlit UI with a structured scan -> findings -> harden -> rescan -> compare workflow

---

## Project Structure

```
webserverseclab/
├── app.py                      # Streamlit entry point and navigation
├── Dockerfile                  # Container image definition
├── docker-compose.yml          # Docker Compose service definition
├── requirements.txt            # Python dependencies
│
├── core/                       # Core engine
│   ├── runner.py               # Run lifecycle orchestration
│   ├── normalize.py            # Scanner output normalization and enrichment
│   ├── hardening.py            # Remediation registry and SSH execution engine
│   ├── agent_runner.py         # Remote SSH agent deployment and execution
│   ├── report_exports.py       # Export generation (JSON, CSV, HTML)
│   ├── rules_db.py             # Rule catalog loader and validator
│   ├── ssh_manager.py          # SSH connection management (Paramiko)
│   ├── storage.py              # Run directory and artifact management
│   └── cve_cache.py            # Local CVE version-match cache
│
├── scanners/                   # External scanner integrations
│   ├── base.py                 # Abstract base class with Docker fallback logic
│   ├── nmap_scanner.py         # Nmap network and service scanner
│   ├── nikto_scanner.py        # Nikto web application scanner
│   ├── testssl_scanner.py      # testssl.sh TLS assessment scanner
│   ├── gobuster_scanner.py     # Gobuster directory and file enumeration
│   ├── curl_scanner.py         # Curl HTTP method and header probe
│   └── trivy_scanner.py        # Trivy OS/package scanner (agent-mode stub)
│
├── ui/                         # Streamlit pages and components
│   ├── dashboard.py            # Dashboard: run overview and trends
│   ├── targets.py              # Target inventory management
│   ├── audit.py                # Scan execution and orchestration UI
│   ├── findings.py             # Findings report review and export
│   ├── hardening_plan.py       # Security control catalog browser
│   ├── harden.py               # Hardening playbook generation and execution
│   ├── execute_hardening.py    # Hardening execution and results page
│   ├── compare.py              # Cross-run comparison (before/after findings)
│   ├── settings.py             # Scan profile and app configuration
│   ├── navigation.py           # Shared navigation helpers
│   └── report_utils.py         # Shared report rendering utilities
│
├── agent/
│   └── agent_payloads/
│       └── internal_agent.py   # Remote agent payload (uploaded to targets over SFTP)
│
├── config/
│   ├── targets.json            # Target inventory (name, IP, platform, SSH config)
│   ├── rule_catalog.json       # Rule-to-remediation-tag mapping for UI
│   └── wordlist.txt            # Gobuster directory brute-force wordlist
│
└── data/
    ├── rules.yaml              # Canonical rule catalog (52 entries)
    └── cve_cache.json          # Static CVE cache for version-based matching
```

---

## End-to-End Workflow

Implementation note: the current app runtime also relies on persisted workflow helpers in `core/workflow.py`, background workers in `core/background_jobs.py`, and a fully implemented `ui/compare.py` page even if those are not all reflected in the simplified tree above.

The app is designed as a persistent scan -> findings -> harden -> rescan -> compare workflow. Scan and hardening jobs run in the background, persist their state under `runs/<run_id>/workflow.json`, and continue across reloads or page switches while the user moves through the flow.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  1. TARGET SELECTION                                                    │
│     User selects one or more configured targets on the Scan page        │
│     → run_id generated, per-target raw directories created              │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  2. EXTERNAL SCANNING (parallel per target, 4 worker threads)           │
│     Nmap       → port scan, service versions, NSE scripts               │
│     Nikto      → HTTP vulnerability checks                              │
│     testssl.sh → TLS protocol, cipher, certificate, HSTS assessment     │
│     Gobuster   → directory and sensitive file discovery                 │
│     Curl       → TRACE method and Server header probe                   │
│     Raw outputs written to runs/<run_id>/<target>/raw/                  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  3. AGENT EXECUTION (per target, sequential)                            │
│     Python agent uploaded to remote /tmp via SFTP                       │
│     Executed in quick or deep mode via SSH                              │
│     Checks: package updates, TLS key permissions, runtime user,         │
│             web root permissions, loaded modules                        │
│     JSON output collected as agent.json                                 │
│     Remote payload cleaned up after collection                          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  4. NORMALIZATION AND ENRICHMENT                                        │
│     Each raw source parsed into unified finding objects                 │
│     rule_id resolved via platform-aware alias mapping                   │
│     Findings enriched with WSTG, CWE, CVSS from data/rules.yaml        │
│     CVE cache queried for version-matched vulnerabilities               │
│     Findings merged and deduplicated by rule_id, preserving all         │
│     evidence_entries across sources                                     │
│     Per-target normalized.json written                                  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  5. AGGREGATION AND EXPORT                                              │
│     Run-level summary.json and coverage.json assembled                  │
│     Exportable artifacts written under runs/<run_id>/exports/           │
│       → report.json, findings.csv, report_print.html                   │
│     Canonical scan export written to scans/<scan_id>.json               │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  6. HARDENING (optional, user-initiated)                                │
│     classify_findings() groups findings into auto and manual tags       │
│     build_playbook() constructs ordered SSH step list                   │
│     execute_remediation() runs steps via SSH, captures exit codes       │
│     verify commands confirm each change took effect                     │
│     hardening_report.json records per-step results and artifacts        │
└─────────────────────────────────────────────────────────────────────────┘
```

In the UI, the intended operator path is: start a scan on **Scan**, review the completed run on **Findings**, open the remediation plan on **Harden**, trigger the follow-up rescan from the hardening report, and finish on **Compare** to inspect the before/after finding tables side by side.

---

## Scanning Subsystem

All scanners live under `scanners/` and inherit from `BaseScanner`. Each scanner is responsible for deterministic invocation, raw output persistence, and producing a parser-friendly artifact for the normalizer. When Docker is available, the base class prefers Docker-backed scanner runtimes by default and keeps one long-lived container per scanner per run so multiple targets do not repeatedly pay container startup cost.

### BaseScanner (`scanners/base.py`)

Defines the shared interface for all external scanners. Key behaviors:

- `scan(target)` — abstract method every scanner implements
- `_run_subprocess(cmd, ...)` — executes the scanner command, captures stdout/stderr, enforces a 600-second timeout
- `_wrap_in_docker(cmd, image)` — rewrites the command to execute inside a reused Docker container for the active run
- Raw outputs are saved to `runs/<run_id>/<target>/raw/` via `StorageManager`

Docker images used by the scanner runtime:

| Scanner | Docker Image |
|---------|-------------|
| Nmap | `instrumentisto/nmap` |
| Nikto | `frapsoft/nikto` |
| testssl.sh | `drwetter/testssl.sh` |
| Gobuster | `trickest/gobuster` |

### Nmap (`scanners/nmap_scanner.py`)

Performs network reconnaissance against web-relevant ports (80, 443, 7080).

- Service version detection (`-sV`) surfaces banner and version strings
- NSE scripts run: `http-methods`, `http-server-header`, `ssl-cert`
- Output format: XML (`nmap.xml`)
- Normalizer extracts: version disclosure (G1), TRACE method presence (G3), self-signed or expired certificates (G4-CERT), OLS admin port exposure

### Nikto (`scanners/nikto_scanner.py`)

Runs HTTP and HTTPS web application checks using tuning mode `123b`.

- Covers CGI vulnerabilities, file disclosure, HTTP method abuse, and header checks
- Output format: plaintext stdout (`nikto_stdout.txt`)
- Normalizer extracts: directory listing (G2), TRACE/DELETE method enabled (G3), missing security headers (G5), server version in header (G1)

### testssl.sh (`scanners/testssl_scanner.py`)

Performs comprehensive TLS security assessment.

- Scans the target's configured HTTPS port from `targets.json`
- Uses `443` by default for Apache/NGINX
- For OpenLiteSpeed, retries sensible HTTPS targets (`443`, configured `https_port`, and `7080`) so the same scan flow can handle both the pre-hardening admin-port TLS surface and the post-hardening public listener
- Tests supported protocol versions (TLS 1.0, 1.1, 1.2, 1.3)
- Tests cipher suite strength and deprecation
- Validates certificate chain, expiry, self-signature, and trust
- Checks HSTS header presence and max-age value
- Checks for DNS CAA record configuration
- Tests for known TLS vulnerabilities (BEAST, POODLE, Heartbleed, etc.)
- Stale output files (JSON/HTML) are removed before each run to prevent false-negative verification
- Detects and surfaces `scanProblem`/`FATAL` conditions
- Output format: JSON (`testssl.json`), optional HTML (`testssl.html`)
- Normalizer maps findings to: G4-CERT, G4-PROTO, G4-CIPHER, G4-HSTS, G4-CAA, G4-VULN, G5

### Gobuster (`scanners/gobuster_scanner.py`)

Enumerates directories and files by dictionary brute-force.

- Wordlist: `config/wordlist.txt` (~35,000 entries)
- 10 concurrent threads, HTTP port 80
- Status code filter: 200, 204, 301, 302, 307, 401, 403
- CRLF normalization applied to wordlist before execution
- Wildcard-response targets are retried with fallback handling instead of being treated as hard scan inconsistencies
- Empty result sets paired with connection/runtime errors are surfaced as scanner failures instead of false-clean output
- Output format: JSON (`gobuster.json`)
- Normalizer extracts: sensitive file paths (G9), metafiles (G8), status/admin pages (M1)

### Curl probe (`scanners/curl_scanner.py`)

Lightweight HTTP probe complementing the above scanners.

- Tests TRACE method by sending a `TRACE /` request and checking for `200 OK`
- Reads `Server` response header to detect version disclosure
- Reads `X-Frame-Options` header for security header coverage
- Output format: JSON (`curl.json`)
- Normalizer maps: G1 (server header), G3 (TRACE), G5 (X-Frame-Options)

---

## Agent-Based Host Checks

The remote agent (`core/agent_runner.py` + `agent/`) runs inside the target server and collects evidence that is not reachable from the network.

**Deployment steps per target:**

1. Agent Python payload uploaded to remote `/tmp` via SFTP
2. Executed via SSH (`python3 /tmp/agent.py --mode quick|deep`)
3. JSON output captured and written as `runs/<run_id>/<target>/agent.json`
4. Remote payload deleted after collection

**Checks performed by the agent:**

| Check | Rule ID | Description |
|-------|---------|-------------|
| Pending package updates | AG-PATCH-STATE | `apt list --upgradable` or equivalent |
| TLS private key permissions | AG-TLS-KEY-PERMS | Key file must not be world/group readable |
| Web service runtime user | AG-RUNTIME-USER | Service should not run as root |
| Web root file permissions | AG-WEBROOT-PERMS | Web root directory permissions |
| Loaded modules | AG-MODULES-01 | Checks for risky or unnecessary modules |
| Platform fingerprint | AG-PLATFORM | Collects version and configuration info |

The agent supports two modes:

- `quick` — fast checks covering the most impactful findings
- `deep` — extended checks including file permission traversal and module enumeration

SSH authentication supports key-based auth, password auth, and key with passphrase. Vagrant key auto-discovery is built into `SSHConnectionManager`.

---

## Normalization and Enrichment

`core/normalize.py` is the central translation layer. It converts heterogeneous raw scanner and agent outputs into a single canonical finding schema, enriches each finding with standards metadata, and deduplicates across sources.

**Processing steps:**

1. Parse each raw source into intermediate finding objects:
   - `_normalize_nmap()` — parses Nmap XML
   - `_normalize_nikto()` — parses Nikto stdout
   - `_normalize_testssl()` — parses testssl JSON
   - `_normalize_gobuster()` — parses Gobuster JSON
   - `_normalize_curl()` — parses curl JSON
   - `_normalize_agent()` — parses agent JSON

2. `map_rule_id()` — resolves generic scanner-emitted IDs (e.g. `G1`, `AG-PATCH-STATE`) to canonical platform-specific IDs (e.g. `G1-Apache-ServerTokens`) using alias tables and platform context

3. `_enrich_with_catalog()` — looks up the resolved rule ID in `data/rules.yaml` and attaches: title, category, WSTG ID, CWE ID, CVSS base score, severity rating, remediation guidance, and references

4. CVE cache lookup — for findings carrying a version string, `cve_cache.py` is queried to inject known CVE findings at the correct severity

5. `_merge_findings_by_rule()` — deduplicates findings with the same rule ID and target, merging `evidence_entries` from all sources into one finding so every contributing scanner is traceable

**Canonical finding schema:**

```
run_id, scan_id, target, server_type, source, rule_id,
category, severity, title, description,
wstg_id, cwe_id, cve_list, cvss,
recommendation, ansible_tags,
evidence, evidence_entries
```

**Outputs written:**

| Path | Contents |
|------|----------|
| `runs/<run_id>/<target>/normalized.json` | Per-target findings |
| `runs/<run_id>/summary.json` | Run-level aggregated summary |
| `runs/<run_id>/coverage.json` | Expected vs found vs missing rules |
| `runs/<run_id>/exports/report.json` | UI-ready report document |
| `runs/<run_id>/exports/findings.csv` | Flat findings table |
| `runs/<run_id>/exports/report_print.html` | Print-ready HTML report |
| `scans/<scan_id>.json` | Cross-run canonical scan export |

---

## Hardening Subsystem

`core/hardening.py` implements the remediation engine. It maps normalized findings to remediation tags, executes the matching SSH steps via Paramiko, runs platform verification and reload commands, and records the outcome in a hardening report.

### Registry

The `REGISTRY` dictionary is the source of truth for all remediation knowledge. Each key is a remediation tag (for example `apache_hide_version`, `nginx_tls_hardening`, or `ols_restrict_admin`). Each entry defines:

```python
"apache_hide_version": {
    "name": "Hide Apache server version",
    "type": "auto",
    "steps": [
        {
            "name": "Set ServerTokens Prod",
            "cmd": "..."
        }
    ]
}
```

Tags are mapped from rule IDs via `RULE_TAG_MAP`. The mapping is many-to-one: multiple rules (e.g. all G4-* TLS sub-rules) can map to a single remediation tag.

### Hardening Lifecycle

**1. Classification**

`classify_findings(findings, platform)` iterates normalized findings, resolves each rule ID to a remediation tag, and divides the result into two buckets:

- `auto` — steps that can be executed non-interactively over SSH (config edits, package installs, service reloads)
- `manual` — steps requiring human action outside SSH scope (DNS CAA record creation, CA operations, credential rotation)

**2. Playbook construction**

`build_playbook(tags, target, platform)` expands each remediation tag into its ordered list of step objects. Steps are de-duplicated, sorted for dependency order, and templated with target-specific variables (paths, service names, platform config file locations).

**3. Execution**

`execute_remediation(target, tags, ssh_conn)` runs each step in order over the established SSH connection:

- Every command is executed as `sudo bash -c '...'`
- `exit_code`, `stdout`, `stderr`, and step status are captured per step
- Results are grouped per remediation tag for the final report

**4. Verification**

After remediation steps execute, the platform-level verify command is run, followed by the reload/restart command. OpenLiteSpeed adds an extra live post-check after restart to confirm that public HTTPS is actually listening on `443`, WebAdmin is no longer publicly reachable on `7080`, and the expected security headers are present in a live response. A follow-up scan is still recommended, especially for TLS work and certificate-related findings.

**5. Reporting**

Every hardening run writes `runs/<run_id>/exports/hardening_report.json` containing:

- `run_id`, `target`, `tags_applied`
- Per-step results: command, exit_code, stdout, stderr, status, timestamps
- Verification / reload / live post-check results
- The generated playbook artifact for each target

**Safety and idempotence practices:**

- Package installs use non-interactive apt commands
- OLS hardening now validates live listener/header state after reload instead of trusting config edits alone
- Non-reversible or infrastructure-level changes are marked `manual` and include guidance text instead of shell commands

---

## Module Reference

### `core/runner.py`

Orchestrates the run lifecycle: creates the `run_id`, distributes targets to worker threads, invokes scanner wrappers and agent execution, triggers normalization, and writes run metadata.

### `core/normalize.py`

Central normalization engine. Parses all raw scanner and agent outputs, maps results to canonical rule IDs, enriches with WSTG/CWE/CVSS metadata from the rule catalog, and produces deduplicated findings with full evidence traces.

### `core/hardening.py`

Remediation registry and SSH execution engine. Defines the `REGISTRY` of platform-specific remediation tags, classifies findings into auto/manual buckets, constructs ordered playbooks, executes steps over SSH, runs verification commands, and exports hardening reports.

### `core/agent_runner.py`

Manages the SSH agent lifecycle: uploads the agent payload via SFTP, executes it in quick or deep mode, collects the JSON result as `agent.json`, and cleans up the remote payload.

### `core/report_exports.py`

Generates all user-facing export formats: the JSON report document, flat CSV findings table, print-optimized HTML report, and severity/target aggregate metrics.

### `core/rules_db.py`

Loads and validates `data/rules.yaml`. Enforces required fields (rule_id, title, category, wstg_id, cwe_id, severity, remediation, references), uniqueness of rule IDs, and HTTPS-only references. Exposes a dictionary-keyed lookup used by the normalizer and UI.

### `core/ssh_manager.py`

Paramiko-based SSH connection manager. Supports key, password, and key-with-passphrase authentication. Includes Vagrant key auto-discovery, secure key storage with restricted file permissions (0o600), and Docker environment detection.

### `core/storage.py`

Manages the `runs/<run_id>/` directory tree. Creates run and per-target directories, provides typed path helpers (`get_raw_filepath`), and persists raw scanner outputs.

### `core/cve_cache.py`

In-memory cache backed by `data/cve_cache.json`. Keyed by `product:version` strings. Used by the normalizer to inject CVE findings when a scanner or agent reports a version string matching a known vulnerable release.

### `scanners/base.py`

Abstract base for all scanner integrations. Provides subprocess execution with timeout enforcement and Docker-first execution with reused per-run containers.

### `scanners/nmap_scanner.py`

Nmap wrapper. Targets ports 80, 443, 7080 with service version detection and HTTP/TLS NSE scripts. Outputs `nmap.xml`.

### `scanners/nikto_scanner.py`

Nikto wrapper. Runs HTTP/HTTPS web checks with tuning mode `123b`. Outputs `nikto_stdout.txt`.

### `scanners/testssl_scanner.py`

testssl.sh wrapper. Full TLS assessment with stale output cleanup, port retry logic, and error surfacing. Outputs `testssl.json`.

### `scanners/gobuster_scanner.py`

Gobuster wrapper. Dictionary-based directory enumeration against port 80 with wildcard and runtime-error handling. Outputs `gobuster.json`.

### `scanners/curl_scanner.py`

Lightweight curl probe for TRACE method and Server/X-Frame-Options headers. Outputs `curl.json`.

---

## UI Pages

The Streamlit application (`app.py`) renders a horizontal navigation bar with the following pages:

| Page | Module | Purpose |
|------|--------|---------|
| Dashboard | `ui/dashboard.py` | Latest run metrics, severity distribution chart, last 12 run history |
| Targets | `ui/targets.py` | Add, edit, and delete targets; SSH key and Vagrant key management |
| Scan | `ui/audit.py` | Target selection, scan or rescan launch, and persistent background execution tracking |
| Findings | `ui/findings.py` | Browse findings by run in a severity-ordered grid and open the next hardening step directly |
| Catalog | `ui/hardening_plan.py` | Browse all 52 catalog rules by category with expandable detail panels |
| Harden | `ui/harden.py` | Structured plan -> execute -> report flow for auto and manual remediation |
| Compare | `ui/compare.py` | Side-by-side run comparison with severity cards, detailed tables, and manual guidance |
| Settings | `ui/settings.py` | Toggle between `standards_mode` (full CVE matching) and `lab_mode` (fast) |

---

## Data Contracts

### Target (`config/targets.json`)

```json
{
  "name": "apache",
  "ip": "192.168.56.10",
  "platform": "apache",
  "https_port": 443,
  "ssh_port": 22,
  "ssh_username": "vagrant",
  "ssh_auth_type": "key",
  "ssh_key_internal_path": "/path/to/secure/key",
  "ssh_key_passphrase": "",
  "ssh_password": ""
}
```

### Normalized Finding

```
run_id          — unique run identifier (timestamp-based)
scan_id         — matches run_id for canonical cross-run export
target          — target name from targets.json
server_type     — platform (apache / nginx / ols)
source          — scanner that produced the evidence (nmap / nikto / testssl / gobuster / curl / agent)
rule_id         — canonical catalog rule ID (e.g. G4-CIPHER)
category        — finding category (e.g. TLS & Transport)
severity        — Critical / High / Medium / Low / Info
title           — human-readable finding title
description     — detailed description
wstg_id         — OWASP WSTG reference (e.g. WSTG-CRYP-01)
cwe_id          — CWE weakness reference
cve_list        — matched CVEs from cve_cache (may be empty)
cvss            — CVSS base score
recommendation  — remediation guidance text
ansible_tags    — list of remediation tags applicable to this finding
evidence        — primary evidence string
evidence_entries — list of per-source evidence objects for full traceability
```

### Run Artifacts

```
runs/<run_id>/
├── <target>/
│   ├── raw/                    # Immutable scanner native outputs
│   │   ├── nmap.xml
│   │   ├── nikto_stdout.txt
│   │   ├── testssl.json
│   │   ├── gobuster.json
│   │   └── curl.json
│   ├── agent.json              # Remote agent JSON output
│   └── normalized.json         # Normalized findings for this target
├── summary.json                # Run-level findings and metrics
├── coverage.json               # Rule coverage (expected/found/missing)
└── exports/
    ├── report.json             # UI-ready report document
    ├── findings.csv            # Flat findings export
    ├── report_print.html       # Print-ready HTML report
    └── hardening_report.json   # Remediation execution results (if run)

scans/<scan_id>.json            # Cross-run canonical scan export
```

---

## Setup

### Local

Requirements: Python 3.11+, and optionally nmap, nikto, testssl.sh, gobuster installed and on PATH.

```bash
pip install -r requirements.txt
streamlit run app.py
```

Docker is the preferred scanner runtime when available. To force local binaries instead, set `WEBSECLAB_SCANNER_MODE=local` before starting the app.

### Docker (all scanners included)

```bash
docker compose up
```

The Dockerfile installs nmap, nikto, gobuster, ansible, curl, openssh-client, and clones testssl.sh from GitHub into the image. The Compose file mounts `~/.vagrant.d` read-only so Vagrant SSH keys are accessible for target authentication.

Access the app at `http://localhost:8501`.

---

## Full Rule Catalog

Source of truth: `data/rules.yaml` — 52 entries.

| # | Rule ID | Title | Category | WSTG | CWE | CVSS | Severity | Scope |
|---|---------|-------|----------|------|-----|------|----------|-------|
| 1 | G1-Apache-ServerTokens | Server Banner Disclosure | Information Disclosure | WSTG-CONF-02 | CWE-200 | 5.3 | Medium | apache |
| 2 | G1-Nginx-ServerTokens | Server Banner Disclosure | Information Disclosure | WSTG-CONF-02 | CWE-200 | 5.0 | Medium | nginx |
| 3 | G2-Directory-Listing | Directory Listing Enabled | Access Control | WSTG-CONF-03 | CWE-548 | 5.3 | Medium | apache, nginx, ols |
| 4 | G3-HTTP-Methods | Risky HTTP Methods Enabled | HTTP Behavior | WSTG-CONF-01 | CWE-693 | 5.9 | Medium | apache, nginx |
| 5 | G4-TLS-Posture | Weak TLS/Transport Posture | TLS & Transport | WSTG-CONF-04 | CWE-326 | 6.8 | Medium | apache, nginx |
| 6 | G5-Security-Headers | Missing Security Response Headers | HTTP Behavior | WSTG-CONF-05 | CWE-693 | 5.4 | Medium | apache, nginx, ols |
| 7 | G6-Logging-Hygiene | Insecure Logging Configuration | Logging & Monitoring | WSTG-CONF-07 | CWE-532 | 5.6 | Medium | apache, nginx, ols |
| 8 | G8-Metafiles | Web Server Metafile Information Exposure | Information Disclosure | WSTG-INFO-03 | CWE-200 | 3.7 | Low | apache, nginx, ols |
| 9 | G9-Sensitive-Files | Sensitive Files Exposed | Information Disclosure | WSTG-CONF-06 | CWE-538 | 7.5 | High | apache, nginx, ols |
| 10 | M1-Status-Page-Exposure | Administrative Status Interface Exposed | Admin Interfaces | WSTG-CONF-08 | CWE-200 | 5.3 | Medium | apache, nginx |
| 11 | AP-A5-G8-AllowOverride | Apache .htaccess Override Risk | Access Control | WSTG-CONF-03 | CWE-16 | 5.3 | Medium | apache |
| 12 | AP-A7-WAF | Apache WAF Not Enforcing | Access Control | WSTG-CONF-08 | CWE-693 | 6.0 | Medium | apache |
| 13 | NG-N2-G2-Autoindex | NGINX Autoindex Enabled | Access Control | WSTG-CONF-03 | CWE-548 | 5.3 | Medium | nginx |
| 14 | NG-N5-G3-Methods-Limits | NGINX Methods and Limits Weak | HTTP Behavior | WSTG-CONF-01 | CWE-16 | 5.9 | Medium | nginx |
| 15 | OLS-O1-Admin-Exposure | OpenLiteSpeed WebAdmin Exposure | Admin Interfaces | WSTG-CONF-08 | CWE-284 | 6.5 | Medium | ols |
| 16 | OLS-O2-Admin-Password | OpenLiteSpeed Weak Admin Password | Admin Interfaces | WSTG-CONF-08 | CWE-521 | 7.1 | High | ols |
| 17 | OLS-HTTP-ONLY | OpenLiteSpeed HTTP-Only Deployment | TLS & Transport | WSTG-CONF-04 | CWE-319 | 5.8 | Medium | ols |
| 18 | CVE-Apache-2.4.49-Traversal | Apache Path Traversal Vulnerability | Components & Dependencies | WSTG-CONF-08 | CWE-22 | 9.8 | Critical | apache |
| 19 | G1 | Server Banner Disclosure | Information Disclosure | WSTG-CONF-02 | CWE-200 | 5.3 | Medium | apache, nginx, ols |
| 20 | G2 | Directory Listing Enabled | Access Control | WSTG-CONF-03 | CWE-548 | 5.3 | Medium | apache, nginx, ols |
| 21 | G3 | Risky HTTP Methods Enabled | HTTP Behavior | WSTG-CONF-01 | CWE-693 | 5.9 | Medium | apache, nginx |
| 22 | G4 | TLS and Transport Misconfiguration | TLS & Transport | WSTG-CONF-04 | CWE-326 | 6.8 | Medium | apache, nginx |
| 23 | G4-CERT | TLS Certificate Trust or Validity Failure | TLS & Transport | WSTG-CRYP-01 | CWE-295 | 7.5 | High | apache, nginx |
| 24 | G4-PROTO | Deprecated TLS Protocol Version Enabled | TLS & Transport | WSTG-CRYP-01 | CWE-326 | 6.5 | Medium | apache, nginx |
| 25 | G4-CIPHER | Weak or Deprecated Cipher Suite Offered | TLS & Transport | WSTG-CRYP-01 | CWE-327 | 5.9 | Medium | apache, nginx |
| 26 | G4-HSTS | HSTS Policy Missing or Insufficient | TLS & Transport | WSTG-CRYP-03 | CWE-523 | 5.4 | Medium | apache, nginx |
| 27 | G4-CAA | DNS CAA Record Not Configured | TLS & Transport | WSTG-CRYP-01 | CWE-295 | 3.7 | Low | apache, nginx |
| 28 | G4-VULN | Known TLS Implementation Vulnerability | TLS & Transport | WSTG-CRYP-01 | CWE-310 | 7.4 | High | apache, nginx |
| 29 | G6 | Logging Misconfiguration | Logging & Monitoring | WSTG-CONF-07 | CWE-532 | 5.6 | Medium | apache, nginx, ols |
| 30 | G5 | Missing Security Response Headers | HTTP Behavior | WSTG-CONF-05 | CWE-693 | 5.4 | Medium | apache, nginx, ols |
| 31 | G7-ETAG-LEAK | ETag Header Leaks Inode Information | Information Disclosure | WSTG-INFO-02 | CWE-200 | 3.7 | Low | apache |
| 32 | G8 | Web Server Metafile Information Exposure | Information Disclosure | WSTG-INFO-03 | CWE-200 | 3.7 | Low | apache, nginx, ols |
| 33 | G9 | Sensitive Files Exposed | Information Disclosure | WSTG-CONF-06 | CWE-538 | 7.5 | High | apache, nginx, ols |
| 34 | M1 | Administrative Status Interface Exposed | Admin Interfaces | WSTG-CONF-08 | CWE-200 | 5.3 | Medium | apache, nginx |
| 35 | AP-A5-G8 | Apache .htaccess Override Risk | Access Control | WSTG-CONF-03 | CWE-16 | 5.3 | Medium | apache |
| 36 | AP-G6-LOGPATH | Apache Logs Exposed In Web Root | Logging & Monitoring | WSTG-CONF-07 | CWE-532 | 7.1 | High | apache |
| 37 | NG-N2-G2 | NGINX Autoindex Enabled | Access Control | WSTG-CONF-03 | CWE-548 | 5.3 | Medium | nginx |
| 38 | NG-N5-G3 | NGINX Methods and Limits Weak | HTTP Behavior | WSTG-CONF-01 | CWE-16 | 5.9 | Medium | nginx |
| 39 | NG-G6-COOKIELOG | NGINX Cookie Logging Enabled | Logging & Monitoring | WSTG-CONF-07 | CWE-532 | 7.1 | High | nginx |
| 40 | OLS-O1-ADMIN | OpenLiteSpeed WebAdmin Exposure | Admin Interfaces | WSTG-CONF-08 | CWE-284 | 6.5 | Medium | ols |
| 41 | OLS-O4-G2 | OpenLiteSpeed Example VHost/Index Exposure | Access Control | WSTG-CONF-03 | CWE-548 | 5.3 | Medium | ols |
| 42 | OLS-O2-ADMIN-PASSWORD | OpenLiteSpeed Weak Admin Password | Admin Interfaces | WSTG-CONF-08 | CWE-521 | 7.1 | High | ols |
| 43 | NIKTO-GEN | Generic Nikto Web Hardening Finding | Information Disclosure | WSTG-CONF-05 | CWE-693 | 5.0 | Medium | apache, nginx, ols |
| 44 | INFO-01 | Exposed Service Surface (Informational) | Components & Dependencies | WSTG-INFO-02 | CWE-200 | 0.0 | Info | apache, nginx, ols |
| 45 | AG-PLATFORM | Platform Fingerprint Collected | Components & Dependencies | WSTG-INFO-08 | CWE-200 | 0.0 | Info | apache, nginx, ols |
| 46 | AG-RUNTIME-USER | Web Service Runtime Account Weakness | Access Control | WSTG-CONF-07 | CWE-250 | 6.5 | Medium | apache, nginx, ols |
| 47 | AG-WEBROOT-PERMS | Weak Web Root Permissions | Access Control | WSTG-CONF-06 | CWE-732 | 6.5 | Medium | apache, nginx, ols |
| 48 | AG-TLS-KEY-PERMS | Weak TLS Private Key Permissions | TLS & Transport | WSTG-CONF-04 | CWE-732 | 7.5 | High | apache, nginx, ols |
| 49 | AG-MODULES-01 | Risky or Unnecessary Modules Enabled | Components & Dependencies | WSTG-CONF-08 | CWE-16 | 5.0 | Medium | apache, nginx, ols |
| 50 | AG-PATCH-STATE | Pending Security Updates | Components & Dependencies | WSTG-CONF-08 | CWE-1104 | 6.0 | Medium | apache, nginx, ols |
| 51 | CVE-Apache-2.4.52-Request-Smuggling | Apache HTTP Server 2.4.52 Request Smuggling Risk | Components & Dependencies | WSTG-CONF-08 | CWE-444 | 9.8 | Critical | apache |
| 52 | CVE-Nginx-1.18.0-Resolver-OOB | NGINX 1.18.0 Resolver Off-By-One Vulnerability Risk | Components & Dependencies | WSTG-CONF-08 | CWE-193 | 7.7 | High | nginx |

Rules G4-CERT through G4-VULN (entries 23–28) replace the former monolithic G4 TLS catch-all with six targeted sub-rules, each with a distinct CWE and WSTG reference. G7-ETAG-LEAK (31) and G8 (32) add dedicated metafile and inode-leak detection. Update this table whenever `data/rules.yaml` changes.

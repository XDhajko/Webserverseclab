#!/usr/bin/env python3
import argparse
import json
import os
import platform
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request


def run_cmd(cmd: str):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def _strip_grep_prefix(line: str) -> str:
    match = re.match(r"^/[^:]+:\d+:(.*)$", line.strip())
    if match:
        return match.group(1).strip()
    return line.strip()


def _probe_response_headers(platform_detected: str) -> dict:
    candidates = [
        "https://127.0.0.1/",
        "https://localhost/",
        "http://127.0.0.1/",
        "http://localhost/",
    ]
    if platform_detected == "ols":
        candidates.extend([
            "https://127.0.0.1:443/",
            "http://127.0.0.1:80/",
        ])

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in candidates:
        req = urllib_request.Request(url, headers={"User-Agent": "WebServerSecLab-Agent/1.0"})
        try:
            with urllib_request.urlopen(req, timeout=6, context=ctx) as resp:
                return {
                    "url": url,
                    "status": resp.getcode(),
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                }
        except urllib_error.HTTPError as exc:
            return {
                "url": url,
                "status": exc.code,
                "headers": {k.lower(): v for k, v in exc.headers.items()},
            }
        except Exception:
            continue

    return {"url": "", "status": None, "headers": {}}


def _listening_addresses(port: int) -> list[str]:
    commands = [
        f"ss -ltnH 2>/dev/null | awk '$4 ~ /:{port}$/ || $4 ~ /\\]:{port}$/ {{print $4}}'",
        f"netstat -ltn 2>/dev/null | awk 'NR>2 && ($4 ~ /:{port}$/ || $4 ~ /\\]:{port}$/) {{print $4}}'",
    ]
    for cmd in commands:
        code, out, _ = run_cmd(cmd)
        if code == 0 and out:
            seen = []
            for line in out.splitlines():
                binding = line.strip()
                if binding and binding not in seen:
                    seen.append(binding)
            if seen:
                return seen
    return []


def _is_local_binding(binding: str) -> bool:
    lower = binding.strip().lower()
    return (
        lower.startswith("127.")
        or lower.startswith("[::1]")
        or lower.startswith("::1:")
        or lower.startswith("localhost:")
    )


def _is_public_binding(binding: str) -> bool:
    lower = binding.strip().lower()
    if not lower or _is_local_binding(lower):
        return False
    if lower.startswith("0.0.0.0:") or lower.startswith("*:") or lower.startswith("[::]:") or lower.startswith(":::"):
        return True
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", lower):
        return True
    if lower.startswith("[") and "]:" in lower and not lower.startswith("[::1]"):
        return True
    return False


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def detect_platform() -> str:
    if Path("/usr/local/lsws").exists() or Path("/usr/local/lsws/conf/httpd_config.conf").exists():
        return "ols"
    code, out, _ = run_cmd("which nginx")
    if code == 0 and out:
        return "nginx"
    code, out, _ = run_cmd("which apache2ctl || which httpd")
    if code == 0 and out:
        return "apache"
    return "unknown"


def get_os_release() -> dict:
    data = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def parse_worker_user(ps_output: str) -> str:
    seen = []
    for line in ps_output.splitlines():
        lower = line.lower()
        if not any(x in lower for x in ["apache2", "httpd", "nginx", "lshttpd"]):
            continue
        parts = line.split()
        if not parts:
            continue
        user = parts[0]
        if user not in seen:
            seen.append(user)
        # Prefer non-root worker processes over master/root processes.
        if user != "root" and ("worker" in lower or "apache2" in lower or "lshttpd" in lower):
            return user

    for user in seen:
        if user != "root":
            return user
    if seen:
        return seen[0]
    return "unknown"


def check_file(path: str) -> dict:
    st = {
        "exists": False,
        "owner": "unknown",
        "group": "unknown",
        "mode": "unknown",
        "permission_denied": False,
    }
    p = Path(path)
    try:
        if not p.exists():
            return st
    except PermissionError:
        # Parent path may be inaccessible for unprivileged user, keep scan alive.
        st["exists"] = True
        st["permission_denied"] = True
        return st
    except Exception:
        return st

    try:
        import pwd
        import grp

        stat_info = p.stat()
        st["exists"] = True
        st["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
        st["group"] = grp.getgrgid(stat_info.st_gid).gr_name
        st["mode"] = oct(stat_info.st_mode & 0o777)
        return st
    except PermissionError:
        st["exists"] = True
        st["permission_denied"] = True
        return st
    except Exception:
        st["exists"] = True
        return st


def discover_config_paths(platform_detected: str) -> dict:
    paths = {
        "web_root": "",
        "config_root": "",
        "tls_key_candidates": [],
        "logs": [],
        "config_files": [],
    }

    if platform_detected == "apache":
        code, out, _ = run_cmd("apache2ctl -V 2>/dev/null | grep SERVER_CONFIG_FILE || httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE")
        if code == 0 and out:
            paths["config_root"] = out
        if not paths["config_root"]:
            if Path("/etc/apache2").exists():
                paths["config_root"] = "/etc/apache2"
            elif Path("/etc/httpd").exists():
                paths["config_root"] = "/etc/httpd"
        paths["web_root"] = "/var/www/html"
        paths["logs"] = ["/var/log/apache2", "/var/log/httpd"]
        paths["config_files"] = [
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
        ]

    elif platform_detected == "nginx":
        code, out, _ = run_cmd("nginx -T 2>/dev/null | head -n 120")
        paths["config_root"] = "/etc/nginx" if Path("/etc/nginx").exists() else out
        paths["web_root"] = "/usr/share/nginx/html"
        paths["logs"] = ["/var/log/nginx"]
        paths["config_files"] = ["/etc/nginx/nginx.conf"]

    elif platform_detected == "ols":
        paths["config_root"] = "/usr/local/lsws/conf"
        # dynamically resolve web root from OLS config
        ols_web_root = "/usr/local/lsws/DEFAULT/html"
        code, wr_out, _ = run_cmd(
            "VH=$(grep -h 'vhRoot' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null | awk '{print $NF}' | sed 's|/$||');"
            " [ -n \"$VH\" ] && [ \"${VH#/}\" = \"$VH\" ] && VH=\"/usr/local/lsws/$VH\";"
            " DR=$(grep -rh 'docRoot' /usr/local/lsws/conf/vhosts/ 2>/dev/null | head -1 | awk '{print $NF}' | sed 's|/$||');"
            " DOC=$(echo \"$DR\" | sed \"s|\\$VH_ROOT|$VH|g;s|\\$SERVER_ROOT|/usr/local/lsws|g\");"
            " [ -n \"$DOC\" ] && [ \"${DOC#/}\" = \"$DOC\" ] && DOC=\"/usr/local/lsws/$DOC\";"
            " echo \"$DOC\""
        )
        if code == 0 and wr_out.strip() and wr_out.strip() != "$VH_ROOT":
            resolved = wr_out.strip()
            if Path(resolved).exists():
                ols_web_root = resolved
        if not Path(ols_web_root).exists():
            code2, fout, _ = run_cmd("find /usr/local/lsws -path '*/html' -type d 2>/dev/null | head -1")
            if code2 == 0 and fout.strip():
                ols_web_root = fout.strip()
        paths["web_root"] = ols_web_root
        paths["logs"] = ["/usr/local/lsws/logs"]
        paths["config_files"] = ["/usr/local/lsws/conf/httpd_config.conf"]

    for candidate in [
        "/etc/ssl/private",
        "/etc/pki/tls/private",
        "/usr/local/lsws/conf",
    ]:
        if Path(candidate).exists():
            code, out, _ = run_cmd(
                f"find {candidate} -maxdepth 4 -type f \\("
                "-name '*.key' -o -name '*.pem' -o -name 'privkey*' \\) "
                "2>/dev/null | head -n 50"
            )
            if code == 0 and out:
                for fp in out.splitlines():
                    fp = fp.strip()
                    if fp and fp not in paths["tls_key_candidates"]:
                        paths["tls_key_candidates"].append(fp)

    # Extend TLS candidates from discovered config values.
    cfg_text = collect_config_text(platform_detected, paths)
    for match in re.findall(r"(?:ssl_certificate_key|keyFile)\s+([^\s;]+)", cfg_text, flags=re.IGNORECASE):
        cleaned = match.strip().strip('"\'')
        if cleaned and cleaned not in paths["tls_key_candidates"]:
            paths["tls_key_candidates"].append(cleaned)

    return paths


def collect_config_text(platform_detected: str, config_paths: dict) -> str:
    if platform_detected == "apache":
        code, out, _ = run_cmd(
            "apache2ctl -S 2>/dev/null; apache2ctl -M 2>/dev/null;"
            " grep -R -nE 'ServerTokens|ServerSignature|AllowOverride|Options|TraceEnable|Header|CustomLog|ErrorLog|SSLCertificateKeyFile'"
            " /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled /etc/httpd/conf /etc/httpd/conf.d"
            " 2>/dev/null | head -n 800"
        )
        return out if code == 0 else ""

    if platform_detected == "nginx":
        code, out, _ = run_cmd("nginx -T 2>/dev/null | head -n 12000")
        return out if code == 0 else ""

    if platform_detected == "ols":
        parts = [
            read_text("/usr/local/lsws/conf/httpd_config.conf"),
            read_text("/usr/local/lsws/admin/conf/admin_config.conf"),
        ]
        # include vhost configs and .htaccess so header/dir-listing checks work
        code, extra, _ = run_cmd(
            "cat /usr/local/lsws/conf/vhosts/*/vhconf.conf* /usr/local/lsws/conf/vhosts/*/vhost.conf* 2>/dev/null;"
            " find /usr/local/lsws -name '.htaccess' -exec cat {} + 2>/dev/null"
        )
        if code == 0 and extra:
            parts.append(extra)
        return "\n".join(parts)

    return ""


def get_enabled_modules(platform_detected: str) -> list:
    modules = []
    if platform_detected == "apache":
        code, out, _ = run_cmd("apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null")
        if code == 0 and out:
            for line in out.splitlines():
                m = line.strip().split()
                if m and "_module" in m[0]:
                    modules.append(m[0])
    elif platform_detected == "nginx":
        code, out, err = run_cmd("nginx -V 2>&1")
        text = out or err
        if code == 0 and text:
            for token in text.split():
                if token.startswith("--with-"):
                    modules.append(token)
    elif platform_detected == "ols":
        conf = read_text("/usr/local/lsws/conf/httpd_config.conf")
        for line in conf.splitlines():
            if "module" in line.lower():
                modules.append(line.strip())

    return modules[:200]


def get_installed_packages() -> dict:
    candidates = ["apache2", "httpd", "nginx", "openlitespeed", "lsws", "openssl"]
    result = {}

    code, out, _ = run_cmd("which dpkg-query")
    if code == 0:
        for pkg in candidates:
            pcode, pout, _ = run_cmd(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null")
            if pcode == 0 and pout:
                result[pkg] = pout
        return result

    code, out, _ = run_cmd("which rpm")
    if code == 0:
        for pkg in candidates:
            pcode, pout, _ = run_cmd(f"rpm -q {pkg} --qf '%{{VERSION}}-%{{RELEASE}}' 2>/dev/null")
            if pcode == 0 and pout:
                result[pkg] = pout

    return result


def get_log_paths_status(paths: list) -> list:
    status = []
    for p in paths:
        status.append({"path": p, "state": check_file(p)})
    return status


def _mode_to_int(mode_str: str) -> int:
    try:
        return int(str(mode_str), 8)
    except Exception:
        return -1


def exposed_file_candidates(web_root: str, worker_user: str) -> list:
    findings = []
    if not web_root:
        return findings
    checks = [".env", ".git/config", "info.php", "backup.sql", "backup_2025.sql"]
    root = Path(web_root)
    if not root.exists():
        return findings
    for rel in checks:
        p = root / rel
        if p.exists():
            state = check_file(str(p))
            mode_int = _mode_to_int(state.get("mode", ""))
            world_readable = mode_int >= 0 and bool(mode_int & 0o004)
            owner_readable_for_worker = (
                mode_int >= 0
                and bool(mode_int & 0o400)
                and state.get("owner") == worker_user
                and worker_user not in ["", "unknown"]
            )
            findings.append({
                "path": str(p),
                "state": state,
                "likely_readable": bool(world_readable or owner_readable_for_worker),
            })
    return findings


def install_temp_trivy() -> tuple:
    code, out, _ = run_cmd("which trivy")
    if code == 0 and out:
        return out, False, ""

    install_cmds = [
        "command -v curl >/dev/null 2>&1 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /tmp/webserverseclab_trivy",
        "command -v wget >/dev/null 2>&1 && wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /tmp/webserverseclab_trivy",
    ]

    install_err = ""
    for cmd in install_cmds:
        code, out, err = run_cmd(cmd)
        if code == 0 and Path("/tmp/webserverseclab_trivy/trivy").exists():
            return "/tmp/webserverseclab_trivy/trivy", True, ""
        if err:
            install_err = err

    return "", False, install_err or "Trivy install script failed"


def apache_specific_checks(config_dump: str, web_root: str) -> list:
    checks = []
    cd = config_dump.lower()

    allow_override_all = bool(re.search(r"allowoverride\s+all\b", cd))
    allow_override_none = bool(re.search(r"allowoverride\s+none\b", cd))
    has_allow_override = "allowoverride" in cd
    if allow_override_all:
        a5_status = "fail"
        a5_evidence = "AllowOverride All found — .htaccess can override any directive"
    elif allow_override_none:
        a5_status = "pass"
        a5_evidence = "AllowOverride None set — .htaccess overrides disabled"
    elif has_allow_override:
        a5_status = "fail"
        a5_evidence = "AllowOverride directive found with partial override scope"
    else:
        a5_status = "unknown"
        a5_evidence = "No AllowOverride directive found in configuration"
    checks.append({
        "rule_id": "AP-A5-G8",
        "category": "config",
        "severity": "medium",
        "title": "Apache AllowOverride broad override",
        "status": a5_status,
        "evidence": a5_evidence,
        "recommendation": "Use AllowOverride None unless .htaccess behavior is strictly required.",
    })

    modsec_loaded = "security2_module" in cd
    detect_only = "secruleengine detectiononly" in cd
    if modsec_loaded and not detect_only:
        waf_status = "pass"
        waf_evidence = "ModSecurity loaded and SecRuleEngine is active"
    elif modsec_loaded and detect_only:
        waf_status = "fail"
        waf_evidence = "ModSecurity loaded but SecRuleEngine is in DetectionOnly mode (not blocking)"
    else:
        waf_status = "fail"
        waf_evidence = "ModSecurity (security2_module) is not loaded"
    checks.append({
        "rule_id": "AP-A7-WAF",
        "category": "modules",
        "severity": "medium",
        "title": "Apache ModSecurity disabled or detect-only",
        "status": waf_status,
        "evidence": waf_evidence,
        "recommendation": "Enable ModSecurity with blocking mode for production security policy.",
    })

    log_in_webroot = False
    log_evidence_line = ""
    for line in config_dump.splitlines():
        ll = line.lower()
        if "customlog" in ll or "errorlog" in ll:
            if web_root and web_root in line:
                log_in_webroot = True
                log_evidence_line = line.strip()
                break

    checks.append({
        "rule_id": "AP-G6-LOGPATH",
        "category": "logging",
        "severity": "high",
        "title": "Apache logs in web root",
        "status": "fail" if log_in_webroot else "pass",
        "evidence": f"Log writing to web root detected: {log_evidence_line}" if log_in_webroot else "No log files found within the document root",
        "recommendation": "Store logs under system log directories, not document roots.",
    })

    return checks


def nginx_specific_checks(config_dump: str) -> list:
    checks = []
    active_lines = []
    for line in config_dump.splitlines():
        ll = line.strip().lower()
        if not ll or ll.startswith("#"):
            continue
        active_lines.append(ll)
    cd = "\n".join(active_lines)

    autoindex_on = bool(re.search(r"autoindex\s+on\b", cd))
    autoindex_off = bool(re.search(r"autoindex\s+off\b", cd))
    has_any_nginx_cfg = "server {" in cd or "http {" in cd
    if autoindex_on:
        n2_status = "fail"
    elif autoindex_off:
        n2_status = "pass"
    elif has_any_nginx_cfg:
        # nginx default is autoindex off when not explicitly enabled.
        n2_status = "pass"
    else:
        n2_status = "unknown"
    checks.append({
        "rule_id": "NG-N2-G2",
        "category": "files",
        "severity": "medium",
        "title": "Nginx autoindex enabled",
        "status": n2_status,
        "evidence": "autoindex directives inspected in nginx configuration",
        "recommendation": "Disable autoindex in public locations.",
    })

    has_method_restriction = (
        "limit_except" in cd
        or "$request_method !~" in cd
        or "restrict-methods.conf" in cd
    )
    has_size_limit = "client_max_body_size" in cd
    evidence_parts = []
    if not has_method_restriction:
        evidence_parts.append("No effective method restriction found")
    if not has_size_limit:
        evidence_parts.append("No client_max_body_size directive found")
    if not evidence_parts:
        evidence_parts.append("Method restriction and client_max_body_size are configured")
    checks.append({
        "rule_id": "NG-N5-G3",
        "category": "methods",
        "severity": "medium",
        "title": "Nginx methods and request limits",
        "status": "pass" if (has_method_restriction and has_size_limit) else "fail",
        "evidence": "; ".join(evidence_parts),
        "recommendation": "Restrict methods and set request size/buffer limits for abuse resistance.",
    })

    cookie_in_log = "$http_cookie" in cd
    has_log_format = "log_format" in cd
    has_access_log = "access_log" in cd
    if cookie_in_log:
        g6_status = "fail"
    elif has_log_format or has_access_log:
        # If access_log is configured without cookie variables, treat as non-cookie logging.
        g6_status = "pass"
    else:
        g6_status = "unknown"
    checks.append({
        "rule_id": "NG-G6-COOKIELOG",
        "category": "logging",
        "severity": "high",
        "title": "Nginx log includes cookies",
        "status": g6_status,
        "evidence": "log_format directives inspected for cookie variable usage",
        "recommendation": "Avoid logging session cookies in access logs.",
    })

    return checks


def ols_specific_checks(config_dump: str, process_snapshot: str) -> list:
    checks = []
    cd = config_dump.lower()

    admin_bindings = _listening_addresses(7080)
    admin_bindings_text = ", ".join(admin_bindings) if admin_bindings else "none"
    admin_exposed = any(_is_public_binding(binding) for binding in admin_bindings)
    admin_local = bool(admin_bindings) and all(_is_local_binding(binding) for binding in admin_bindings)
    admin_local_cfg = bool(re.search(r"address\s+(?:127\.0\.0\.1|localhost):7080\b", cd))
    admin_declared = "7080" in cd or "adminlistener" in cd
    if admin_exposed:
        admin_status = "fail"
        admin_evidence = f"WebAdmin listener is bound to public interface(s): {admin_bindings_text}"
    elif admin_local:
        admin_status = "pass"
        admin_evidence = f"WebAdmin listener is restricted to localhost ({admin_bindings_text})"
    elif admin_local_cfg:
        admin_status = "pass"
        admin_evidence = "Config restricts WebAdmin to localhost and no public 7080 listener was detected"
    elif admin_declared:
        admin_status = "unknown"
        admin_evidence = f"WebAdmin listener declared in config, but no live binding could be confirmed (live bindings: {admin_bindings_text})"
    else:
        admin_status = "unknown"
        admin_evidence = "No explicit WebAdmin listener declaration found"

    checks.append({
        "rule_id": "OLS-O1-ADMIN",
        "category": "admin_surface",
        "severity": "medium",
        "title": "OpenLiteSpeed WebAdmin exposure",
        "status": admin_status,
        "evidence": admin_evidence,
        "recommendation": "Bind WebAdmin to localhost or management-only interfaces.",
    })

    allow_browse_on = bool(re.search(r"allowbrowse\s+1\b", cd))
    autoindex_on = bool(re.search(r"autoindex\s+1\b", cd))
    example_vhost_or_index = allow_browse_on or autoindex_on
    checks.append({
        "rule_id": "OLS-O4-G2",
        "category": "files",
        "severity": "medium",
        "title": "OpenLiteSpeed example vhost or directory listing",
        "status": "fail" if example_vhost_or_index else "pass",
        "evidence": (
            "allowBrowse 1 or autoIndex 1 detected in OLS vhost config"
            if example_vhost_or_index
            else "No allowBrowse/autoIndex exposure patterns detected"
        ),
        "recommendation": "Disable directory listing and remove sample/example vhost content.",
    })

    https_bindings = _listening_addresses(443)
    https_bindings_text = ", ".join(https_bindings) if https_bindings else "none"
    has_https_listener = ":443" in cd or "listener ssl" in cd or "listener https" in cd or "secure 1" in cd
    has_public_https = any(_is_public_binding(binding) for binding in https_bindings)
    has_local_https_only = bool(https_bindings) and not has_public_https
    checks.append({
        "rule_id": "OLS-HTTP-ONLY",
        "category": "tls",
        "severity": "medium",
        "title": "OpenLiteSpeed lacks HTTPS listener",
        "status": "pass" if has_public_https else "fail",
        "evidence": (
            f"HTTPS listener is live on public binding(s): {https_bindings_text}"
            if has_public_https
            else (
                f"HTTPS listener is only bound locally: {https_bindings_text}"
                if has_local_https_only
                else (
                    "HTTPS listener is declared in config but no live public 443 listener was detected"
                    if has_https_listener
                    else "No HTTPS listener found in config or live sockets"
                )
            )
        ),
        "recommendation": "Enable HTTPS listener and redirect HTTP to HTTPS.",
    })

    htpasswd_state = check_file("/usr/local/lsws/admin/conf/htpasswd")
    htpasswd_text = read_text("/usr/local/lsws/admin/conf/htpasswd")
    weak_sha = "{sha}fEqNCco3Yq9h5ZUglD3CZJT4lBs=".lower()
    has_weak_literal = ":123456" in htpasswd_text
    has_weak_sha = weak_sha in htpasswd_text.lower()
    if has_weak_literal or has_weak_sha:
        o2_status = "fail"
        o2_evidence = "OLS admin htpasswd matches weak default password indicator (123456)."
    elif htpasswd_state.get("permission_denied"):
        o2_status = "unknown"
        o2_evidence = "Cannot read OLS admin password file due to permissions."
    elif htpasswd_state.get("exists") and htpasswd_text.strip():
        o2_status = "pass"
        o2_evidence = "OLS admin htpasswd present and no known weak default marker found."
    else:
        o2_status = "unknown"
        o2_evidence = "OLS admin password file not found or empty."

    checks.append({
        "rule_id": "OLS-O2-ADMIN-PASSWORD",
        "category": "auth",
        "severity": "high",
        "title": "OpenLiteSpeed weak admin password",
        "status": o2_status,
        "evidence": o2_evidence,
        "recommendation": "Set a strong non-default admin password and store it securely.",
    })

    return checks


def build_checks(platform_detected: str, config_paths: dict, worker_user: str) -> list:
    checks = []
    config_dump = collect_config_text(platform_detected, config_paths)
    modules = get_enabled_modules(platform_detected)

    checks.append({
        "rule_id": "AG-PLATFORM",
        "category": "discovery",
        "severity": "info",
        "title": "Platform detection",
        "status": "pass" if platform_detected != "unknown" else "unknown",
        "evidence": f"Detected platform: {platform_detected}",
        "recommendation": "Verify platform-specific hardening profile is selected.",
    })

    if worker_user == "root":
        runtime_status = "fail"
    elif worker_user == "unknown":
        runtime_status = "unknown"
    else:
        runtime_status = "pass"

    checks.append({
        "rule_id": "AG-RUNTIME-USER",
        "category": "permissions",
        "severity": "medium",
        "title": "Web runtime user least privilege",
        "status": runtime_status,
        "evidence": f"Worker process user: {worker_user}",
        "recommendation": "Run web workers as a dedicated non-root service account.",
    })

    web_root = config_paths.get("web_root", "")
    web_root_state = check_file(web_root) if web_root else {"exists": False}
    wr_mode = web_root_state.get("mode", "unknown")
    if not web_root_state.get("exists"):
        wr_status = "unknown"
    elif wr_mode in ["0o777", "0o776", "0o775"]:
        wr_status = "fail"
    else:
        wr_status = "pass"
    checks.append({
        "rule_id": "AG-WEBROOT-PERMS",
        "category": "permissions",
        "severity": "medium",
        "title": "Web root permissions",
        "status": wr_status,
        "evidence": f"Web root {web_root}: owner={web_root_state.get('owner', '?')}, group={web_root_state.get('group', '?')}, mode={wr_mode}",
        "recommendation": "Ensure web root ownership and permissions are restricted.",
    })

    tls_private_ok = False
    tls_private_bad = False
    tls_evidence = []
    for p in config_paths.get("tls_key_candidates", []):
        state = check_file(p)
        tls_evidence.append({"path": p, "state": state})
        if state.get("exists") and state.get("mode") in ["0o600", "0o640"]:
            tls_private_ok = True
        elif state.get("exists") and state.get("mode") in ["0o777", "0o755", "0o775", "0o666"]:
            tls_private_bad = True

    if tls_private_bad:
        tls_status = "fail"
    elif tls_private_ok:
        tls_status = "pass"
    else:
        tls_status = "unknown"

    checks.append({
        "rule_id": "AG-TLS-KEY-PERMS",
        "category": "tls",
        "severity": "high",
        "title": "TLS private key permissions",
        "status": tls_status,
        "evidence": json.dumps(tls_evidence),
        "recommendation": "Restrict private key access to root and service group only.",
    })

    # Build active directives (exclude comments and grep prefixes) for directive checks.
    active_directives = []
    for line in config_dump.splitlines():
        directive = _strip_grep_prefix(line).lower()
        if not directive or directive.startswith("#"):
            continue
        active_directives.append(directive)
    active_dump = "\n".join(active_directives)

    # Fingerprinting and version disclosure checks.
    fp_fail = False
    fp_evidence = "No version-disclosure directives found in config"
    if platform_detected == "apache":
        fp_fail = any(
            re.match(r"servertokens\s+full\b", d) or re.match(r"serversignature\s+on\b", d)
            for d in active_directives
        )
        if fp_fail:
            fp_evidence = "Apache config contains ServerTokens Full or ServerSignature On"
        else:
            fp_evidence = "Apache config does not expose ServerTokens Full or ServerSignature On"
    elif platform_detected == "nginx":
        fp_fail = "server_tokens on" in active_dump
        fp_evidence = "nginx server_tokens on" if fp_fail else "nginx server_tokens not enabled (default: off)"
    checks.append({
        "rule_id": "AG-FP-01",
        "category": "fingerprinting",
        "severity": "medium",
        "title": "Server fingerprinting disclosure controls",
        "status": "fail" if fp_fail else "pass",
        "evidence": fp_evidence,
        "recommendation": "Suppress version and signature disclosure in server responses.",
    })

    # Directory listing risk.
    dir_listing_matches = []
    for line in config_dump.splitlines():
        directive = _strip_grep_prefix(line).lower()
        # skip comments
        if directive.startswith("#"):
            continue
        if "options" in directive and "indexes" in directive and "-indexes" not in directive:
            dir_listing_matches.append(line.strip())
        elif "autoindex on" in directive or "autoindex 1" in directive:
            dir_listing_matches.append(line.strip())
    dir_listing_fail = len(dir_listing_matches) > 0
    checks.append({
        "rule_id": "AG-DIR-01",
        "category": "files",
        "severity": "medium",
        "title": "Directory listing controls",
        "status": "fail" if dir_listing_fail else "pass",
        "evidence": "\n".join(dir_listing_matches[:10]) if dir_listing_matches else "No directory listing directives found in config",
        "recommendation": "Disable directory auto-indexing for public paths.",
    })

    # HTTP methods exposure.
    trace_enabled = any(re.match(r"traceenable\s+on\b", d) for d in active_directives)
    trace_disabled = any(re.match(r"traceenable\s+off\b", d) for d in active_directives)
    if trace_enabled:
        methods_status = "fail"
        methods_evidence = "TraceEnable On found in server configuration"
    elif trace_disabled:
        methods_status = "pass"
        methods_evidence = "TraceEnable Off explicitly set in config"
    elif platform_detected in ["nginx", "ols"]:
        # TRACE is not supported by nginx/OLS by default
        methods_status = "pass"
        methods_evidence = f"{platform_detected} does not support TRACE by default"
    else:
        methods_status = "unknown"
        methods_evidence = "No explicit TraceEnable directive found in Apache config"
    checks.append({
        "rule_id": "AG-METHODS-01",
        "category": "methods",
        "severity": "medium",
        "title": "Potentially risky HTTP method settings",
        "status": methods_status,
        "evidence": methods_evidence,
        "recommendation": "Disable TRACE and restrict unneeded methods.",
    })

    # Security headers presence.
    headers = [
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    ]
    found_headers = [h for h in headers if h in active_dump]
    header_probe = _probe_response_headers(platform_detected)
    live_headers = header_probe.get("headers", {}) if isinstance(header_probe, dict) else {}
    live_found_headers = [h for h in headers if h in live_headers]
    header_evidence = []
    header_evidence.append(
        f"Detected headers in config: {', '.join(found_headers) if found_headers else 'none'}"
    )
    if header_probe.get("url"):
        header_evidence.append(
            f"Detected headers in live response ({header_probe.get('url')} status {header_probe.get('status')}): "
            f"{', '.join(live_found_headers) if live_found_headers else 'none'}"
        )
    if header_probe.get("url"):
        header_status = "pass" if live_found_headers else "fail"
    else:
        header_status = "pass" if found_headers else "fail"
        header_evidence.append("No live response header probe succeeded")
    checks.append({
        "rule_id": "AG-HEADERS-01",
        "category": "headers",
        "severity": "medium",
        "title": "Security headers configuration presence",
        "status": header_status,
        "evidence": "\n".join(header_evidence),
        "recommendation": "Configure HSTS, X-Frame-Options, X-Content-Type-Options, and CSP where applicable.",
    })

    # Logging paths/status.
    log_states = get_log_paths_status(config_paths.get("logs", []))
    checks.append({
        "rule_id": "AG-LOG-01",
        "category": "logging",
        "severity": "low",
        "title": "Logging path availability",
        "status": "pass" if any(s.get("state", {}).get("exists") for s in log_states) else "unknown",
        "evidence": json.dumps(log_states),
        "recommendation": "Ensure access and error logs are enabled and retained securely.",
    })

    # Module inventory.
    checks.append({
        "rule_id": "AG-MODULES-01",
        "category": "modules",
        "severity": "low",
        "title": "Enabled module inventory",
        "status": "pass" if modules else "unknown",
        "evidence": "\n".join(modules[:60]) if modules else "No module inventory collected",
        "recommendation": "Disable unnecessary modules to reduce attack surface.",
    })

    # Potentially exposed files in web root.
    exposed = exposed_file_candidates(web_root, worker_user)
    exposed_readable = [f for f in exposed if f.get("likely_readable")]
    if exposed_readable:
        exposed_status = "fail"
        exposed_severity = "high"
        exposed_evidence = "\n".join(
            f"{f.get('path')} (mode={f.get('state', {}).get('mode', 'unknown')}, owner={f.get('state', {}).get('owner', 'unknown')})"
            for f in exposed_readable
        )
    elif exposed:
        exposed_status = "unknown"
        exposed_severity = "low"
        exposed_evidence = (
            "Sensitive filenames exist but appear permission-restricted for the runtime user:\n"
            + "\n".join(
                f"{f.get('path')} (mode={f.get('state', {}).get('mode', 'unknown')}, owner={f.get('state', {}).get('owner', 'unknown')})"
                for f in exposed
            )
        )
    else:
        exposed_status = "pass"
        exposed_severity = "high"
        exposed_evidence = "No common sensitive filenames found in web root"

    checks.append({
        "rule_id": "AG-EXPOSED-01",
        "category": "files",
        "severity": exposed_severity,
        "title": "Sensitive file indicators in web root",
        "status": exposed_status,
        "evidence": exposed_evidence,
        "recommendation": "Remove or block sensitive files from public document roots.",
    })

    if platform_detected == "apache":
        checks.extend(apache_specific_checks(config_dump, web_root))
    elif platform_detected == "nginx":
        checks.extend(nginx_specific_checks(config_dump))
    elif platform_detected == "ols":
        checks.extend(ols_specific_checks(config_dump, ""))

    return checks


def collect_package_state(mode: str) -> dict:
    pkg = {
        "upgradable": [],
        "installed_packages": get_installed_packages(),
        "trivy": {"mode": mode, "status": "skipped"},
    }

    code, out, _ = run_cmd("apt list --upgradable 2>/dev/null | sed '1d' | head -n 200")
    if code == 0 and out:
        pkg["upgradable"] = out.splitlines()

    if mode == "deep":
        trivy_bin, installed_tmp, install_err = install_temp_trivy()
        if not trivy_bin:
            pkg["trivy"] = {"mode": mode, "status": "install-failed", "error": install_err}
            return pkg

        tcode, tout, terr = run_cmd(f"{trivy_bin} rootfs --quiet --skip-db-update --format json / 2>/dev/null | head -c 120000")
        if tcode == 0 and tout:
            pkg["trivy"] = {
                "mode": mode,
                "status": "ok",
                "summary": tout,
                "binary": trivy_bin,
                "installed_temp": installed_tmp,
            }
        else:
            pkg["trivy"] = {
                "mode": mode,
                "status": "error",
                "error": terr,
                "binary": trivy_bin,
                "installed_temp": installed_tmp,
            }

        if installed_tmp:
            run_cmd("rm -f /tmp/webserverseclab_trivy/trivy")

    return pkg


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="quick", choices=["quick", "deep"])
    args = parser.parse_args()

    platform_detected = detect_platform()
    os_release = get_os_release()
    _, ps_out, _ = run_cmd("ps -eo user,comm,args")
    worker_user = parse_worker_user(ps_out)
    config_paths = discover_config_paths(platform_detected)

    result = {
        "agent_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "os_release": os_release,
        },
        "platform_detected": platform_detected,
        "evidence": {
            "config_paths": config_paths,
            "process_snapshot": ps_out[:4000],
        },
        "checks": build_checks(platform_detected, config_paths, worker_user),
        "package_state": collect_package_state(args.mode),
        "cleanup_hint": "Controller should delete uploaded script from /tmp after execution",
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()

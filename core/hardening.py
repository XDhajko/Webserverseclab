"""
Ansible-driven hardening engine.

Builds dynamic playbooks from scan findings and executes
remediation tasks over SSH via paramiko.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from core.ssh_manager import SSHConnectionManager

logger = logging.getLogger(__name__)

# ── Platform service definitions ─────────────────────────────────────────

PLATFORM_SVC: Dict[str, Dict[str, str]] = {
    "apache": {"verify": "apache2ctl -t 2>&1", "reload": "systemctl reload apache2"},
    "nginx":  {"verify": "nginx -t 2>&1",      "reload": "systemctl reload nginx"},
    "ols":    {
        "verify": "if [ -x /usr/local/lsws/bin/openlitespeed ]; then /usr/local/lsws/bin/openlitespeed -t 2>&1; else echo 'OpenLiteSpeed verify binary not found'; exit 1; fi",
        "reload": "systemctl restart lsws 2>&1 || /usr/local/lsws/bin/lswsctrl restart",
    },
}

# Shared shell snippet: resolve OLS document root dynamically
_OLS_DOCROOT = (
    "VH_ROOT=$(grep -h 'vhRoot' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null"
    " | awk '{print $NF}' | sed 's|/$||' | head -1);"
    " [ -n \"$VH_ROOT\" ] && [ \"${VH_ROOT#/}\" = \"$VH_ROOT\" ] && VH_ROOT=\"/usr/local/lsws/$VH_ROOT\";"
    " DOCROOT=$(grep -rh 'docRoot' /usr/local/lsws/conf/vhosts/ 2>/dev/null"
    " | head -1 | awk '{print $NF}' | sed 's|/$||');"
    ' DOCROOT=$(echo "$DOCROOT" | sed "s|\\$VH_ROOT|$VH_ROOT|g");'
    ' DOCROOT=$(echo "$DOCROOT" | sed "s|\\$SERVER_ROOT|/usr/local/lsws|g");'
    " [ -n \"$DOCROOT\" ] && [ \"${DOCROOT#/}\" = \"$DOCROOT\" ] && DOCROOT=\"/usr/local/lsws/$DOCROOT\";"
    " [ -z \"$DOCROOT\" ] && DOCROOT=$(find /usr/local/lsws -path '*/html' -type d 2>/dev/null | head -1);"
    " [ -z \"$DOCROOT\" ] && DOCROOT='/usr/local/lsws/Example/html'"
)

_OLS_VHOST_CONFIGS = (
    "find /usr/local/lsws/conf/vhosts -type f \\("
    " -name 'vhconf.conf*' -o -name 'vhost.conf*' \\)"
)

_OLS_VHOST_LOOP = (
    "for F in /usr/local/lsws/conf/vhosts/*/vhconf.conf*"
    " /usr/local/lsws/conf/vhosts/*/vhost.conf*; do"
)

_OLS_BIND_ADMIN_LOCAL = (
    "CONF=/usr/local/lsws/admin/conf/admin_config.conf;"
    " [ -f \"$CONF\" ] || exit 1;"
    " sed -i -E 's#^([[:space:]]*address)[[:space:]]+[^[:space:]]+:7080([[:space:]]*)$#\\1               127.0.0.1:7080#'"
    " \"$CONF\" 2>/dev/null;"
    " awk 'BEGIN {local_seen=0}"
    " /^[[:space:]]*address[[:space:]]+127\\.0\\.0\\.1:7080([[:space:]]|$)/ { if (local_seen++) next }"
    " { print }' \"$CONF\" > \"$CONF.tmp\" && mv \"$CONF.tmp\" \"$CONF\";"
    " grep -qE '^[[:space:]]*address[[:space:]]+127\\.0\\.0\\.1:7080\\b' \"$CONF\" 2>/dev/null"
    " || sed -i '/^[[:space:]]*listener[[:space:]]\\+/a\\  address               127.0.0.1:7080' \"$CONF\" 2>/dev/null;"
    " grep -qE '^[[:space:]]*address[[:space:]]+127\\.0\\.0\\.1:7080\\b' \"$CONF\" 2>/dev/null || exit 1"
)

_OLS_REBUILD_HTTPS_LISTENER = (
    "CONF=/usr/local/lsws/conf/httpd_config.conf;"
    " [ -f \"$CONF\" ] || exit 1;"
    " VH_NAME=$(grep -m1 '^virtualHost ' \"$CONF\" 2>/dev/null | awk '{print $2}');"
    " [ -z \"$VH_NAME\" ] && VH_NAME=Example;"
    " HTTP_MAPS=$(awk '"
    "BEGIN {in_listener=0; has_http=0; maps=\"\"}"
    " !in_listener && /^[[:space:]]*listener[[:space:]]+[^[:space:]]+[[:space:]]*\\{[[:space:]]*$/ {"
    "   in_listener=1; has_http=0; maps=\"\"; next"
    " }"
    " in_listener {"
    "   if ($0 ~ /^[[:space:]]*address[[:space:]]+[^[:space:]]*:80([[:space:]]|$)/) has_http=1;"
    "   if ($0 ~ /^[[:space:]]*map[[:space:]]+[^[:space:]]+[[:space:]]+/) maps = maps $0 ORS;"
    "   if ($0 ~ /^[[:space:]]*}[[:space:]]*$/) {"
    "     if (has_http && maps != \"\") { printf \"%s\", maps; exit }"
    "     in_listener=0; has_http=0; maps=\"\""
    "   }"
    " }' \"$CONF\");"
    " [ -z \"$HTTP_MAPS\" ] && HTTP_MAPS=\"  map                     ${VH_NAME} *\";"
    " TMP=$(mktemp);"
    " awk '"
    "BEGIN {in_managed=0; in_listener=0; drop=0; buf=\"\"}"
    " /^[[:space:]]*# webserverseclab https begin[[:space:]]*$/ {in_managed=1; next}"
    " /^[[:space:]]*# webserverseclab https end[[:space:]]*$/ {in_managed=0; next}"
    " in_managed {next}"
    " !in_listener && /^[[:space:]]*listener[[:space:]]+[^[:space:]]+[[:space:]]*\\{[[:space:]]*$/ {"
    "   in_listener=1;"
    "   drop=($0 ~ /^[[:space:]]*listener[[:space:]]+(HTTPS|Secure)[[:space:]]*\\{[[:space:]]*$/);"
    "   buf=$0 ORS;"
    "   next"
    " }"
    " in_listener {"
    "   if ($0 ~ /^[[:space:]]*address[[:space:]]+[^[:space:]]*:443([[:space:]]|$)/) drop=1;"
    "   buf = buf $0 ORS;"
    "   if ($0 ~ /^[[:space:]]*}[[:space:]]*$/) {"
    "     if (!drop) printf \"%s\", buf;"
    "     buf=\"\"; in_listener=0; drop=0"
    "   }"
    "   next"
    " }"
    " {print}"
    " END { if (in_listener && !drop) printf \"%s\", buf }' \"$CONF\" > \"$TMP\""
    " && mv \"$TMP\" \"$CONF\";"
    " cat >> \"$CONF\" <<EOF\n"
    "# webserverseclab https begin\n"
    "listener HTTPS {\n"
    "  address                 *:443\n"
    "  secure                  1\n"
    "  keyFile                 /usr/local/lsws/conf/key.pem\n"
    "  certFile                /usr/local/lsws/conf/cert.pem\n"
    "${HTTP_MAPS}\n"
    "}\n"
    "# webserverseclab https end\n"
    "EOF\n"
    " MANAGED_BLOCK=$(awk '/# webserverseclab https begin/,/# webserverseclab https end/' \"$CONF\");"
    " echo \"$MANAGED_BLOCK\" | grep -qE '^[[:space:]]*address[[:space:]]+\\*:443\\b'"
    " && echo \"$MANAGED_BLOCK\" | grep -qE '^[[:space:]]*secure[[:space:]]+1\\b'"
    " && echo \"$MANAGED_BLOCK\" | grep -qE '^[[:space:]]*keyFile[[:space:]]+/usr/local/lsws/conf/key\\.pem\\b'"
    " && echo \"$MANAGED_BLOCK\" | grep -qE '^[[:space:]]*certFile[[:space:]]+/usr/local/lsws/conf/cert\\.pem\\b'"
    " && echo \"$MANAGED_BLOCK\" | grep -qE '^[[:space:]]*map[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+'"
    " || exit 1"
)

_OLS_ALLOW_HTTPS = (
    "if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then"
    " ufw allow 443/tcp >/dev/null 2>&1 || true;"
    " fi;"
    " if command -v iptables >/dev/null 2>&1; then"
    " iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1"
    " || iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true;"
    " fi;"
    " if command -v ip6tables >/dev/null 2>&1; then"
    " ip6tables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1"
    " || ip6tables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true;"
    " fi;"
)

_OLS_RESTRICT_ADMIN_NETWORK = (
    "if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then"
    " ufw deny 7080/tcp >/dev/null 2>&1 || true;"
    " fi;"
    " if command -v iptables >/dev/null 2>&1; then"
    " iptables -C INPUT -p tcp --dport 7080 ! -s 127.0.0.1 -j REJECT >/dev/null 2>&1"
    " || iptables -I INPUT -p tcp --dport 7080 ! -s 127.0.0.1 -j REJECT >/dev/null 2>&1 || true;"
    " fi;"
    " if command -v ip6tables >/dev/null 2>&1; then"
    " ip6tables -C INPUT -p tcp --dport 7080 -j REJECT >/dev/null 2>&1"
    " || ip6tables -I INPUT -p tcp --dport 7080 -j REJECT >/dev/null 2>&1 || true;"
    " fi;"
)

_OLS_LIVE_POSTCHECK = (
    "set -e;"
    " HTTPS_BINDINGS=$(ss -ltnH 2>/dev/null | awk '$4 ~ /:443$/ || $4 ~ /\\]:443$/ {print $4}' | tr '\\n' ' ');"
    " ADMIN_BINDINGS=$(ss -ltnH 2>/dev/null | awk '$4 ~ /:7080$/ || $4 ~ /\\]:7080$/ {print $4}' | tr '\\n' ' ');"
    " echo \"HTTPS 443 bindings: ${HTTPS_BINDINGS:-none}\";"
    " echo \"Admin 7080 bindings: ${ADMIN_BINDINGS:-none}\";"
    " echo \"$HTTPS_BINDINGS\" | grep -Eq '(^| )(0\\.0\\.0\\.0:443|\\*:443|\\[::\\]:443|::+:443|[0-9]{1,3}(\\.[0-9]{1,3}){3}:443)( |$)';"
    " if echo \"$ADMIN_BINDINGS\" | grep -Eq '(^| )(0\\.0\\.0\\.0:7080|\\*:7080|\\[::\\]:7080|::+:7080|[0-9]{1,3}(\\.[0-9]{1,3}){3}:7080)( |$)'; then"
    " echo 'OLS WebAdmin is still publicly reachable on port 7080' >&2; exit 1;"
    " fi;"
    " if curl -k -I -s --max-time 8 https://127.0.0.1/ >/tmp/webserverseclab_ols_headers.txt; then"
    " echo 'Header probe target: https://127.0.0.1/';"
    " grep -qi '^strict-transport-security:' /tmp/webserverseclab_ols_headers.txt;"
    " else"
    " curl -I -s --max-time 8 http://127.0.0.1/ >/tmp/webserverseclab_ols_headers.txt;"
    " echo 'Header probe target: http://127.0.0.1/';"
    " fi;"
    " grep -qi '^x-frame-options:' /tmp/webserverseclab_ols_headers.txt;"
    " grep -qi '^x-content-type-options:' /tmp/webserverseclab_ols_headers.txt;"
    " grep -qi '^referrer-policy:' /tmp/webserverseclab_ols_headers.txt;"
)


# ── Remediation task registry ────────────────────────────────────────────
#
# Maps each ansible tag -> remediation definition.
#   name   - human-readable label
#   type   - "auto" | "manual"
#   steps  - list of {name, cmd[, platform]} dicts  (auto only)
#   note   - markdown instructions                  (manual only)

REGISTRY: Dict[str, Dict[str, Any]] = {

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  APACHE                                                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    "apache_hide_version": {
        "name": "Hide Apache server version",
        "type": "auto",
        "steps": [
            {
                "name": "Set ServerTokens Prod",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " grep -qE '^[[:space:]]*ServerTokens\\b' \"$F\""
                    " && sed -i 's/^[[:space:]]*ServerTokens .*/ServerTokens Prod/' \"$F\""
                    " || echo 'ServerTokens Prod' >> \"$F\";"
                    " done"
                ),
            },
            {
                "name": "Set ServerSignature Off",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " grep -qE '^[[:space:]]*ServerSignature\\b' \"$F\""
                    " && sed -i 's/^[[:space:]]*ServerSignature .*/ServerSignature Off/' \"$F\""
                    " || echo 'ServerSignature Off' >> \"$F\";"
                    " done"
                ),
            },
        ],
    },

    "apache_no_autoindex": {
        "name": "Disable Apache directory listing",
        "type": "auto",
        "steps": [
            {"name": "Disable autoindex module", "cmd": "a2dismod -f autoindex 2>/dev/null; true"},
            {"name": "Disable userdir module", "cmd": "a2dismod -f userdir 2>/dev/null; true"},
            {
                "name": "Replace Options Indexes with -Indexes across Apache configs",
                "cmd": (
                    "find /etc/apache2 -type f -name '*.conf'"
                    " -exec sed -i -E '/^[[:space:]]*Options[[:space:]]+/ s/[[:space:]][+-]?Indexes([[:space:]]|$)/\\1/g;"
                    " /^[[:space:]]*Options[[:space:]]+$/ s//Options FollowSymLinks/' {} +"
                    " 2>/dev/null; true"
                ),
            },
        ],
    },

    "apache_disable_trace": {
        "name": "Disable TRACE method (Apache)",
        "type": "auto",
        "steps": [
            {
                "name": "Set TraceEnable Off",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " grep -qE '^[[:space:]]*TraceEnable\\b' \"$F\""
                    " && sed -i 's/^[[:space:]]*TraceEnable .*/TraceEnable Off/' \"$F\""
                    " || echo 'TraceEnable Off' >> \"$F\";"
                    " done"
                ),
            },
        ],
    },

    "apache_tls_hardening": {
        "name": "Harden Apache TLS configuration",
        "type": "auto",
        "steps": [
            {"name": "Enable SSL and headers modules", "cmd": "a2enmod ssl headers 2>/dev/null; true"},
            {"name": "Disable deflate module to mitigate BREACH", "cmd": "a2dismod -f deflate 2>/dev/null; true"},
            {
                "name": "Enforce TLSv1.2+ protocols",
                "cmd": "sed -i 's/^\\s*SSLProtocol .*/SSLProtocol -all +TLSv1.2 +TLSv1.3/' /etc/apache2/mods-enabled/ssl.conf",
            },
            {
                "name": "Set strong cipher suite",
                "cmd": "sed -i 's|^\\s*SSLCipherSuite .*|SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256|' /etc/apache2/mods-enabled/ssl.conf",
            },
            {
                "name": "Prefer server cipher order",
                "cmd": (
                    "grep -q '^\\s*SSLHonorCipherOrder' /etc/apache2/mods-enabled/ssl.conf"
                    " && sed -i 's/^\\s*SSLHonorCipherOrder .*/SSLHonorCipherOrder on/' /etc/apache2/mods-enabled/ssl.conf"
                    " || echo 'SSLHonorCipherOrder on' >> /etc/apache2/mods-enabled/ssl.conf"
                ),
            },
        ],
    },

    "apache_security_headers": {
        "name": "Add Apache security response headers",
        "type": "auto",
        "steps": [
            {"name": "Enable headers module", "cmd": "a2enmod headers 2>/dev/null; true"},
            {
                "name": "Add Strict-Transport-Security",
                "cmd": (
                    "grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+set[[:space:]]+Strict-Transport-Security\\b'"
                    " /etc/apache2/conf-enabled/security.conf"
                    ' || echo \'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\''
                    " >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
            {
                "name": "Add X-Content-Type-Options",
                "cmd": (
                    "grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+set[[:space:]]+X-Content-Type-Options\\b'"
                    " /etc/apache2/conf-enabled/security.conf"
                    ' || echo \'Header always set X-Content-Type-Options "nosniff"\''
                    " >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
            {
                "name": "Add X-Frame-Options",
                "cmd": (
                    "grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+set[[:space:]]+X-Frame-Options\\b'"
                    " /etc/apache2/conf-enabled/security.conf"
                    ' || echo \'Header always set X-Frame-Options "SAMEORIGIN"\''
                    " >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
            {
                "name": "Add Referrer-Policy",
                "cmd": (
                    "grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+set[[:space:]]+Referrer-Policy\\b'"
                    " /etc/apache2/conf-enabled/security.conf"
                    ' || echo \'Header always set Referrer-Policy "strict-origin-when-cross-origin"\''
                    " >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
            {
                "name": "Add Permissions-Policy",
                "cmd": (
                    "grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+set[[:space:]]+Permissions-Policy\\b'"
                    " /etc/apache2/conf-enabled/security.conf"
                    ' || echo \'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"\''
                    " >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
        ],
    },

    "apache_disable_directory_listing": {
        "name": "Disable Apache directory listing",
        "type": "auto",
        "steps": [
            {
                "name": "Set Options -Indexes globally",
                "cmd": (
                    "grep -q '^\\s*Options.*-Indexes' /etc/apache2/conf-enabled/security.conf"
                    " || echo 'Options -Indexes' >> /etc/apache2/conf-enabled/security.conf"
                ),
            },
        ],
    },

    "apache_secure_logging": {
        "name": "Secure Apache log paths",
        "type": "auto",
        "steps": [
            {
                "name": "Ensure ErrorLog under /var/log",
                "cmd": "sed -i 's|^\\s*ErrorLog .*|ErrorLog ${APACHE_LOG_DIR}/error.log|' /etc/apache2/apache2.conf",
            },
        ],
    },

    "apache_restrict_overrides": {
        "name": "Restrict Apache AllowOverride",
        "type": "auto",
        "steps": [
            {
                "name": "Set AllowOverride None for /var/www/",
                "cmd": "sed -i '/<Directory \\/var\\/www\\/>/,/<\\/Directory>/s/AllowOverride .*/AllowOverride None/' /etc/apache2/apache2.conf",
            },
        ],
    },

    "apache_enable_modsecurity": {
        "name": "Install and enable ModSecurity WAF",
        "type": "auto",
        "steps": [
            {"name": "Install libapache2-mod-security2", "cmd": "DEBIAN_FRONTEND=noninteractive apt-get install -y libapache2-mod-security2 2>/dev/null; true"},
            {"name": "Copy recommended config", "cmd": "[ -f /etc/modsecurity/modsecurity.conf-recommended ] && cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf; true"},
            {"name": "Set SecRuleEngine On", "cmd": "sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf 2>/dev/null; true"},
            {"name": "Enable security2 module", "cmd": "a2enmod security2 2>/dev/null; true"},
        ],
    },

    "apache_upgrade": {
        "name": "Upgrade Apache packages",
        "type": "auto",
        "steps": [
            {"name": "Update package list", "cmd": "apt-get update -qq"},
            {"name": "Upgrade apache2", "cmd": "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y apache2 2>/dev/null; true"},
        ],
    },

    "apache_fix_etag": {
        "name": "Fix Apache ETag inode leak",
        "type": "auto",
        "steps": [
            {
                "name": "Disable ETag generation",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " grep -qE '^[[:space:]]*FileETag\\b' \"$F\""
                    " && sed -i 's/^[[:space:]]*FileETag .*/FileETag None/' \"$F\""
                    " || echo 'FileETag None' >> \"$F\";"
                    " done"
                ),
            },
            {
                "name": "Explicitly unset ETag response header",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " grep -qE '^[[:space:]]*Header[[:space:]]+always[[:space:]]+unset[[:space:]]+ETag\\b' \"$F\""
                    " || echo 'Header always unset ETag' >> \"$F\";"
                    " done"
                ),
            },
        ],
    },

    "apache_fix_logpath": {
        "name": "Move Apache logs out of webroot",
        "type": "auto",
        "steps": [
            {
                "name": "Redirect any webroot logs to /var/log/apache2",
                "cmd": (
                    "find /etc/apache2/ -name '*.conf' -exec"
                    " sed -i 's|ErrorLog /var/www/[^ ]*|ErrorLog /var/log/apache2/error.log|g;"
                    " s|CustomLog /var/www/[^ ]*|CustomLog /var/log/apache2/access.log|g' {} + 2>/dev/null; true"
                ),
            },
        ],
    },

    "apache_tls_certificate": {
        "name": "Deploy valid TLS certificate (Apache)",
        "type": "manual",
        "steps": [],
        "note": (
            "Self-signed certificates cannot be automatically replaced "
            "with CA-signed ones.\n\n"
            "**Option A** - Let's Encrypt (recommended):\n"
            "```bash\n"
            "sudo apt install certbot python3-certbot-apache\n"
            "sudo certbot --apache -d yourdomain.com\n"
            "```\n\n"
            "**Option B** - Generate a stronger self-signed cert:\n"
            "```bash\n"
            "openssl req -x509 -nodes -days 365 -newkey rsa:4096 \\\n"
            "  -keyout /etc/ssl/private/apache-selfsigned.key \\\n"
            "  -out /etc/ssl/certs/apache-selfsigned.crt \\\n"
            "  -subj '/CN=localhost' -sha256\n"
            "```"
        ),
    },

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  NGINX                                                       ║
    # ╚═══════════════════════════════════════════════════════════════╝

    "nginx_hide_version": {
        "name": "Hide Nginx server version",
        "type": "auto",
        "steps": [
            {
                "name": "Set server_tokens off",
                "cmd": (
                    "grep -qP '^\\s*server_tokens' /etc/nginx/nginx.conf"
                    " && sed -i 's/^\\(\\s*\\)server_tokens .*/\\1server_tokens off;/' /etc/nginx/nginx.conf"
                    " || sed -i '/http\\s*{/a\\    server_tokens off;' /etc/nginx/nginx.conf"
                ),
            },
        ],
    },

    "nginx_no_autoindex": {
        "name": "Disable Nginx directory listing",
        "type": "auto",
        "steps": [
            {
                "name": "Disable autoindex in all configs",
                "cmd": (
                    "for F in /etc/nginx/nginx.conf /etc/nginx/conf.d/* /etc/nginx/snippets/*"
                    " /etc/nginx/sites-available/* /etc/nginx/sites-enabled/*; do"
                    " [ -f \"$F\" ] || continue;"
                    " sed -i -E 's/autoindex[[:space:]]+on[[:space:]]*;/autoindex off;/Ig' \"$F\" 2>/dev/null;"
                    " done; true"
                ),
            },
        ],
    },

    "nginx_restrict_methods": {
        "name": "Restrict Nginx HTTP methods",
        "type": "auto",
        "steps": [
            {
                "name": "Create method-restriction snippet",
                "cmd": (
                    "mkdir -p /etc/nginx/snippets;"
                    " cat > /etc/nginx/snippets/restrict-methods.conf << 'EOF'\n"
                    "if ($request_method !~ ^(GET|HEAD|POST)$ ) {\n"
                    "    return 405;\n"
                    "}\n"
                    "EOF"
                ),
            },
            {
                "name": "Include snippet in default site",
                "cmd": (
                    "for F in /etc/nginx/sites-enabled/*; do"
                    " sed -i '/restrict-methods/d' \"$F\" 2>/dev/null;"
                    " sed -i '0,/server_name/{/server_name/a\\    include /etc/nginx/snippets/restrict-methods.conf;\n}' \"$F\" 2>/dev/null;"
                    " done; true"
                ),
            },
            {
                "name": "Set client_max_body_size baseline",
                "cmd": (
                    "grep -qP '^\\s*client_max_body_size\\b' /etc/nginx/nginx.conf"
                    " && sed -i 's/^\\(\\s*\\)client_max_body_size .*/\\1client_max_body_size 10m;/' /etc/nginx/nginx.conf"
                    " || sed -i '/http\\s*{/a\\    client_max_body_size 10m;' /etc/nginx/nginx.conf"
                ),
            },
        ],
    },

    "nginx_tls_hardening": {
        "name": "Harden Nginx TLS configuration",
        "type": "auto",
        "steps": [
            {
                "name": "Create TLS hardening snippet",
                "cmd": (
                    "mkdir -p /etc/nginx/snippets;"
                    " cat > /etc/nginx/snippets/ssl-hardening.conf << 'EOF'\n"
                    "ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
                    "ssl_prefer_server_ciphers on;\n"
                    "ssl_session_tickets off;\n"
                    "EOF"
                ),
            },
            {
                "name": "Disable gzip to mitigate BREACH",
                "cmd": (
                    "grep -qP '^\\s*gzip\\s' /etc/nginx/nginx.conf"
                    " && sed -i 's/^\\(\\s*\\)gzip .*/\\1gzip off;/' /etc/nginx/nginx.conf"
                    " || sed -i '/http\\s*{/a\\    gzip off;' /etc/nginx/nginx.conf"
                ),
            },
            {
                "name": "Include TLS snippet in SSL site config",
                "cmd": (
                    "for F in /etc/nginx/sites-enabled/*; do"
                    " if grep -q 'ssl_certificate' \"$F\" 2>/dev/null; then"
                    "   sed -i '/ssl-hardening/d' \"$F\";"
                    "   sed -i '/^\\s*ssl_protocols /d;"
                    " /^\\s*ssl_ciphers /d;"
                    " /^\\s*ssl_prefer_server_ciphers /d;"
                    " /^\\s*add_header\\s\\+Strict-Transport-Security\\b/d' \"$F\";"
                    "   sed -i '0,/ssl_certificate /{/ssl_certificate /a\\    include /etc/nginx/snippets/ssl-hardening.conf;\n}' \"$F\";"
                    " fi;"
                    " done; true"
                ),
            },
        ],
    },

    "nginx_security_headers": {
        "name": "Add Nginx security response headers",
        "type": "auto",
        "steps": [
            {
                "name": "Create security headers snippet",
                "cmd": (
                    "mkdir -p /etc/nginx/snippets;"
                    " cat > /etc/nginx/snippets/security-headers.conf << 'EOF'\n"
                    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
                    'add_header X-Content-Type-Options "nosniff" always;\n'
                    'add_header X-Frame-Options "SAMEORIGIN" always;\n'
                    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
                    'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;\n'
                    "EOF"
                ),
            },
            {
                "name": "Include headers snippet in site configs",
                "cmd": (
                    "for F in /etc/nginx/sites-enabled/*; do"
                    " sed -i '/security-headers/d' \"$F\" 2>/dev/null;"
                    " sed -i '/add_header\\s\\+Strict-Transport-Security\\b/d;"
                    " /add_header\\s\\+X-Content-Type-Options\\b/d;"
                    " /add_header\\s\\+X-Frame-Options\\b/d;"
                    " /add_header\\s\\+Referrer-Policy\\b/d;"
                    " /add_header\\s\\+Permissions-Policy\\b/d' \"$F\" 2>/dev/null;"
                    " sed -i '0,/server_name/{/server_name/a\\    include /etc/nginx/snippets/security-headers.conf;\n}' \"$F\" 2>/dev/null;"
                    " done; true"
                ),
            },
        ],
    },

    "nginx_secure_logging": {
        "name": "Secure Nginx log paths",
        "type": "auto",
        "steps": [
            {
                "name": "Ensure access_log under /var/log/nginx",
                "cmd": (
                    "grep -qP '^\\s*access_log' /etc/nginx/nginx.conf"
                    " && sed -i 's|^\\(\\s*\\)access_log .*|\\1access_log /var/log/nginx/access.log;|'"
                    " /etc/nginx/nginx.conf; true"
                ),
            },
        ],
    },

    "nginx_upgrade": {
        "name": "Upgrade Nginx packages",
        "type": "auto",
        "steps": [
            {"name": "Update package list", "cmd": "apt-get update -qq"},
            {"name": "Upgrade nginx", "cmd": "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y nginx 2>/dev/null; true"},
        ],
    },

    "nginx_fix_etag": {
        "name": "Fix Nginx ETag inode leak",
        "type": "auto",
        "steps": [
            {
                "name": "Disable etag in http block",
                "cmd": (
                    "grep -qP '^\\s*etag\\s' /etc/nginx/nginx.conf"
                    " && sed -i 's/^\\(\\s*\\)etag .*/\\1etag off;/' /etc/nginx/nginx.conf"
                    " || sed -i '/http\\s*{/a\\    etag off;' /etc/nginx/nginx.conf"
                ),
            },
        ],
    },

    "nginx_fix_cookie_logging": {
        "name": "Remove cookie fields from Nginx logs",
        "type": "auto",
        "steps": [
            {
                "name": "Strip $http_cookie from log_format directives",
                "cmd": (
                    "find /etc/nginx/ -name '*.conf'"
                    " -exec sed -i 's/\\$http_cookie//g' {} + 2>/dev/null; true"
                ),
            },
        ],
    },

    "nginx_tls_certificate": {
        "name": "Deploy valid TLS certificate (Nginx)",
        "type": "manual",
        "steps": [],
        "note": (
            "Self-signed certificates cannot be automatically replaced.\n\n"
            "**Option A** - Let's Encrypt:\n"
            "```bash\n"
            "sudo apt install certbot python3-certbot-nginx\n"
            "sudo certbot --nginx -d yourdomain.com\n"
            "```\n\n"
            "**Option B** - Generate a stronger self-signed cert:\n"
            "```bash\n"
            "openssl req -x509 -nodes -days 365 -newkey rsa:4096 \\\n"
            "  -keyout /etc/ssl/private/nginx.key \\\n"
            "  -out /etc/ssl/certs/nginx.crt \\\n"
            "  -subj '/CN=localhost' -sha256\n"
            "```"
        ),
    },

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  OLS (OpenLiteSpeed)                                         ║
    # ╚═══════════════════════════════════════════════════════════════╝

    "ols_no_autoindex": {
        "name": "Disable OLS directory listing",
        "type": "auto",
        "steps": [
            {
                "name": "Set autoIndex and allowBrowse to safe defaults",
                "cmd": (
                    _OLS_VHOST_CONFIGS
                    + " -exec sed -i -E"
                    " 's#^([[:space:]]*[Aa]uto[Ii]ndex)[[:space:]]+1\\b#\\1 0#g;"
                    " s#^([[:space:]]*allowBrowse)[[:space:]]+1\\b#\\1 0#g' {} +"
                    " 2>/dev/null;"
                    + _OLS_VHOST_LOOP
                    + " [ -f \"$F\" ] || continue;"
                    " grep -qi '^[[:space:]]*[Aa]uto[Ii]ndex[[:space:]]+0\\b' \"$F\" 2>/dev/null"
                    " || sed -i '/context \\/ {/a\\  autoIndex            0' \"$F\" 2>/dev/null;"
                    " grep -qi '^[[:space:]]*allowBrowse[[:space:]]+0\\b' \"$F\" 2>/dev/null"
                    " || sed -i '/context \\/ {/a\\  allowBrowse         0' \"$F\" 2>/dev/null;"
                    " done;"
                    " find /usr/local/lsws -name '.htaccess' -exec sed -i -E"
                    " '/^[[:space:]]*Options[[:space:]]+/ s/[[:space:]][+-]?Indexes([[:space:]]|$)/ -Indexes\\1/g' {} +"
                    " 2>/dev/null; true"
                ),
            },
        ],
    },

    "ols_security_headers": {
        "name": "Add OLS security headers via vhost config",
        "type": "auto",
        "steps": [
            {
                "name": "Inject OLS extraHeaders directives in vhost root context",
                "cmd": (
                    _OLS_VHOST_LOOP
                    + " [ -f \"$F\" ] || continue;"
                    " sed -i '/extraHeaders[[:space:]]\\+<<<END_webserverseclab_headers/,/END_webserverseclab_headers/d' \"$F\" 2>/dev/null;"
                    " if grep -q 'context / {' \"$F\" 2>/dev/null; then"
                    "   sed -i -E 's#^([[:space:]]*accessible)[[:space:]]+.*#\\1              1#g' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\END_webserverseclab_headers' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\Permissions-Policy: geolocation=(self \"\")' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\Referrer-Policy: strict-origin-when-cross-origin' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\X-Content-Type-Options: nosniff' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\X-Frame-Options: SAMEORIGIN' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\Strict-Transport-Security: max-age=31536000; includeSubDomains' \"$F\" 2>/dev/null;"
                    "   grep -qi '^[[:space:]]*accessible[[:space:]]+1\\b' \"$F\" 2>/dev/null"
                    "   || sed -i '/context \\/ {/a\\  accessible              1' \"$F\" 2>/dev/null;"
                    "   grep -qi '^[[:space:]]*location[[:space:]]+\\$DOC_ROOT/' \"$F\" 2>/dev/null"
                    "   || sed -i '/context \\/ {/a\\  location                $DOC_ROOT/' \"$F\" 2>/dev/null;"
                    "   sed -i '/context \\/ {/a\\  extraHeaders            <<<END_webserverseclab_headers' \"$F\" 2>/dev/null;"
                    " else"
                    "   cat >> \"$F\" <<'EOF'\n"
                    "# webserverseclab headers context begin\n"
                    "context / {\n"
                    "  location                $DOC_ROOT/\n"
                    "  accessible              1\n"
                    "  allowBrowse             0\n"
                    "  extraHeaders            <<<END_webserverseclab_headers\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "X-Frame-Options: SAMEORIGIN\n"
                    "X-Content-Type-Options: nosniff\n"
                    "Referrer-Policy: strict-origin-when-cross-origin\n"
                    "Permissions-Policy: geolocation=(self \"\")\n"
                    "END_webserverseclab_headers\n"
                    "}\n"
                    "# webserverseclab headers context end\n"
                    "EOF\n"
                    " fi;"
                    " grep -qi 'extraHeaders[[:space:]]\\+<<<END_webserverseclab_headers' \"$F\""
                    " && grep -qi 'X-Frame-Options: SAMEORIGIN' \"$F\""
                    " && grep -qi 'X-Content-Type-Options: nosniff' \"$F\""
                    " && grep -qi 'Referrer-Policy: strict-origin-when-cross-origin' \"$F\""
                    " || exit 1;"
                    " done"
                ),
            },
        ],
    },

    "ols_secure_logging": {
        "name": "Secure OLS log paths",
        "type": "auto",
        "steps": [
            {
                "name": "Move error log outside webroot",
                "cmd": (
                    "mkdir -p /var/log/lsws;"
                    " find /usr/local/lsws -name '*.conf'"
                    " -exec sed -i 's|errorlog.*\\$VH_ROOT.*|errorlog /var/log/lsws/error.log|g' {} + 2>/dev/null; true"
                ),
            },
        ],
    },

    "ols_restrict_admin": {
        "name": "Restrict OLS admin to localhost",
        "type": "auto",
        "steps": [
            {
                "name": "Bind admin listener to 127.0.0.1",
                "cmd": _OLS_BIND_ADMIN_LOCAL,
            },
            {
                "name": "Restrict external access to OLS admin port",
                "cmd": (
                    _OLS_RESTRICT_ADMIN_NETWORK
                    + " if command -v iptables >/dev/null 2>&1; then"
                    " iptables -C INPUT -p tcp --dport 7080 ! -s 127.0.0.1 -j REJECT >/dev/null 2>&1"
                    " || exit 1;"
                    " fi"
                ),
            },
        ],
    },

    "ols_admin_password": {
        "name": "Set strong OLS admin password",
        "type": "manual",
        "steps": [],
        "note": (
            "Set a strong admin password interactively:\n\n"
            "```bash\n"
            "sudo /usr/local/lsws/admin/misc/admpass.sh\n"
            "```\n\n"
            "Choose a password with at least 16 characters, "
            "mixing upper/lower, digits, and symbols."
        ),
    },

    "ols_enable_https": {
        "name": "Enable HTTPS on OLS",
        "type": "auto",
        "steps": [
            {
                "name": "Generate self-signed cert for OLS if missing",
                "cmd": (
                    "[ -f /usr/local/lsws/conf/key.pem ] && [ -f /usr/local/lsws/conf/cert.pem ]"
                    " || openssl req -x509 -nodes -days 365 -newkey rsa:2048"
                    " -keyout /usr/local/lsws/conf/key.pem"
                    " -out /usr/local/lsws/conf/cert.pem"
                    " -subj '/CN=localhost' -sha256"
                ),
            },
            {
                "name": "Repair HTTPS listener on port 443",
                "cmd": _OLS_REBUILD_HTTPS_LISTENER,
            },
            {
                "name": "Allow external HTTPS traffic to port 443",
                "cmd": (
                    _OLS_ALLOW_HTTPS
                    + " if command -v iptables >/dev/null 2>&1; then"
                    " iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1"
                    " || exit 1;"
                    " fi"
                ),
            },
        ],
    },

    "ols_tls_hardening": {
        "name": "Harden OLS TLS/HTTPS posture",
        "type": "auto",
        "steps": [
            {
                "name": "Disable gzip/brotli compression in OLS vhost configs (BREACH mitigation)",
                "cmd": (
                    _OLS_VHOST_LOOP
                    + " [ -f \"$F\" ] || continue;"
                    " sed -i -E 's/^([[:space:]]*enableGzip)[[:space:]]+[0-9]+/\\1 0/g;"
                    " s/^([[:space:]]*enableDynGzip)[[:space:]]+[0-9]+/\\1 0/g;"
                    " s/^([[:space:]]*enableBr)[[:space:]]+[0-9]+/\\1 0/g' \"$F\" 2>/dev/null;"
                    " grep -q '^[[:space:]]*enableBr[[:space:]]\\+0\\b' \"$F\" 2>/dev/null"
                    " || sed -i '/context \\/ {/a\\  enableBr             0' \"$F\" 2>/dev/null;"
                    " grep -q '^[[:space:]]*enableDynGzip[[:space:]]\\+0\\b' \"$F\" 2>/dev/null"
                    " || sed -i '/context \\/ {/a\\  enableDynGzip       0' \"$F\" 2>/dev/null;"
                    " grep -q '^[[:space:]]*enableGzip[[:space:]]\\+0\\b' \"$F\" 2>/dev/null"
                    " || sed -i '/context \\/ {/a\\  enableGzip          0' \"$F\" 2>/dev/null;"
                    " done; true"
                ),
            },
            {
                "name": "Disable gzip/brotli compression in global OLS config",
                "cmd": (
                    "sed -i -E 's/^([[:space:]]*enableGzip)[[:space:]]+[0-9]+/\\1 0/g;"
                    " s/^([[:space:]]*enableDynGzip)[[:space:]]+[0-9]+/\\1 0/g;"
                    " s/^([[:space:]]*enableBr)[[:space:]]+[0-9]+/\\1 0/g'"
                    " /usr/local/lsws/conf/httpd_config.conf 2>/dev/null; true"
                ),
            },
            {
                "name": "Disable global dynamic gzip/brotli compression",
                "cmd": (
                    "sed -i -E 's/^([[:space:]]*enableGzipCompress)[[:space:]]+[0-9]+/\\1           0/g;"
                    " s/^([[:space:]]*enableDynGzipCompress)[[:space:]]+[0-9]+/\\1        0/g;"
                    " s/^([[:space:]]*enableBrCompress)[[:space:]]+[0-9]+/\\1              0/g'"
                    " /usr/local/lsws/conf/httpd_config.conf 2>/dev/null; true"
                ),
            },
            {
                "name": "Reduce OLS TLS cipher exposure in SSL blocks",
                "cmd": (
                    "if grep -qE '^listener (Secure|HTTPS)[[:space:]]*{' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null; then"
                    " sed -i '/^listener \\(Secure\\|HTTPS\\)[[:space:]]*{/,/^}/{/^[[:space:]]*ciphers[[:space:]]/d;}'"
                    " /usr/local/lsws/conf/httpd_config.conf 2>/dev/null;"
                    " sed -i '/^listener \\(Secure\\|HTTPS\\)[[:space:]]*{/a\\    ciphers                 EECDH+AESGCM:EECDH+CHACHA20'"
                    " /usr/local/lsws/conf/httpd_config.conf 2>/dev/null;"
                    " fi;"
                    "find /usr/local/lsws/conf /usr/local/lsws/conf/vhosts"
                    " -type f \\( -name 'httpd_config.conf' -o -name 'vhconf.conf*' -o -name 'vhost.conf*' \\)"
                    " -exec sed -i -E 's#^([[:space:]]*ciphers)[[:space:]]+.*#\\1 EECDH+AESGCM:EECDH+CHACHA20#g' {} +"
                    " 2>/dev/null; true"
                ),
            },
        ],
    },

    "ols_fix_etag": {
        "name": "Fix OLS ETag inode leak",
        "type": "auto",
        "steps": [
            {
                "name": "Set FileETag in .htaccess",
                "cmd": (
                    _OLS_DOCROOT + ";"
                    " grep -q 'FileETag' \"$DOCROOT/.htaccess\" 2>/dev/null"
                    " || echo 'FileETag MTime Size' >> \"$DOCROOT/.htaccess\""
                ),
            },
        ],
    },

    "ols_tls_certificate": {
        "name": "Deploy valid TLS certificate (OLS)",
        "type": "manual",
        "steps": [],
        "note": (
            "Obtain a CA-signed certificate and configure it in the "
            "OLS admin panel or in:\n"
            "`/usr/local/lsws/conf/httpd_config.conf`\n\n"
            "```bash\n"
            "openssl req -x509 -nodes -days 365 -newkey rsa:4096 \\\n"
            "  -keyout /usr/local/lsws/conf/key.pem \\\n"
            "  -out /usr/local/lsws/conf/cert.pem \\\n"
            "  -subj '/CN=localhost' -sha256\n"
            "```"
        ),
    },

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  CROSS-PLATFORM                                              ║
    # ╚═══════════════════════════════════════════════════════════════╝

    "review_metafiles": {
        "name": "Clean metafile sensitive paths",
        "type": "auto",
        "steps": [
            {
                "name": "Remove sensitive Disallow entries from robots.txt",
                "cmd": (
                    "find /var/www /usr/share/nginx/html /usr/local/lsws"
                    " -name 'robots.txt' -exec"
                    " sed -i '/[Dd]isallow.*admin\\|[Dd]isallow.*backup"
                    "\\|[Dd]isallow.*\\.git/Id' {} + 2>/dev/null; true"
                ),
            },
        ],
    },

    "remove_sensitive_files": {
        "name": "Quarantine sensitive webroot files and hide sensitive paths",
        "type": "auto",
        "steps": [
            {
                "name": "Prepare quarantine directory",
                "cmd": "mkdir -p /var/quarantine/webserverseclab; chmod 700 /var/quarantine/webserverseclab 2>/dev/null; true",
            },
            {
                "name": "Move sensitive files and .git dirs to quarantine (non-destructive)",
                "cmd": (
                    "ROOTS='/var/www /usr/share/nginx/html';"
                    " if [ -d /usr/local/lsws ]; then"
                    "   VH_ROOT=$(grep -h 'vhRoot' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null | awk '{print $NF}' | sed 's|/$||' | head -1);"
                    "   [ -n \"$VH_ROOT\" ] && [ \"${VH_ROOT#/}\" = \"$VH_ROOT\" ] && VH_ROOT=\"/usr/local/lsws/$VH_ROOT\";"
                    "   DOCROOT=$(grep -rh 'docRoot' /usr/local/lsws/conf/vhosts/ 2>/dev/null | head -1 | awk '{print $NF}' | sed 's|/$||');"
                    "   DOCROOT=$(echo \"$DOCROOT\" | sed \"s|\\$VH_ROOT|$VH_ROOT|g;s|\\$SERVER_ROOT|/usr/local/lsws|g\");"
                    "   [ -n \"$DOCROOT\" ] && [ \"${DOCROOT#/}\" = \"$DOCROOT\" ] && DOCROOT=\"/usr/local/lsws/$DOCROOT\";"
                    "   [ -z \"$DOCROOT\" ] && DOCROOT='/usr/local/lsws/Example/html';"
                    "   ROOTS=\"$ROOTS $DOCROOT\";"
                    " fi;"
                    " for ROOT in $ROOTS; do"
                    "   [ -d \"$ROOT\" ] || continue;"
                    "   find \"$ROOT\" \\( -path '*/.git' -o -name '.env' -o -name '*.bak' -o -name '*.old'"
                    "   -o -name '*.backup' -o -name '*.swp' -o -name '*~' -o -name '.htpasswd' -o -name '.htaccess'"
                    "   -o -name 'info.php' -o -name 'phpinfo.php' -o -name '*.sql' \\) -print0 2>/dev/null"
                    "   | while IFS= read -r -d '' P; do"
                    "       REL=${P#/}; DEST=\"/var/quarantine/webserverseclab/$REL\";"
                    "       mkdir -p \"$(dirname \"$DEST\")\";"
                    "       mv \"$P\" \"$DEST\" 2>/dev/null || true;"
                    "     done;"
                    " done; true"
                ),
            },
            {
                "name": "Return 404 for Apache dotfiles and status endpoints",
                "platform": "apache",
                "cmd": (
                    "for F in /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-available/security.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " sed -i '/RedirectMatch 404 \"^\\/\\\\\\./d; /RedirectMatch 404 \"^\\/(server-status|nginx_status)\\$/d' \"$F\";"
                    " echo 'RedirectMatch 404 \"^/\\.(?!well-known(?:/|$)).*\"' >> \"$F\";"
                    " echo 'RedirectMatch 404 \"^/(server-status|nginx_status)$\"' >> \"$F\";"
                    " done; true"
                ),
            },
            {
                "name": "Return 404 for Nginx dotfiles and status endpoints",
                "platform": "nginx",
                "cmd": (
                    "mkdir -p /etc/nginx/snippets;"
                    " cat > /etc/nginx/snippets/hide-sensitive-paths-404.conf << 'EOF'\n"
                    "if ($request_uri ~ \"^/\\.(?!well-known(?:/|$))\") { return 404; }\n"
                    "if ($request_uri ~ \"^/(server-status|nginx_status)$\") { return 404; }\n"
                    "EOF\n"
                    "for F in /etc/nginx/sites-enabled/*; do"
                    " [ -f \"$F\" ] || continue;"
                    " sed -i '/hide-sensitive-paths-404/d' \"$F\" 2>/dev/null;"
                    " sed -i '0,/server_name/{/server_name/a\\    include /etc/nginx/snippets/hide-sensitive-paths-404.conf;\n}' \"$F\" 2>/dev/null;"
                    "done; true"
                ),
            },
        ],
    },

    "restrict_status_page": {
        "name": "Disable public status page paths",
        "type": "auto",
        "steps": [
            {
                "name": "Disable Apache mod_status",
                "cmd": (
                    "a2dismod -f status 2>/dev/null;"
                    "for F in /etc/apache2/mods-enabled/status.conf /etc/apache2/mods-available/status.conf; do"
                    " [ -f \"$F\" ] || continue;"
                    " sed -i 's/Require all granted/Require all denied/' \"$F\";"
                    "done; true"
                ),
                "platform": "apache",
            },
            {
                "name": "Return 404 for Nginx status endpoints",
                "cmd": (
                    "mkdir -p /etc/nginx/snippets;"
                    " cat > /etc/nginx/snippets/status-404.conf << 'EOF'\n"
                    "if ($request_uri ~ \"^/(server-status|nginx_status)$\") { return 404; }\n"
                    "EOF\n"
                    "for F in /etc/nginx/sites-enabled/*; do"
                    " [ -f \"$F\" ] || continue;"
                    " sed -i '/status-404/d' \"$F\" 2>/dev/null;"
                    " sed -i '0,/server_name/{/server_name/a\\    include /etc/nginx/snippets/status-404.conf;\n}' \"$F\" 2>/dev/null;"
                    "done; true"
                ),
                "platform": "nginx",
            },
        ],
    },

    "fix_runtime_user": {
        "name": "Set least-privilege runtime user",
        "type": "auto",
        "steps": [
            {
                "name": "Ensure www-data user for Apache envvars",
                "cmd": (
                    "sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=www-data/' /etc/apache2/envvars;"
                    " sed -i 's/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=www-data/' /etc/apache2/envvars"
                ),
                "platform": "apache",
            },
            {
                "name": "Set nginx worker user to www-data",
                "cmd": "sed -i 's/^user .*/user www-data;/' /etc/nginx/nginx.conf",
                "platform": "nginx",
            },
            {
                "name": "Set OLS worker user to nobody",
                "cmd": (
                    "sed -i 's/^\\(\\s*\\)user .*$/\\1user                  nobody/' "
                    "/usr/local/lsws/conf/httpd_config.conf 2>/dev/null; true"
                ),
                "platform": "ols",
            },
        ],
    },

    "fix_tls_key_perms": {
        "name": "Restrict TLS private key permissions",
        "type": "auto",
        "steps": [
            {
                "name": "chmod 600 private key files",
                "cmd": (
                    "find /etc/ssl/private /etc/letsencrypt/live /usr/local/lsws/conf"
                    " -name '*.key' -o -name '*.pem' -o -name 'privkey*'"
                    " 2>/dev/null | xargs -r chmod 600 2>/dev/null; true"
                ),
            },
            {
                "name": "Set ownership to root",
                "cmd": (
                    "find /etc/ssl/private /etc/letsencrypt/live /usr/local/lsws/conf"
                    " -name '*.key' -o -name '*.pem' -o -name 'privkey*'"
                    " 2>/dev/null | xargs -r chown root:root 2>/dev/null; true"
                ),
            },
        ],
    },

    "fix_webroot_perms": {
        "name": "Restrict webroot permissions",
        "type": "auto",
        "steps": [
            {
                "name": "Fix Apache webroot ownership and mode",
                "cmd": "chown -R root:www-data /var/www/html 2>/dev/null; chmod -R 755 /var/www/html 2>/dev/null; true",
                "platform": "apache",
            },
            {
                "name": "Fix Nginx webroot ownership and mode",
                "cmd": (
                    "DOCROOT=/var/www/html; [ -d /usr/share/nginx/html ] && DOCROOT=/usr/share/nginx/html;"
                    " chown -R root:www-data $DOCROOT; chmod -R 755 $DOCROOT"
                ),
                "platform": "nginx",
            },
            {
                "name": "Fix OLS webroot ownership and mode",
                "cmd": (
                    _OLS_DOCROOT + ";"
                    " [ -n \"$DOCROOT\" ] && [ -d \"$DOCROOT\" ]"
                    " && chown -R root:nobody \"$DOCROOT\" && chmod -R 755 \"$DOCROOT\"; true"
                ),
                "platform": "ols",
            },
        ],
    },

    "apply_security_updates": {
        "name": "Apply pending security updates",
        "type": "auto",
        "steps": [
            {"name": "Update package lists", "cmd": "apt-get update -qq"},
            {
                "name": "Install pending package upgrades",
                "cmd": (
                    "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
                    "-o Dpkg::Options::='--force-confold' 2>/dev/null; true"
                ),
            },
            {"name": "Remove obsolete packages", "cmd": "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null; true"},
        ],
    },

    "review_modules": {
        "name": "Review and minimize server modules",
        "type": "manual",
        "steps": [],
        "note": (
            "Review the list of loaded modules and disable any that are "
            "not required by your application.\n\n"
            "**Apache:**\n"
            "```bash\n"
            "apache2ctl -M          # list loaded modules\n"
            "sudo a2dismod <mod>    # disable a module\n"
            "```\n\n"
            "**Nginx:** Remove unnecessary `load_module` directives from "
            "`/etc/nginx/modules-enabled/`.\n\n"
            "**OLS:** Disable modules via the WebAdmin panel under "
            "Server Configuration > Modules."
        ),
    },

    "fix_tls_certificate": {
        "name": "Deploy valid CA-signed TLS certificate",
        "type": "manual",
        "steps": [],
        "note": (
            "A self-signed certificate was detected. Replace it with a "
            "CA-signed certificate.\n\n"
            "**Let's Encrypt (free, automated):**\n"
            "```bash\n"
            "sudo apt install certbot\n"
            "sudo certbot certonly --standalone -d yourdomain.com\n"
            "```\n\n"
            "Then update your server config to reference the new cert "
            "and key files."
        ),
    },

    "fix_dns_caa": {
        "name": "Add DNS CAA record",
        "type": "manual",
        "steps": [],
        "note": (
            "Add a CAA record to your DNS zone to restrict which CAs "
            "can issue certificates for your domain.\n\n"
            "Example DNS records:\n"
            "```\n"
            "example.com. IN CAA 0 issue \"letsencrypt.org\"\n"
            "example.com. IN CAA 0 issuewild \";\"\n"
            "```\n\n"
            "This must be done at your DNS provider."
        ),
    },
}


# ── Rule-ID -> tag mapping for agent findings ────────────────────────────
#
# Agent findings carry generic tags like "apache_agent_check" instead
# of actionable remediation tags.  This map resolves them.

RULE_TAG_MAP: Dict[str, Optional[str]] = {
    # Agent host checks
    "AG-RUNTIME-USER":       "fix_runtime_user",
    "AG-TLS-KEY-PERMS":      "fix_tls_key_perms",
    "AG-WEBROOT-PERMS":      "fix_webroot_perms",
    "AG-MODULES-01":         "review_modules",
    "AG-PATCH-STATE":        "apply_security_updates",
    "AG-PLATFORM":           None,
    # Platform-specific agent findings
    "AP-G6-LOGPATH":         "apache_fix_logpath",
    "AP-A5-G8":              "apache_restrict_overrides",
    "AP-A7-WAF":             "apache_enable_modsecurity",
    "NG-G6-COOKIELOG":       "nginx_fix_cookie_logging",
    "NG-N2-G2":              "nginx_no_autoindex",
    "NG-N5-G3":              "nginx_restrict_methods",
    "OLS-O1-ADMIN":          "ols_restrict_admin",
    "OLS-O2-ADMIN-PASSWORD": "ols_admin_password",
    "OLS-O4-G2":             "ols_no_autoindex",
    "OLS-HTTP-ONLY":         "ols_enable_https",
    # Scanner normalized IDs with no tags
    "G7-ETAG-LEAK":          "fix_etag_leak",
    "G4-CERT":               "_resolve_tls_certificate",
    "G4-CAA":                "fix_dns_caa",
    "G4":                    "_resolve_tls_hardening",
    "G4-PROTO":              "_resolve_tls_hardening",
    "G4-CIPHER":             "_resolve_tls_hardening",
    "G4-HSTS":               "_resolve_headers",
    "G4-VULN":               "_resolve_tls_hardening",
    "INFO-01":               None,
    # Generic agent rule IDs that need platform-specific resolution
    "G1":                    "_resolve_version",
    "G2":                    "_resolve_dirlist",
    "G3":                    "_resolve_methods",
    "G5":                    "_resolve_headers",
    "G8":                    "review_metafiles",
    "G9":                    "remove_sensitive_files",
    "M1":                    "restrict_status_page",
}

# ETag tag resolution per platform
_ETAG_TAG = {
    "apache": "apache_fix_etag",
    "nginx":  "nginx_fix_etag",
    "ols":    "ols_fix_etag",
}

# TLS certificate tag resolution per platform
_CERT_TAG = {
    "apache": "apache_tls_certificate",
    "nginx":  "nginx_tls_certificate",
    "ols":    "ols_tls_certificate",
}

# TLS hardening per platform
_TLS_HARDENING_TAG = {
    "apache": "apache_tls_hardening",
    "nginx":  "nginx_tls_hardening",
    "ols":    "ols_tls_hardening",
}

# Version hiding per platform
_HIDE_VERSION_TAG = {
    "apache": "apache_hide_version",
    "nginx":  "nginx_hide_version",
    "ols":    None,
}

# Directory listing per platform
_DIRLIST_TAG = {
    "apache": "apache_no_autoindex",
    "nginx":  "nginx_no_autoindex",
    "ols":    "ols_no_autoindex",
}

# HTTP methods per platform
_METHODS_TAG = {
    "apache": "apache_disable_trace",
    "nginx":  "nginx_restrict_methods",
    "ols":    None,
}

# Security headers per platform
_SEC_HEADERS_TAG = {
    "apache": "apache_security_headers",
    "nginx":  "nginx_security_headers",
    "ols":    "ols_security_headers",
}

_AGENT_CHECK_SUFFIX = "_agent_check"
_FOLLOW_ON_TAGS: Dict[str, List[str]] = {
    # Enabling HTTPS on OLS often surfaces the next TLS layer only on the
    # verification scan, so we schedule the first-pass TLS baseline together.
    "OLS-HTTP-ONLY": ["ols_enable_https", "ols_tls_hardening"],
}


# ── Helpers ──────────────────────────────────────────────────────────────

def get_registry_entry(tag: str) -> Optional[Dict[str, Any]]:
    return REGISTRY.get(tag)


def get_registry_name(tag: str) -> str:
    entry = REGISTRY.get(tag)
    return entry["name"] if entry else tag


def _is_meta_result(tag: str) -> bool:
    return tag in {"_verify", "_reload"}


def _is_generic_agent_tag(tags: List[str]) -> bool:
    """True when every tag in the list is a generic *_agent_check tag."""
    return bool(tags) and all(t.endswith(_AGENT_CHECK_SUFFIX) for t in tags)


def _append_follow_on_tags(rule_id: str, tags: List[str]) -> List[str]:
    """Add deterministic follow-on tags while preserving order."""
    out: List[str] = []
    for tag in [*(tags or []), *(_FOLLOW_ON_TAGS.get(rule_id, []))]:
        if tag and tag not in out:
            out.append(tag)
    return out


# Platform-specific tag resolution lookup
_PLATFORM_TAG_MAPS: Dict[str, Dict[str, Optional[str]]] = {
    "fix_etag_leak":      _ETAG_TAG,
    "_resolve_tls_certificate": _CERT_TAG,
    "_resolve_version":   _HIDE_VERSION_TAG,
    "_resolve_dirlist":   _DIRLIST_TAG,
    "_resolve_methods":   _METHODS_TAG,
    "_resolve_headers":   _SEC_HEADERS_TAG,
    "_resolve_tls_hardening": _TLS_HARDENING_TAG,
}


def _resolve_platform_tag(mapped: Optional[str], platform: str) -> Optional[str]:
    """Resolve a sentinel tag to a platform-specific registry tag."""
    if mapped is None:
        return None
    plat_map = _PLATFORM_TAG_MAPS.get(mapped)
    if plat_map is not None:
        return plat_map.get(platform)
    return mapped


def _resolve_tags(finding: dict) -> List[str]:
    """Resolve a finding's tags to actionable remediation tags."""
    raw_tags: List[str] = (finding.get("ansible") or {}).get("tags") or []
    rule_id: str = finding.get("rule_id", "")
    platform: str = (finding.get("target") or {}).get("platform", "unknown")

    # If all tags are generic agent tags, look up by rule_id
    if _is_generic_agent_tag(raw_tags) or not raw_tags:
        mapped = RULE_TAG_MAP.get(rule_id)
        mapped = _resolve_platform_tag(mapped, platform)
        if mapped is not None:
            return _append_follow_on_tags(rule_id, [mapped])
        return _append_follow_on_tags(rule_id, [])

    # Filter out generic agent check tags and keep actionable ones
    actionable = [t for t in raw_tags if not t.endswith(_AGENT_CHECK_SUFFIX)]
    if not actionable:
        mapped = RULE_TAG_MAP.get(rule_id)
        mapped = _resolve_platform_tag(mapped, platform)
        if mapped is not None:
            return _append_follow_on_tags(rule_id, [mapped])
        return _append_follow_on_tags(rule_id, [])

    # Resolve platform-specific certificate tags
    resolved: List[str] = []
    for t in actionable:
        if t in REGISTRY:
            resolved.append(t)
        elif t in ("apache_tls_certificate", "nginx_tls_certificate", "ols_tls_certificate"):
            resolved.append(t)
        else:
            # Unknown tag - try RULE_TAG_MAP as fallback
            mapped = _resolve_platform_tag(RULE_TAG_MAP.get(rule_id), platform)
            if mapped and mapped not in resolved:
                resolved.append(mapped)

    return _append_follow_on_tags(rule_id, resolved if resolved else actionable)


# ── Classification ───────────────────────────────────────────────────────

def classify_findings(
    findings: List[dict],
) -> Dict[str, Dict[str, Any]]:
    """
    Classify findings into auto / manual / pass / info buckets per target.

    Returns ``{target_name: {"platform": str, "auto": [...], "manual": [...],
    "pass": [...], "info": [...]}}``.
    """
    result: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        target = f.get("target") or {}
        tname = target.get("name", "unknown")
        platform = target.get("platform", "unknown")
        check_status = f.get("check_status")
        rule_id = f.get("rule_id", "")

        if tname not in result:
            result[tname] = {
                "platform": platform,
                "auto": [], "manual": [], "pass": [], "info": [],
            }

        # Already-passing agent checks
        if check_status == "pass":
            result[tname]["pass"].append({"finding": f, "tag": None})
            continue

        # Informational findings with no remediation
        if rule_id in ("AG-PLATFORM", "INFO-01"):
            result[tname]["info"].append({"finding": f, "tag": None})
            continue

        tags = _resolve_tags(f)

        if not tags:
            # Still no tag after resolution - classify as info
            result[tname]["info"].append({
                "finding": f, "tag": None,
                "reason": "No remediation mapping",
            })
            continue

        for tag in tags:
            entry = REGISTRY.get(tag)
            if entry is None:
                result[tname]["info"].append({
                    "finding": f, "tag": tag,
                    "reason": f"Tag '{tag}' not in registry",
                })
            elif entry["type"] == "auto":
                result[tname]["auto"].append({"finding": f, "tag": tag, "entry": entry})
            elif entry["type"] == "manual":
                result[tname]["manual"].append({
                    "finding": f, "tag": tag, "entry": entry,
                    "note": entry.get("note", ""),
                })

    return result


def deduplicate_tags(items: List[dict]) -> List[str]:
    """Return unique tags from classification items, preserving order."""
    seen: set = set()
    out: List[str] = []
    for item in items:
        tag = item.get("tag")
        if tag and tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


# ── Playbook builder ────────────────────────────────────────────────────

def build_playbook(target_name: str, platform: str, tags: List[str]) -> list:
    """Build an Ansible playbook (list of plays) for *tags* on *target_name*."""
    tasks: List[dict] = []

    for tag in tags:
        entry = REGISTRY.get(tag)
        if not entry or entry["type"] != "auto":
            continue
        for step in entry.get("steps", []):
            step_platform = step.get("platform")
            if step_platform and step_platform != platform:
                continue
            tasks.append({
                "name": f"[{tag}] {step['name']}",
                "ansible.builtin.shell": step["cmd"],
                "become": True,
                "tags": [tag],
            })

    svc = PLATFORM_SVC.get(platform, {})
    if svc.get("verify"):
        tasks.append({"name": f"Verify {platform} configuration", "ansible.builtin.shell": svc["verify"], "become": True, "tags": ["verify"]})
    if svc.get("reload"):
        tasks.append({"name": f"Reload {platform} service", "ansible.builtin.shell": svc["reload"], "become": True, "tags": ["reload"]})

    return [{"hosts": target_name, "become": True, "tasks": tasks}]


def save_playbook(playbook: Any, output_dir: Path, target_name: str) -> Path:
    """Write playbook YAML to *output_dir* and return the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"playbook_{target_name}.yml"
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(playbook, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return path


# ── SSH execution engine ─────────────────────────────────────────────────

def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _run_cmd(client: Any, cmd: str) -> dict:
    full = f"sudo bash -c {_shell_quote(cmd)}"
    _stdin, stdout, stderr = client.exec_command(full, timeout=120)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return {"exit_code": exit_code, "stdout": out, "stderr": err, "status": "ok" if exit_code == 0 else "failed"}


def execute_remediation(
    target: dict,
    tags: List[str],
    ssh_mgr: SSHConnectionManager,
    progress_cb: Optional[Callable[[str, str, str], None]] = None,
) -> List[dict]:
    """Execute remediation tasks for *tags* on *target* via SSH."""
    platform = target.get("platform", "unknown")
    results: List[dict] = []

    client = ssh_mgr.connect(target)
    try:
        for tag in tags:
            entry = REGISTRY.get(tag)
            if not entry or entry["type"] != "auto":
                continue
            step_results: List[dict] = []
            task_ok = True
            for step in entry.get("steps", []):
                step_platform = step.get("platform")
                if step_platform and step_platform != platform:
                    continue
                if progress_cb:
                    progress_cb(tag, step["name"], "running")
                res = _run_cmd(client, step["cmd"])
                res["step"] = step["name"]
                step_results.append(res)
                if res["status"] == "failed":
                    task_ok = False
                if progress_cb:
                    progress_cb(tag, step["name"], res["status"])
            results.append({"tag": tag, "name": entry["name"], "status": "ok" if task_ok else "failed", "steps": step_results})

        svc = PLATFORM_SVC.get(platform, {})
        verify_ok = True
        if svc.get("verify"):
            vr = _run_cmd(client, svc["verify"])
            results.append({"tag": "_verify", "name": f"Verify {platform} config", "status": vr["status"], "steps": [vr]})
            verify_ok = vr["status"] == "ok"
        if svc.get("reload"):
            if verify_ok:
                rr = _run_cmd(client, svc["reload"])
                results.append({"tag": "_reload", "name": f"Reload {platform}", "status": rr["status"], "steps": [rr]})
            else:
                results.append({
                    "tag": "_reload", "name": f"Reload {platform}", "status": "skipped",
                    "steps": [{"stdout": "Skipped: config verification failed", "stderr": "", "exit_code": -1, "status": "skipped"}],
                })
        if verify_ok and platform == "ols":
            pr = _run_cmd(client, _OLS_LIVE_POSTCHECK)
            pr["step"] = "Validate live OLS listeners and response headers"
            results.append({"tag": "_postcheck", "name": "Validate live OLS listener and header state", "status": pr["status"], "steps": [pr]})
    finally:
        client.close()

    return results


# ── Report builder ───────────────────────────────────────────────────────

def build_hardening_report(
    run_id: str,
    results_by_target: Dict[str, List[dict]],
    manual_tags: Optional[Dict[str, List[str]]] = None,
) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    targets_summary: Dict[str, Any] = {}
    total_ok = total_failed = total_manual = 0

    for tname, results in results_by_target.items():
        ok = sum(1 for r in results if r["status"] == "ok" and not _is_meta_result(r.get("tag", "")))
        failed = sum(1 for r in results if r["status"] == "failed" and not _is_meta_result(r.get("tag", "")))
        targets_summary[tname] = {"ok": ok, "failed": failed, "results": results}
        total_ok += ok
        total_failed += failed

    if manual_tags:
        for tags in manual_tags.values():
            total_manual += len(tags)

    return {
        "report_type": "hardening",
        "run_id": run_id,
        "generated_at": generated_at,
        "summary": {"total_applied": total_ok, "total_failed": total_failed, "total_manual": total_manual},
        "targets": targets_summary,
    }


# ── Export ────────────────────────────────────────────────────────────────

def export_hardening_report(report: dict, output_dir: Path) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "hardening_report.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    html_path = output_dir / "hardening_report.html"
    _write_hardening_html(report, str(html_path))
    return {"json": str(json_path), "html": str(html_path)}


def _write_hardening_html(report: dict, path: str) -> None:
    run_id = report.get("run_id", "")
    generated = report.get("generated_at", "")
    summary = report.get("summary", {})
    rows = ""
    for tname, tdata in report.get("targets", {}).items():
        for r in tdata.get("results", []):
            if _is_meta_result(r.get("tag", "")):
                continue
            cls = "ok" if r["status"] == "ok" else "fail"
            rows += f'<tr class="{cls}"><td>{tname}</td><td>{r["tag"]}</td><td>{r["name"]}</td><td>{r["status"].upper()}</td></tr>\n'
    html = f"""<!doctype html>
<html><head>
  <meta charset="utf-8"/>
  <title>Hardening Report - {run_id}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #1f2937; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #4b5563; margin-bottom: 18px; }}
    .stats {{ display: flex; gap: 16px; margin-bottom: 20px; }}
    .stat {{ border: 1px solid #d1d5db; border-radius: 6px; padding: 12px 20px; text-align: center; }}
    .stat strong {{ display: block; font-size: 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; }}
    th {{ background: #f3f4f6; }}
    tr.ok td:last-child {{ color: #16a34a; font-weight: 600; }}
    tr.fail td:last-child {{ color: #dc2626; font-weight: 600; }}
    @media print {{ body {{ margin: 10mm; }} }}
  </style>
</head><body>
  <h1>Hardening Report</h1>
  <div class="meta">Run: {run_id} | Generated: {generated}</div>
  <div class="stats">
    <div class="stat"><strong>{summary.get('total_applied', 0)}</strong>Applied</div>
    <div class="stat"><strong>{summary.get('total_failed', 0)}</strong>Failed</div>
    <div class="stat"><strong>{summary.get('total_manual', 0)}</strong>Manual</div>
  </div>
  <h2>Task Results</h2>
  <table><thead><tr><th>Target</th><th>Tag</th><th>Task</th><th>Status</th></tr></thead>
  <tbody>\n{rows}</tbody></table>
  <p style="font-size:11px;color:#6b7280;margin-top:18px;">Generated by WebServerSecLab Hardening Engine.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

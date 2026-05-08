import os
import shutil
from core.storage import StorageManager
from scanners.base import BaseScanner

import logging
logger = logging.getLogger(__name__)

class TestsslScanner(BaseScanner):
    name = "testssl"

    def _get_https_port(self) -> int:
        """
        Resolve the HTTPS port for TLS scanning.

        OLS lab targets default to 7080 because that is the HTTPS-capable
        listener exposed in the current lab image before hardening enables
        a public listener on 443.
        """
        platform = str(self.target.get("platform", "")).strip().lower()
        default_port = 7080 if platform == "ols" else 443
        try:
            return int(self.target.get("https_port", default_port))
        except (TypeError, ValueError):
            return default_port

    def _get_scan_target(self) -> str:
        port = self._get_https_port()
        return f"{self.ip}:{port}"

    def _candidate_ports(self) -> list[int]:
        configured = self._get_https_port()
        platform = str(self.target.get("platform", "")).strip().lower()
        if platform == "ols":
            candidates: list[int] = [443, configured, 7080]
        else:
            candidates = [configured]
            if configured != 443:
                candidates.append(443)

        ordered: list[int] = []
        for port in candidates:
            if port not in ordered:
                ordered.append(port)
        return ordered

    @staticmethod
    def _remove_if_exists(path: str) -> None:
        if not path:
            return
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            # Best-effort cleanup; testssl will report if output cannot be written.
            pass

    @staticmethod
    def _detect_scan_problem(json_path: str) -> str:
        """Return an error string if testssl reported scanProblem/FATAL in JSON output."""
        if not os.path.exists(json_path):
            return ""
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return ""

        has_scan_problem = "scanProblem" in content
        has_fatal = '"severity"' in content and "FATAL" in content
        if has_scan_problem and has_fatal:
            # Keep message stable and concise for UI logs.
            return "testssl reported scanProblem/FATAL in output"
        return ""
    
    def scan(self) -> dict:
        """
        Runs testssl.sh against the target's configured HTTPS port.
        Outputs JSON structure for TLS posture.
        """
        json_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "json")
        html_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "html")
        testssl_cmd = "testssl.sh" if shutil.which("testssl.sh") else "/opt/testssl/testssl.sh"
        target_json = json_filepath
        target_html = html_filepath

        attempts = []
        last_stdout = ""
        last_stderr = ""
        last_error = ""

        for port in self._candidate_ports():
            scan_target = f"{self.ip}:{port}"
            attempts.append(scan_target)

            self._remove_if_exists(json_filepath)
            self._remove_if_exists(html_filepath)

            cmd = [
                testssl_cmd,
                "--quiet",
                "--color", "0",
                "--jsonfile", target_json,
                scan_target,
            ]

            returncode, stdout, stderr = self._run_subprocess(cmd)
            scan_problem = self._detect_scan_problem(json_filepath)
            last_stdout = stdout
            last_stderr = stderr
            last_error = scan_problem or stderr or ""

            if not scan_problem and (returncode == 0 or os.path.exists(json_filepath)):
                if len(attempts) > 1:
                    last_stderr = (last_stderr + "\n" if last_stderr else "") + (
                        f"testssl succeeded after retrying ports: {', '.join(attempts)}"
                    )
                StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", last_stdout)
                StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stderr", last_stderr)
                return {"status": "success", "raw_json": json_filepath, "raw_html": html_filepath}

        retry_note = f"Ports tried: {', '.join(attempts)}"
        if retry_note not in last_error:
            last_error = f"{last_error}\n{retry_note}".strip()

        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", last_stdout)
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stderr", last_error or last_stderr)

        if not os.path.exists(json_filepath):
            return {"status": "error", "error": last_error or last_stderr}

        return {
            "status": "error",
            "raw_json": json_filepath,
            "raw_html": html_filepath,
            "stderr": last_error or last_stderr or "testssl scan failed",
        }

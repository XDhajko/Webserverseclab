import os
import json
import re
import uuid
from urllib import error as urllib_error
from urllib import request as urllib_request
from core.storage import StorageManager
from scanners.base import BaseScanner

class GobusterScanner(BaseScanner):
    name = "gobuster"

    @staticmethod
    def _clean_console_text(text: str) -> str:
        if not text:
            return ""
        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)

    @staticmethod
    def _looks_like_runtime_error(stderr: str) -> bool:
        text = (stderr or "").lower()
        return any(
            token in text
            for token in [
                "error on running gobuster",
                "unable to connect",
                "client.timeout exceeded",
                "timeout exceeded",
                "context deadline exceeded",
                "connection refused",
            ]
        )

    @staticmethod
    def _probe_nonexistent(url: str) -> tuple[int | None, int | None]:
        probe_url = f"{url.rstrip('/')}/{uuid.uuid4()}"
        req = urllib_request.Request(probe_url, headers={"User-Agent": "WebServerSecLab/1.0"})
        try:
            with urllib_request.urlopen(req, timeout=10) as response:
                body = response.read()
                return response.getcode(), len(body)
        except urllib_error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""
            return exc.code, len(body)
        except Exception:
            return None, None
    
    def scan(self) -> dict:
        """
        Runs Gobuster to discover sensitive files based on the specified wordlist.
        Specifically targeting G9 scenarios (Sensitive Files) from the analysis.
        """
        json_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "json")
        wordlist = "config/wordlist.txt"

        # Prevent CRLF entries from breaking URL parsing inside gobuster.
        if os.path.exists(wordlist):
            with open(wordlist, "rb") as f:
                data = f.read()
            if b"\r\n" in data:
                with open(wordlist, "wb") as f:
                    f.write(data.replace(b"\r\n", b"\n"))
        
        # We target port 80 by default.
        url = f"http://{self.ip}/"
        
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-q", # Quiet
            "-t", "10", # Threads
        ]
        
        returncode, stdout, stderr = self._run_subprocess(cmd)
        stdout = self._clean_console_text(stdout)
        stderr = self._clean_console_text(stderr)
        wildcard_note = ""

        wildcard_hint = "specify the '--wildcard' switch"
        if returncode != 0 and wildcard_hint in (stderr or "").lower():
            probe_status, probe_length = self._probe_nonexistent(url)
            retry_cmd = [*cmd, "--wildcard"]
            if probe_length is not None:
                retry_cmd.extend(["--exclude-length", str(probe_length)])
            retry_code, retry_stdout, retry_stderr = self._run_subprocess(retry_cmd)
            retry_stdout = self._clean_console_text(retry_stdout)
            retry_stderr = self._clean_console_text(retry_stderr)
            wildcard_note = (
                f"Gobuster wildcard fallback used for baseline status {probe_status or 'unknown'} "
                f"and body length {probe_length if probe_length is not None else 'unknown'}."
            )

            if retry_code == 0:
                returncode, stdout = retry_code, retry_stdout
                stderr = "\n".join(part for part in [retry_stderr.strip(), wildcard_note] if part)
            else:
                returncode, stdout = 0, ""
                stderr = "\n".join(
                    part for part in [
                        stderr.strip(),
                        retry_stderr.strip(),
                        wildcard_note,
                        "Treating wildcard-only directory responses as no Gobuster findings for this target.",
                    ] if part
                )
        
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", stdout)
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stderr", stderr)

        if returncode != 0:
            with open(json_filepath, "w", encoding="utf-8") as f:
                json.dump([], f)
            return {
                "status": "error",
                "raw_json": json_filepath,
                "stderr": stderr.strip() or "Gobuster failed with non-zero exit code",
            }
        
        # Parse gobuster stdout and keep path + status for stronger normalization.
        findings = []
        for line in stdout.splitlines():
            match = re.match(r"^(\/\S+)\s+\(Status:\s*(\d{3})\)", line.strip())
            if not match:
                continue
            path, status = match.group(1), int(match.group(2))
            if status in {200, 204, 301, 302, 307, 401, 403}:
                findings.append({"path": path, "status": status})
                    
        with open(json_filepath, "w", encoding="utf-8") as f:
            json.dump(findings, f)

        if not findings and self._looks_like_runtime_error(stderr):
            return {
                "status": "error",
                "raw_json": json_filepath,
                "stderr": stderr.strip() or "Gobuster failed during execution",
            }
            
        return {"status": "success", "raw_json": json_filepath, "count": len(findings)}

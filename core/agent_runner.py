import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

from core.ssh_manager import SSHConnectionManager
from core.storage import StorageManager, RUNS_DIR


class AgentRunner:
    def __init__(self, run_id: str, mode: str = "quick"):
        self.run_id = run_id
        self.mode = mode
        self.payload_path = Path(__file__).resolve().parent.parent / "agent" / "agent_payloads" / "internal_agent.py"

    def _target_root(self, target_name: str) -> Path:
        return Path(RUNS_DIR) / self.run_id / target_name

    def run_for_target(self, target: Dict[str, Any], runtime_password: Optional[str] = None) -> Dict[str, Any]:
        target_name = target.get("name", "target")
        StorageManager.init_target_dir(self.run_id, target_name)
        raw_dir = self._target_root(target_name) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        stdout_path = raw_dir / "agent_stdout.txt"
        stderr_path = raw_dir / "agent_stderr.txt"
        agent_json_path = self._target_root(target_name) / "agent.json"

        if not self.payload_path.exists():
            return {"status": "error", "error": f"Agent payload missing: {self.payload_path}"}

        manager = SSHConnectionManager()
        client = None
        sftp = None
        remote_path = f"/tmp/webserverseclab_agent_{self.run_id}.py"

        try:
            client = manager.connect(target, runtime_password=runtime_password)
            sftp = client.open_sftp()
            sftp.put(str(self.payload_path), remote_path)
            client.exec_command(f"chmod 700 {remote_path}")

            cmd = (
                "if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then "
                f"sudo -n python3 {remote_path} --mode {self.mode}; "
                "else "
                f"python3 {remote_path} --mode {self.mode}; "
                "fi"
            )
            stdin, stdout, stderr = client.exec_command(cmd)
            del stdin

            stdout_data = stdout.read().decode("utf-8", errors="ignore")
            stderr_data = stderr.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()

            stdout_path.write_text(stdout_data, encoding="utf-8")
            stderr_path.write_text(stderr_data, encoding="utf-8")

            if exit_code != 0:
                return {
                    "status": "error",
                    "error": f"Agent exited with code {exit_code}",
                    "stderr": stderr_data,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }

            parsed = json.loads(stdout_data)
            with open(agent_json_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2)

            return {
                "status": "success",
                "agent_json": str(agent_json_path),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            }

        except json.JSONDecodeError as exc:
            return {
                "status": "error",
                "error": f"Agent output is not valid JSON: {exc}",
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
        finally:
            if client:
                try:
                    client.exec_command(f"rm -f {remote_path}")
                except Exception:
                    pass
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass
            if client:
                try:
                    client.close()
                except Exception:
                    pass

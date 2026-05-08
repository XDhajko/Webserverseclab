import logging
import os
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)


class BaseScanner:
    """Base class for all external scanners."""

    name = "base"

    _DOCKER_LOCK = threading.Lock()
    _DOCKER_CONTAINERS: Dict[tuple[str, str], str] = {}
    _DOCKER_IMAGES = {
        "nmap": "instrumentisto/nmap",
        "nikto": "frapsoft/nikto",
        "testssl.sh": "drwetter/testssl.sh",
        "/opt/testssl/testssl.sh": "drwetter/testssl.sh",
        "gobuster": "trickest/gobuster",
    }

    def __init__(self, target: Dict[str, Any], run_id: str):
        self.target = target
        self.run_id = run_id
        self.ip = target.get("ip")
        self.target_name = target.get("name")

    @staticmethod
    def _docker_mode() -> str:
        return str(os.environ.get("WEBSECLAB_SCANNER_MODE", "docker")).strip().lower()

    @classmethod
    def _docker_available(cls) -> bool:
        return bool(shutil.which("docker"))

    @classmethod
    def _docker_preferred(cls) -> bool:
        return cls._docker_mode() != "local"

    @classmethod
    def _scanner_image(cls, tool: str) -> str | None:
        return cls._DOCKER_IMAGES.get(tool)

    @classmethod
    def _container_name(cls, run_id: str, tool: str) -> str:
        tool_key = re.sub(r"[^a-z0-9]+", "-", tool.lower()).strip("-")
        run_key = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
        return f"webserverseclab-{run_key}-{tool_key}"

    @staticmethod
    def _app_root() -> str:
        return os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    @staticmethod
    def _runs_root() -> str:
        from core.storage import RUNS_DIR

        return os.path.abspath(RUNS_DIR)

    @classmethod
    def _ensure_docker_container(cls, run_id: str, tool: str) -> str:
        docker_bin = shutil.which("docker")
        image = cls._scanner_image(tool)
        if not docker_bin or not image:
            raise RuntimeError(f"Docker execution is not available for tool '{tool}'")

        name = cls._container_name(run_id, tool)
        with cls._DOCKER_LOCK:
            cached = cls._DOCKER_CONTAINERS.get((run_id, tool))
            if cached:
                return cached

            inspect = subprocess.run(
                [docker_bin, "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True,
                text=True,
            )
            if inspect.returncode == 0 and inspect.stdout.strip().lower() == "true":
                cls._DOCKER_CONTAINERS[(run_id, tool)] = name
                return name
            if inspect.returncode == 0:
                subprocess.run([docker_bin, "rm", "-f", name], capture_output=True, text=True)

            app_root = cls._app_root()
            runs_root = cls._runs_root()
            start = subprocess.run(
                [
                    docker_bin,
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--entrypoint",
                    "sh",
                    "-v",
                    f"{runs_root}:/runs",
                    "-v",
                    f"{app_root}:/app",
                    "-w",
                    "/app",
                    image,
                    "-c",
                    "trap exit TERM; while :; do sleep 3600; done",
                ],
                capture_output=True,
                text=True,
            )
            if start.returncode != 0:
                raise RuntimeError(start.stderr.strip() or f"Failed to start docker container for {tool}")

            cls._DOCKER_CONTAINERS[(run_id, tool)] = name
            return name

    @classmethod
    def cleanup_run_containers(cls, run_id: str) -> None:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return

        with cls._DOCKER_LOCK:
            items = [(key, value) for key, value in cls._DOCKER_CONTAINERS.items() if key[0] == run_id]
            for key, name in items:
                subprocess.run([docker_bin, "rm", "-f", name], capture_output=True, text=True)
                cls._DOCKER_CONTAINERS.pop(key, None)

    @classmethod
    def _translate_to_container_path(cls, run_id: str, target_name: str, arg: str) -> str:
        if not isinstance(arg, str):
            return arg

        if arg.startswith("/out/"):
            filename = os.path.basename(arg)
            return f"/runs/{run_id}/{target_name}/raw/{filename}"

        if not os.path.isabs(arg):
            return arg.replace("\\", "/")

        app_root = cls._app_root()
        runs_root = cls._runs_root()
        arg_abs = os.path.abspath(arg)

        if arg_abs.startswith(runs_root):
            rel = os.path.relpath(arg_abs, runs_root).replace("\\", "/")
            return f"/runs/{rel}"
        if arg_abs.startswith(app_root):
            rel = os.path.relpath(arg_abs, app_root).replace("\\", "/")
            return f"/app/{rel}"
        return arg.replace("\\", "/")

    @classmethod
    def _wrap_in_docker(cls, run_id: str, target_name: str, cmd: list) -> list:
        tool = cmd[0]
        docker_bin = shutil.which("docker")
        container = cls._ensure_docker_container(run_id, tool)
        translated = ["testssl.sh" if tool.endswith("testssl.sh") else tool]
        translated.extend(cls._translate_to_container_path(run_id, target_name, str(arg)) for arg in cmd[1:])
        return [docker_bin, "exec", container, *translated]

    def _run_subprocess(self, cmd: list) -> Tuple[int, str, str]:
        """
        Executes a subprocess command safely.
        Docker is the default execution mode when available; local binaries are
        used only when Docker is unavailable or explicitly forced via
        WEBSECLAB_SCANNER_MODE=local.
        """
        tool = cmd[0]
        docker_available = self._docker_available()
        local_available = bool(shutil.which(tool))
        use_docker = docker_available and self._docker_preferred() and bool(self._scanner_image(tool))

        if use_docker:
            try:
                cmd = self._wrap_in_docker(self.run_id, self.target_name, cmd)
            except Exception as exc:
                logger.error(f"Failed to prepare docker scanner runtime for {tool}: {exc}")
                return -1, "", str(exc)
        elif not local_available:
            if docker_available and self._scanner_image(tool):
                try:
                    cmd = self._wrap_in_docker(self.run_id, self.target_name, cmd)
                except Exception as exc:
                    logger.error(f"Failed to prepare docker scanner runtime for {tool}: {exc}")
                    return -1, "", str(exc)
            else:
                msg = f"[WinError 2] {tool} not found and Docker execution is unavailable."
                logger.error(msg)
                return -1, "", msg

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return result.returncode, result.stdout, result.stderr
        except Exception as exc:
            logger.error(f"{self.name} failed on {self.ip}: {str(exc)}")
            return -1, "", str(exc)

    def scan(self) -> Dict[str, Any]:
        """
        Runs the scan, handles specific logic.
        Must be implemented by subclasses.
        Returns a dictionary with status, paths, or extracted basics.
        """
        raise NotImplementedError("Scanner must implement scan()")

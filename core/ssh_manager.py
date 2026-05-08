import os
import stat
import shutil
import secrets
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import paramiko

logger = logging.getLogger(__name__)


def running_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def get_secure_key_store_dir() -> Path:
    env_path = os.getenv("WEBSECLAB_KEY_STORE")
    if env_path:
        base = Path(env_path)
    elif running_in_docker():
        base = Path("/data/keys")
    else:
        base = Path.home() / ".webserverseclab" / "keys"

    base.mkdir(parents=True, exist_ok=True)
    restrict_permissions(base)
    return base


def is_ntfs_like_path(path_str: str) -> bool:
    lowered = path_str.lower().replace("\\", "/")
    return (
        ":/" in lowered
        or lowered.startswith("/mnt/c/")
        or lowered.startswith("/mnt/d/")
        or lowered.startswith("c:/")
        or lowered.startswith("d:/")
    )


def restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # On Windows/NTFS permission semantics differ; best effort only.
        pass


def copy_key_to_secure_store(source_path: str, target_name: str) -> Path:
    src = Path(source_path).expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"SSH key not found: {src}")

    key_store = get_secure_key_store_dir()
    suffix = src.suffix if src.suffix else ".key"
    safe_name = f"{target_name}_{secrets.token_hex(6)}{suffix}"
    dst = key_store / safe_name

    shutil.copy2(src, dst)
    restrict_permissions(dst)
    return dst


def save_uploaded_key_to_secure_store(filename: str, content: bytes, target_name: str) -> Path:
    key_store = get_secure_key_store_dir()
    suffix = Path(filename).suffix if filename else ".key"
    if not suffix:
        suffix = ".key"

    safe_name = f"{target_name}_{secrets.token_hex(6)}{suffix}"
    dst = key_store / safe_name

    with open(dst, "wb") as f:
        f.write(content)

    restrict_permissions(dst)
    return dst


def resolve_password(target: Dict[str, Any], runtime_password: Optional[str] = None) -> Optional[str]:
    if runtime_password:
        return runtime_password
    return target.get("ssh_password")


def _find_vagrant_key(target_name: str) -> Optional[Path]:
    """Auto-discover Vagrant private key for a target.

    Looks in ``../Projekt/.vagrant/machines/<name>/virtualbox/private_key``
    relative to the workspace root (the directory containing this package).
    """
    workspace_root = Path(__file__).resolve().parent.parent          # webserverseclab/
    projekt_dir = workspace_root.parent.parent / "Projekt"           # ../../Projekt  (BVI/Projekt)
    candidate = projekt_dir / ".vagrant" / "machines" / target_name / "virtualbox" / "private_key"
    if candidate.exists():
        logger.info("Auto-discovered Vagrant key for %s: %s", target_name, candidate)
        return candidate
    return None


def _auto_provision_key(target: Dict[str, Any]) -> Optional[str]:
    """Resolve the SSH key for a target, preferring a fresh Vagrant key.

    Vagrant regenerates keys on ``vagrant up`` / ``vagrant reload``, so the
    Vagrant key is always the most up-to-date source of truth.  If a Vagrant
    key exists we copy it to the secure store every time (cheap & safe) to
    guarantee the stored copy matches the current VM.
    """
    target_name = target.get("name", "")
    vagrant_key = _find_vagrant_key(target_name)

    if vagrant_key is not None:
        stored = copy_key_to_secure_store(str(vagrant_key), target_name)
        logger.info("Refreshed Vagrant key for %s -> %s", target_name, stored)
        return str(stored)

    # No Vagrant key found — fall back to whatever is already configured
    key_path = target.get("ssh_key_internal_path")
    return key_path


class SSHConnectionManager:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def connect(self, target: Dict[str, Any], runtime_password: Optional[str] = None) -> paramiko.SSHClient:
        host = target.get("ip") or target.get("host")
        port = int(target.get("ssh_port", 22))
        username = target.get("ssh_username") or target.get("user") or "vagrant"
        auth_type = target.get("ssh_auth_type", "key")
        key_path = _auto_provision_key(target)
        key_passphrase = target.get("ssh_key_passphrase")
        password = resolve_password(target, runtime_password)

        if not host:
            raise ValueError("Target host/IP is missing")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_args: Dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": self.timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if auth_type in ["key", "key+passphrase"]:
            if not key_path:
                raise ValueError("SSH key authentication selected, but no internal key path is set")
            connect_args["key_filename"] = key_path
            if auth_type == "key+passphrase" and key_passphrase:
                connect_args["passphrase"] = key_passphrase
        elif auth_type == "password":
            if not password:
                raise ValueError("Password authentication selected, but no password was provided")
            connect_args["password"] = password
        else:
            raise ValueError(f"Unsupported auth type: {auth_type}")

        client.connect(**connect_args)
        return client

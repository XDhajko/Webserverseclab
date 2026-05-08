import os
import shutil
from core.storage import StorageManager
from scanners.base import BaseScanner

import logging
logger = logging.getLogger(__name__)

class NiktoScanner(BaseScanner):
    name = "nikto"
    
    def scan(self) -> dict:
        """
        Runs Nikto against the target's HTTP and HTTPS ports.
        Outputs JSON structure for easier parsing later.
        """
# We will parse stdout since JSON support is bad in some Nikto docker images
        cmd = [
            "nikto",
            "-h", self.ip,
            "-Tuning", "123b"
        ]

        returncode, stdout, stderr = self._run_subprocess(cmd)

        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", stdout)
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stderr", stderr)

        return {"status": "success", "raw_stdout": "saved_in_raw"}

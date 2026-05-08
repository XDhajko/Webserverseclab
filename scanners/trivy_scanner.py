import os
import json
from core.storage import StorageManager
from scanners.base import BaseScanner

import logging
logger = logging.getLogger(__name__)

class TrivyScanner(BaseScanner):
    name = "trivy"
    
    def scan(self) -> dict:
        """
        Runs Trivy against the local dependencies if feasible.
        For remote targets, we might need a different approach, e.g. agent-based.
        """
        json_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "json")
        
        # Skipping Trivy for direct remote IP scanning as it usually scans images/repos/filesystems.
        # This will act as a placeholder or perform a local repo scan.
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", "Trivy remote scan skipped. Use agent for OS vuln scanning.")
        
        with open(json_filepath, 'w') as f:
            json.dump([], f)
            
        return {"status": "skipped", "message": "Trivy remote host scan not supported directly, requires agent."}
    

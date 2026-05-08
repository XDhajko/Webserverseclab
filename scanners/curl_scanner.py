import os
import json
from core.storage import StorageManager
from scanners.base import BaseScanner

class CurlVulnScanner(BaseScanner):
    name = "curl"
    
    def scan(self) -> dict:
        """
        Uses cURL to specifically test for TRACE method (G3),
        Server Tokens in Headers (G1), and missing Security Headers (G4).
        """
        json_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "json")
        
        results = {
            "trace_enabled": False,
            "server_header": None,
            "x_frame_options": None
        }
        
        url = f"http://{self.ip}/"

        # Test TRACE method
        trace_cmd = ["curl", "-s", "-X", "TRACE", "-I", url]
        _, stdout_trace, _ = self._run_subprocess(trace_cmd)
        if "HTTP/1.1 200" in stdout_trace and "TRACE /" in stdout_trace:
            results["trace_enabled"] = True

        # Check Headers (Server and X-Frame-Options)
        head_cmd = ["curl", "-s", "-I", url]
        _, stdout_head, _ = self._run_subprocess(head_cmd)
        
        for line in stdout_head.splitlines():
            low_line = line.lower()
            if low_line.startswith("server:"):
                results["server_header"] = line.split(":", 1)[1].strip()
            if low_line.startswith("x-frame-options:"):
                results["x_frame_options"] = line.split(":", 1)[1].strip()
                
        # Save raw outputs
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", f"TRACE:\n{stdout_trace}\n\nHEAD:\n{stdout_head}")
        
        with open(json_filepath, "w") as f:
            json.dump(results, f)
            
        return {"status": "success", "raw_json": json_filepath}

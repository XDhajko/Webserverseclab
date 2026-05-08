import os
import xml.etree.ElementTree as ET
from core.storage import StorageManager
from scanners.base import BaseScanner

class NmapScanner(BaseScanner):
    name = "nmap"
    
    def scan(self) -> dict:
        """
        Runs Nmap targeting common web ports and outputs XML.
        Extracts basic port information.
        """
        # Save output directly to standard location
        xml_filepath = StorageManager.get_raw_filepath(self.run_id, self.target_name, self.name, "xml")
        
        # When running in docker wrapper, use /out as directory
        # -sV: Service version detection
        # -p 80,443,7080: Web ports (7080 is OLS webadmin)
        # --script http-methods,http-server-header,ssl-cert
        # -oX: Output as XML
        cmd = ["nmap", "-sV", "-p", "80,443,7080", "--script", "http-methods,http-server-header,ssl-cert", "-oX", xml_filepath, self.ip]
        
        returncode, stdout, stderr = self._run_subprocess(cmd)
        
        # We also save standard output just for reference/debugging
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stdout", stdout)
        StorageManager.save_raw_output(self.run_id, self.target_name, f"{self.name}_stderr", stderr)
        
        if returncode != 0 and not os.path.exists(xml_filepath):
            return {"status": "error", "error": stderr}
            
        return {"status": "success", "raw_xml": xml_filepath}

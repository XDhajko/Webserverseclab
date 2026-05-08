import os
import uuid
import json
from datetime import datetime

RUNS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "runs")

class StorageManager:
    """Manages filesystem storage for audit runs according to the architecture spec."""
    
    @staticmethod
    def create_run() -> str:
        """Creates a new run directory structure and returns the run_id."""
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        run_path = os.path.join(RUNS_DIR, run_id)
        
        # Create base run directory and logs
        os.makedirs(os.path.join(run_path, "logs"), exist_ok=True)
        return run_id
        
    @staticmethod
    def init_target_dir(run_id: str, target_name: str):
        """Creates the raw output directory for a specific target in a run."""
        target_path = os.path.join(RUNS_DIR, run_id, target_name, "raw")
        os.makedirs(target_path, exist_ok=True)
        
    @staticmethod
    def get_raw_filepath(run_id: str, target_name: str, scanner_name: str, ext: str = "txt") -> str:
        """Returns the absolute path to save raw scanner output."""
        return os.path.join(RUNS_DIR, run_id, target_name, "raw", f"{scanner_name}.{ext}")

    @staticmethod
    def save_raw_output(run_id: str, target_name: str, scanner_name: str, output: str, ext: str = "txt"):
        """Saves raw output string to the designated run file."""
        filepath = StorageManager.get_raw_filepath(run_id, target_name, scanner_name, ext)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)
        return filepath

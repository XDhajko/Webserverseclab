import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Any


class CVECache:
    def __init__(self, path: str = "data/cve_cache.json"):
        self.path = path
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {"_meta": {"last_updated": "1970-01-01T00:00:00Z", "source": "manual", "schema": "v1"}}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {"_meta": {"last_updated": "1970-01-01T00:00:00Z", "source": "manual", "schema": "v1"}}

    def is_stale(self, max_age_hours: int = 24) -> bool:
        try:
            ts = self.data.get("_meta", {}).get("last_updated", "1970-01-01T00:00:00Z")
            updated = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age_seconds = (datetime.now(timezone.utc) - updated).total_seconds()
            return age_seconds > (max_age_hours * 3600)
        except Exception:
            return True

    def lookup(self, product: str, version: str) -> List[Dict[str, Any]]:
        key = f"{product.lower()}:{version}"
        entries = self.data.get(key, [])
        return entries if isinstance(entries, list) else []

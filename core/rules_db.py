import os
import yaml
from typing import Any, Dict, List


class RulesDBError(Exception):
    pass


REQUIRED_FIELDS = [
    "rule_id",
    "title",
    "category",
    "wstg_id",
    "cwe_id",
    "severity",
    "remediation",
    "references",
]


def _is_https(url: str) -> bool:
    return isinstance(url, str) and url.startswith("https://")


def load_rules(path: str = "data/rules.yaml") -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise RulesDBError(f"Rules file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    if not isinstance(data, list):
        raise RulesDBError("Rules database must be a YAML list")

    seen = set()
    validated: List[Dict[str, Any]] = []

    for idx, rule in enumerate(data):
        if not isinstance(rule, dict):
            raise RulesDBError(f"Rule at index {idx} is not an object")

        for field in REQUIRED_FIELDS:
            if field not in rule:
                raise RulesDBError(f"Rule {rule.get('rule_id', idx)} missing required field: {field}")

        rid = rule.get("rule_id")
        if rid in seen:
            raise RulesDBError(f"Duplicate rule_id detected: {rid}")
        seen.add(rid)

        refs = rule.get("references", [])
        if not isinstance(refs, list) or any(not _is_https(x) for x in refs):
            raise RulesDBError(f"Rule {rid} contains invalid references. All references must be HTTPS URLs")

        rtype = rule.get("rule_type", "configuration")
        has_cve = bool(rule.get("cve_dependent", False))
        if rtype == "configuration" and has_cve:
            raise RulesDBError(f"Rule {rid} mixes configuration and vulnerability semantics")

        validated.append(rule)

    return validated


def rules_to_map(rules: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {r["rule_id"]: r for r in rules}

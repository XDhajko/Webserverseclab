# Severity Model

This project uses a dual severity policy:

- Vulnerability findings:
  - Use official CVSS v3.1 when a CVE is present in local cache.
- Configuration findings:
  - Use a deterministic heuristic mapped to CVSS-like ratings.

## Configuration Scoring Rubric

Score = Impact + Exploitability

- Impact (0.0-6.0):
  - confidentiality impact
  - integrity impact
  - availability impact
- Exploitability (0.0-4.0):
  - required access level
  - remote reachability
  - attacker skill complexity

## Rating Mapping

- 0.1-3.9: Low
- 4.0-6.9: Medium
- 7.0-8.9: High
- 9.0-10.0: Critical

## Notes

- The scanner never performs live NVD queries during scan execution.
- CVE enrichment is done from data/cve_cache.json only.
- Unknown or incomplete evidence can keep a finding open with unknown confidence.

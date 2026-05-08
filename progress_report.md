# Webserver Security Lab: Progress Report (April 2026)

## Overview
This report summarizes the progress made since the introduction of new security rules and hardening procedures in the webserver security lab. The focus has been on improving scanner reliability, automating hardening, and mapping findings to actionable remediation tags.

---

## Key Achievements

### 1. Scanner Reliability Improvements
- **Stale Output Cleanup:** The testssl.sh scanner now deletes old outputs before each run, preventing underreporting of findings.
- **Error Detection:** The scanner treats `scanProblem` and `FATAL` states as errors, ensuring that failed scans are never silently accepted.
- **Verification Workflow:** Hardening runs now produce per-step verification output and are intended to be followed by a fresh scan to confirm effectiveness.

### 2. Hardening Logic Enhancements
- **Tag Mapping:** Findings are mapped to remediation tags, distinguishing between auto-remediable and manual actions.
- **Automated Remediation:** Coverage for auto-remediable findings has improved substantially, though follow-up scans can still surface additional TLS work after HTTPS is enabled or when certificate trust remains a manual task.
- **Immutable Run Snapshots:** Each scan and hardening cycle creates a new, immutable run directory, ensuring clear audit trails and preventing confusion from in-place mutations.

### 3. Normalization and Tracking
- **Findings Normalization:** All scanner outputs are normalized and aggregated into a unified summary.json for each run.
- **Progress Tracking:** The number and severity of findings are tracked across runs, enabling clear measurement of hardening effectiveness.

---

## Results Since New Rules/Hardening
- **Initial State:** Early runs showed high numbers of findings due to scanner bugs and incomplete hardening.
- **After Fixes:** Scanner reliability fixes and improved hardening logic reduced false negatives and enabled consistent remediation.
- **Current State:**
  - Historical runs show a much lower finding count after hardening than the early baseline.
  - Some post-hardening scans still contain auto-remediable TLS follow-up items, especially when HTTPS enablement reveals a second round of transport-layer checks.

---

## Lessons Learned
- Always follow hardening with a verification scan.
- Never mutate existing run snapshots; always create new ones.
- Treat all scan errors as failures to ensure reliability.

---

## Next Steps
- Complete full auto-remediation and verification for the latest run.
- Continue refining TLS normalization, OLS header injection, and follow-on hardening logic.
- Maintain immutable, auditable run records for all future operations.

---

*Prepared for presentation: April 14, 2026*

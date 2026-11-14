# M1 — sensor ingest rate bound on the v0.33 candidate (v0.34)

Date: 2026-11-14 · Branch: `feature/sensor-ingest-rate-bound-v034-20261114` · Base: `test/keyboard-and-untrusted-ui-v033-20261016` (PR #46/#47 head `2793d42`)

## Findings from reviewing PR #48 (head `25f669e`)
1. **Wrong base.** #48 targets v0.1 `main`; the v0.2–v0.33 stack (81 commits) does not contain it, and v0.33 refactored ingestion into a shared `authenticated_sensor` step plus a heartbeat route. #48 cannot be merged as-is without leaving heartbeats unthrottled.
2. **Replay quota exhaustion (defect).** #48 counts quota before the replay-nonce check. One captured signed request, replayed inside the 120 s skew window, burns the sensor's quota (each replay returns 409 but still counts), blocking genuine telemetry.

## Change
- `backend/sentinel/rate_limit.py` ported from #48; `Retry-After` derived from the window.
- Limiter applied in `authenticated_sensor`, so events and heartbeats share one per-sensor quota.
- Stored-nonce lookup returns 409 **before** counting; DB unique constraint stays authoritative.
- Tests: `backend/tests/test_ingest_rate_limit.py` (forged-signature, replay-exhaustion, shared heartbeat quota, default-limit compatibility).

## Evidence status
- Planned: yes · Coded: yes
- Locally tested: **NOT RUN** (authoring environment could not install Python packages; syntax compiled only)
- CI on exact SHA `a52cabf` (2026-11-14): backend 243 passed / 2 failed; all 7 new rate-limit tests PASS. frontend, postgres, detection-quality, release-candidate-integration, runtime-observation: PASS. linux-recovery-drill: FAIL.
- **Pre-existing CI drift, not caused by this change:** the 2 backend failures (`test_systemd_unit_verify.py`) and the recovery-drill failure reproduce on the untouched v0.33 base `2793d42` when re-run on 2026-11-14 (run 38933542729); the same SHA passed in October. The current GitHub runner's `systemd-analyze verify` now emits output for the shipped unit, and the verifier deliberately fails closed on any output.
- Merged / deployed / owner accepted: **no**

## Recommended follow-up
- **Next milestone (blocks every stacked PR):** fix the systemd verifier drift. Capture the runner's `systemd-analyze verify` output in a private debug run, then adjust the unit (or the reviewed contract) without loosening the fail-closed rule.
- Close or retarget PR #48 in favour of this PR once CI passes.
- Remaining roadmap: M2 reproducible browser/a11y run, M3 threat-model & retention review before any live sensor, M4 status wording.

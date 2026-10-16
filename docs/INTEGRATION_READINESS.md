# Integration readiness — stacked Sentinel development branches

**Status:** pre-production; automated integration qualification only, not a real-host security certificate.

## Verified branch topology (October 16, 2026)

- `main`: Sentinel v0.1 baseline (`1b21a599c3a5b376d325ca1d67bd30735495eb4b` at review).
- PR #1: independent v0.1 documentation correction, based on `main`.
- PR #2: v0.2 alert triage, based on `main`.
- PRs #3 through #17: linear sequence, each based on the previous feature PR's branch.
- The present release-candidate qualification branch is based on PR #17, not `main`.

**Do not merge a dependent PR into `main` out of order.** Before merging any PR, review it, recheck GitHub CI on its actual head SHA, and verify that the target base branch is still correct. Once the earliest PR is integrated, re-target/review dependent PRs so the final diff, branch history, and CI results match what will actually land. Do not assume a green descendant branch means every intermediate PR was reviewed. Do not squash/rebase or delete branches without reviewing their dependencies.

## Integrated automated contract

`backend/tests/test_release_candidate.py` checks the real SQLite/Alembic schema and signed FastAPI operations together:

1. Migration graph has a single head equal to the application-declared revision, no disconnected roots or branches.
2. Database-backed admin and analyst are enrolled using the offline credential lifecycle.
3. Legacy/static credentials do not authenticate in database mode; analyst cannot access admin audit endpoint.
4. Explicit sensor-to-asset enrollment allows valid heartbeat and events; mismatched asset is rejected.
5. Five signed authentication failures produce one evidence-linked alert, which can be investigated by the analyst.
6. Revoked analyst cannot authenticate or change the incident; admin continues to work.
7. API stops before an offline backup is made; the backup is independently verified and restored to a new DB.
8. Restored alert state, sensor assignment, record counts, audit chain and case-decision links agree with the source.
9. HMAC-sealed evidence export from the restored snapshot verifies without modifying the backup. Its 30-day selection uses a simulated future instant, not aged production events.

The test intentionally does **not** start systemd, access host SSH logs, exercise a real network endpoint, measure production detection accuracy, verify browser accessibility, or certify an external immutable evidence store. Its evidence artifacts contain only test metadata. No operator secret or host IP is required.

## Release blockers and next priorities

- **Linux-host verification:** install on an authorized Linux host, check actual `systemctl` identity, boot/restart, rotation, outage, recovery, resource usage and operator sign-off; store redacted evidence separately.
- **Reproducible dependency installs:** frontend lacks a committed `package-lock.json`; current CI uses `npm install` and version ranges. Generate a reviewed lockfile in an environment with registry access, verify provenance, switch CI to `npm ci`. Pin GitHub Actions to verified release SHAs in a separate reviewed change.
- **Security acceptance:** external review of authentication, key storage/rotation, privilege separation, signed-event replay and forensic evidence limitations. No permission for automatic containment or unauthorized scanning.
- **Data retention:** current event export is a non-destructive copy, not a verified archival-and-purge protocol. Events, alerts and audit logs must not be deleted using this feature.
- **Default-branch update:** after the chain is reviewed and merged in dependency order, perform a clean checkout from `main`, rerun the entire CI suite on the resulting merge commit and update the release documentation to reflect the actual shipped scope.

## Developer commands

From the `backend/` directory after installing declared test dependencies:

```sh
python -m pytest -q tests/test_release_candidate.py
python -m pytest -q
```

A green CI result establishes automated acceptance on the tested commit only. It is **not** evidence of production readiness or protection of a real machine.

CI entrypoint regression: v0.18 fixed a previously missing `scripts.benchmark_detection` job target by invoking the repository's actual `scripts.benchmark_quality` entry point. The integration test now validates every `python -m scripts.*` workflow target against the checked-out files; only a successful fresh CI run can qualify this correction.

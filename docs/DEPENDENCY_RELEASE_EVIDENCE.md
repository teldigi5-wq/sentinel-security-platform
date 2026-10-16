# Dependency release evidence — v0.20

**Status:** integration candidate with a committed frontend lock, not a production-certified release.

## Verified GitHub Actions provenance

- Source run: [`38883189383`](https://github.com/teldigi5-wq/sentinel-security-platform/actions/runs/38883189383), completed successfully on commit `d4f93240cfda96bc5a594cab23f39106322cc4aa` (October 16, 2026).
- Downloaded artifact ID `12037524902`, `sentinel-frontend-candidate-lock`, from that run.
- Extracted `package-lock.json` unchanged and reviewed its package manifest consistency, full version resolutions, registry URLs, and subresource integrity fields.
- Committed lockfile SHA-256: `9dc3ef0b8ba19d3a817fbf2ae3b672c24d8a281e0023c8327541cb51996ef253`.
- Node 22, npm v3 lockfile schema; dependency tree contains 60 packages plus root. Top-level `package.json` and the lockfile root match exactly.
- All 60 package entries use `https://registry.npmjs.org/` and declare SRI integrity hashes. This is a structural/provenance review, **not** an independent malware or vulnerability audit.

## Current continuous-integration behavior

- `frontend/scripts/verify-lockfile.mjs` rejects a mismatched root package, unapproved resolution URLs, missing hashes, direct-dependency omissions, and lockfile symlinks. The tool does not contact the registry or silently repair the lockfile.
- Frontend CI verifies the committed file, runs `npm ci --no-audit --no-fund` and `npm ls --depth=0`, then type-checks and builds the application.
- Generating a new ephemeral lockfile during CI has been removed. Changes to dependency versions require a reviewed lockfile PR. A CI green result is not a guarantee of a bit-identical compiled application across different OS/Node versions.
- GitHub Actions continue to run with `permissions: contents: read` and SHA-pinned third-party actions. No workflow may write to the repository.

## Remaining release blockers

- The **Python** application still uses version ranges and needs a reviewed constraints/lock strategy covering production, tests and PostgreSQL extras.
- Dependency advisories and licensing must be reviewed independently; this update **does not claim zero vulnerabilities**. The previous CI used `--no-audit` and the new CI retains that flag to avoid failures from registry audit access.
- Linux real-host install, restart/reboot, log rotation, sensor outage and credential recovery still lack signed-off host evidence.
- PR #1 and the v0.2–v0.20 stacked chain must be reviewed and merged in dependency order, with CI rerun on the resultant main branch.

**Scope:** development reproducibility hardening only; not SOC production qualification, attacker attribution, or automated containment.

# Dependency release evidence — v0.19

**Status:** integration candidate, not a locked or production-certified release.

## Security assumptions

GitHub Actions now reference full commit SHAs verified against the upstream Git refs on
2026-10-16: `actions/checkout` v4, `actions/setup-python` v5, `actions/setup-node` v4,
and `actions/upload-artifact` v4. This avoids silent tag movement *between reviews*.
A pinned SHA is a content reference, not a guarantee that an upstream action is
safe. Review action provenance and release notes before repinning.

The workflow uses `permissions: contents: read` for its token and does not
publish repository changes from CI. Permissions for the connected GitHub App
are separate from the workflow's GITHUB_TOKEN.

## Frontend: candidate lock, not a committed lock

The frontend currently declares semver ranges and **does not yet commit**
`frontend/package-lock.json`. Until review, CI:

1. Runs `npm install --package-lock-only --ignore-scripts --no-audit --no-fund` using Node 22.
2. Installs from that same run's resolved lock with `npm ci --no-audit --no-fund`.
3. Uploads the exact candidate lockfile as a seven-day artifact named
   `sentinel-frontend-candidate-lock`.
4. Runs TypeScript checks and a production build.

This prevents the install step from resolving versions *differently within one
run*, and exposes its dependency tree for inspection. It **does not** make
separate CI runs reproducible; each run can choose newer transitive dependencies.
The absence of `--audit` saves CI registry calls, but is **not** a vulnerability
assessment. npm lifecycle scripts can execute during `npm ci`; review their
provenance before release.

## Review before integrating to main

- Download `sentinel-frontend-candidate-lock` from one successful GitHub Actions run.
- Review the lockfile's direct/transitive packages, integrity hashes, registry
  domains, dependency licenses, vulnerability advisories, and compatibility.
- Commit the reviewed `frontend/package-lock.json` unchanged in a separate PR.
- Replace the candidate-generation step with a *strict* `npm ci` that fails if the
  committed lock and manifest differ. Keep static typecheck, production build,
  and existing CI jobs.
- Retest on a clean checkout and document the reviewed lock SHA-256 and CI run URL.
- Create a separately reviewed Python constraints/lock strategy, including extras
  for PostgreSQL and test tools; `backend/pyproject.toml` still uses version ranges.

## Qualification boundaries

A green v0.19 CI result establishes action-reference hygiene and a recorded
frontend dependency resolution, **not** end-to-end reproducible builds, release
artifact provenance, dependency vulnerability clearance, Linux-host qualification,
or authorization for autonomous security operations. Do not merge the stacked
security PRs based only on this check.

## v0.20 — Reviewed and committed frontend lock

The lockfile was retrieved unchanged from successful workflow [38883189383](https://github.com/teldigi5-wq/sentinel-security-platform/actions/runs/38883189383), head commit `d4f93240cfda96bc5a594cab23f39106322cc4aa`, artifact `12037524902`. Lock SHA-256: `9dc3ef0b8ba19d3a817fbf2ae3b672c24d8a281e0023c8327541cb51996ef253`.

The 60 resolved packages use the npm registry HTTPS URL and include integrity metadata. The checked-in npm v3 lock matches the direct runtime/development dependency declarations in `package.json`. CI rejects missing hashes, altered manifest metadata, unapproved package sources and non-locked installs; it runs `npm ci`, direct dependency listing, type-checking and a production build. Lockfile changes must be reviewed in future dependency-update PRs.

**Limits:** This structural review is not a malware, CVE, or license audit. The Python package graph remains unpinned and real Linux deployment remains unqualified. The original v0.19 candidate-generation instructions above describe the historical state, not the new CI behavior.

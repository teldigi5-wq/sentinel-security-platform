# Python dependency qualification — CI Python 3.12 on Linux

SENTINEL v0.21 freezes the **34 (observed) exact distribution versions** installed during a successful v0.20 GitHub Actions `postgres` job (run `38885449442`, job `116921964344`, October 16, 2026). The file `backend/constraints/py312-linux-ci.txt` covers backend runtime, PostgreSQL and test extras. It excludes the editable Sentinel project itself.

GitHub CI now installs all backend jobs with `pip install -c backend/constraints/py312-linux-ci.txt -e './backend[test]'`, while PostgreSQL uses `[postgres,test]`. CI executes an offline validator to check exact installed versions and missing required distributions, plus `pip check`. All constraints are pinned rather than broad ranges, and the validator rejects duplicates, alternate sources, options and VCS references.

**Scope / limitations:** CPython 3.12 on Ubuntu x86_64, using GitHub Actions. This is a **version-constrained resolver**, not a hash-locked requirements installation, not platform-neutral (including Windows or Python 3.13), and not a vulnerability audit. Transitive requirements, build backend, index content, pip tooling and container images are not independently immutable. A future dependency refresh must reproduce resolution in CI, review advisories/licensing, record its evidence, then re-run PostgreSQL and full integration gates before acceptance.

From repository root, after installing dependencies in a Python 3.12 Linux virtual environment:

```sh
python -m pip install -c backend/constraints/py312-linux-ci.txt -e './backend[postgres,test]'
python -m backend.scripts.verify_python_constraints --file backend/constraints/py312-linux-ci.txt --postgres
python -m pip check
```

Host deployment and Python runtime compatibility beyond this CI environment remain unqualified.

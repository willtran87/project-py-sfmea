# Contributing to PySFMEA

PySFMEA welcomes focused changes that improve evidence quality, reviewability, interoperability,
or truthful handling of uncertainty. It is an assurance workbench, so a change is expected to
preserve claim boundaries as carefully as behavior.

## Development setup

Python 3.11 or newer is supported.

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -e ".[dev,signing,quality]"
.venv\Scripts\Activate.ps1
```

Run the same core checks as CI:

```powershell
python -m compileall -q src
python -m ruff check src tests
python -m pytest -q
python -m coverage run --branch -m pytest -q
python -m coverage report
python -m coverage json
python scripts/check_coverage_ratchets.py coverage.json
python scripts/check_module_size_ratchets.py
python -m mypy
python -m bandit -q -r src/pysfmea -c pyproject.toml -ll
python -m pip_audit . --strict --progress-spinner off
python -m pip_audit . --format cyclonedx-json --output pysfmea-build.cdx.json --progress-spinner off
python -m build
```

The CI matrix repeats compilation, linting, tests, and public-schema validation on Linux and
Windows across supported Python versions. Separate jobs build and install the wheel, enforce
branch coverage with critical-module ratchets, type-check extracted subsystem boundaries, scan
source and dependencies, publish a dependency SBOM, run property tests, and mutation-test the
critical fault-plan, outcome, and sandbox-policy verdict logic.
The focused mutation job consumes mutmut 3 native metadata and enforces checked-in aggregate and
independently partitioned per-function population, score, survivor, invalid, and skipped ratchets.
Do not raise survivor or module-size ceilings merely
to pass CI; add tests or subsystem extractions and move the baselines downward.

## Engineering invariants

Changes must preserve these boundaries:

- Scanning and reporting do not import or execute the repository being analyzed.
- Heuristic, observed, human-supplied, and model-generated evidence remain distinguishable.
- Missing context, truncation, opaque regions, and checks that did not run remain explicit.
- Generated artifacts are bounded and published atomically where replacement is supported.
- Integrity and binding checks do not claim authorship, engineering approval, or risk acceptance.
- LLM output remains optional, grounded, reviewable suggestion data rather than an accepted finding.
- Public format changes retain stable identifiers or introduce a new compatibility boundary.

## Tests and fixtures

Place deterministic unit or integration tests under `tests/`. Prefer temporary repositories and
small purpose-built fixtures. Tests must not depend on network access, external model providers,
or execution of untrusted repositories. Optional browser, signing, and standards validators may
be skipped when their dependencies are unavailable, but deterministic core behavior must remain
covered without third-party runtime packages.

If a public diagram, bundle, report-verdict, or verifier-verdict structure changes, update the
schema catalog, documentation, adapter provenance, and compatibility tests in the same change.
Breaking required-field, meaning, type, or closed-vocabulary changes require a new schema/format
major identifier.

## Pull requests

Keep pull requests scoped and include:

- the failure or assurance gap being addressed;
- user-visible behavior and compatibility impact;
- tests and commands run;
- new limitations or unresolved questions;
- documentation and schema changes where applicable.

Do not include generated analyses, review packages, credentials, proprietary guidance, customer
repositories, or assurance evidence unless they are intentionally synthetic and safe to publish.

### GitHub publishing prerequisites

Before pushing a branch, confirm that GitHub CLI authentication is active:

```powershell
gh auth status
```

GitHub requires the additional `workflow` OAuth scope when any commit being pushed creates or
updates `.github/workflows/*.yml`. Refresh the existing authorization interactively before the
push when that scope is absent:

```powershell
gh auth refresh -h github.com -s workflow
```

Never place a token in the remote URL, command history, repository configuration, issue, or pull
request. Prefer the operating system credential store managed by GitHub CLI.

# Release checklist

This checklist produces a reviewable source distribution and wheel. Publishing, tagging, and
signing remain explicit maintainer actions.

## 1. Establish the release state

- Work from an approved release branch with intended changes reviewed.
- Confirm the version in `src/pysfmea/version.py` and the matching changelog entry.
- Confirm public format/schema compatibility and update major identifiers for breaking changes.
- Confirm current diagnostic/guidance/SFTA/evidence/interchange/provenance/review-view/register/work-queue review-package
  capabilities are explicitly declared and verifier-enforced.
- Confirm directory and ZIP package verification retains bounded entry, file, and total sizes,
  streaming hashes, flat layouts, bounded semantic JSON reads, and iterative analysis node/depth
  limits plus fail-closed core-container checks before governed-state hashing or projection
  regeneration.
- Confirm malformed scalar/configuration mutations and forced semantic-projector failures return
  schema-valid sanitized verdicts without tracebacks or internal exception messages.
- Confirm absent and malformed derived assurance state is materialized on a private package
  snapshot, the input analysis remains unchanged, and the resulting directory and ZIP packages
  pass exact analysis-state, register, and work-queue reconciliation.
- Confirm an explicit case-insensitive `.zip` package output selects archive publication without
  requiring `--zip`, while `--zip` without an output retains the default archive filename.
- Confirm package generation independently verifies the complete staging directory before
  publication and that a forced-refresh verification failure preserves the prior destination,
  removes staging residue, and returns bounded rule identifiers.
- Confirm `package --json` emits exactly one schema-valid post-publication verification verdict
  for directory and ZIP outputs and returns nonzero for an invalid receipt.
- Confirm exact interchange verification uses package-producer metadata and retains genuine
  prior-version package compatibility under the current verifier.
- Confirm exact SFTA, validation, and worksheet verification use the package producer's selector
  semantics and that current ID-only selectors cannot widen to unrelated findings.
- Confirm package/audit/CycloneDX/README timestamps reconcile and text projections remain
  semantically portable across LF and CRLF while manifest byte checks remain exact.
- Confirm NASA/FAA/other guidance metadata and captured hashes were not changed unintentionally.
- Ensure the CI matrix is green and dependency-update alerts are reviewed.

## 2. Run release validation

```powershell
python -m pip install -e ".[dev,signing]"
python -m compileall -q src
python -m ruff check src tests
python -m pytest -q
python -m build
sfmea --version
sfmea schema --list --json
sfmea schema --bundle .release-contracts --force
sfmea schema --verify-bundle .release-contracts --json
```

Validate each public schema with a Draft 2020-12 validator and retain the catalog SHA-256 values
with the release evidence. Run the golden evaluation corpus and review unsupported-verification
claims, citation accuracy, trace integrity, and adapter provenance.

```powershell
sfmea scan benchmarks\python_sfmea_corpus\repository `
  -o benchmark-analysis.json --fresh
sfmea evaluate benchmark-analysis.json `
  benchmarks\python_sfmea_corpus\expected.json --json
sfmea assurance benchmark-analysis.json --format work-json -o benchmark-assurance-work.json
sfmea assurance-work-verify benchmark-assurance-work.json --analysis benchmark-analysis.json --json
sfmea package benchmark-analysis.json -o benchmark-review-package --json
sfmea verify-package benchmark-review-package --json
```

## 3. Smoke-test the built wheel

Create a clean virtual environment, install only the wheel, and exercise dependency-free paths.

```powershell
py -3.11 -m venv .release-smoke
$wheel = Get-ChildItem dist\pysfmea-*.whl | Select-Object -First 1
.release-smoke\Scripts\python.exe -m pip install $wheel.FullName
.release-smoke\Scripts\sfmea.exe --version
.release-smoke\Scripts\sfmea.exe schema --list
```

Also test the `signing` extra separately when package signing is part of the release evidence.
Do not treat a successful build or smoke test as tool qualification or analytical validation.

## 4. Publish deliberately

- Review wheel and source-distribution contents before upload.
- Create a signed or otherwise organization-approved tag matching the package version.
- Publish through the project's approved PyPI/GitHub release process.
- Attach checksums, schema-catalog digests, test results, and known limitations.
- Verify installation from the published artifact in a new environment.
- Preserve the release evidence and record any accepted residual tool risks.

# PySFMEA tool-validation corpus

This checked-in corpus provides a reproducible regression baseline for the deterministic scanner. Its source intentionally contains calculation, untrusted-data, serialization, external-interface, persistence, subprocess, configuration, state, timing, and masked-failure constructs.

Run the end-to-end public CLI evaluation:

```powershell
sfmea scan benchmarks/python_sfmea_corpus/repository -o benchmark-analysis.json --fresh
sfmea evaluate benchmark-analysis.json benchmarks/python_sfmea_corpus/expected.json --json
```

Run the release-gating validation tests:

```powershell
python -m unittest tests.test_validation_benchmark
```

The golden baseline is source-aware and enumerates all candidates in its scope. A release
passes when recall, precision, source localization, citation-link accuracy, traceability
integrity, adapter provenance, and repository source accounting remain `1.0`; duplicate
rate and unsupported verification claims remain zero; no expected candidate is missing;
no unexpected candidate appears; repeated scans preserve source/input digests; and
domain-specific guidance profiles remain isolated.

`expected.json` follows the closed `pysfmea-golden-corpus-1` contract. Evaluation requires a
stable regular non-link UTF-8 JSON input, applies byte/structure/record limits, rejects duplicate
keys and cases, and reports the canonical corpus digest in `pysfmea-evaluation-result-1`. Retain
that digest with release evidence so an approved baseline update is explicit.

This synthetic corpus validates deterministic behavior; it does not establish real-world completeness, regulatory qualification, certification credit, or performance on unseen repositories. Any intentional scanner change must be independently reviewed before updating `expected.json`.

The project also maintains a machine-readable SFMEA of PySFMEA itself in
[`tool_sfmea.json`](tool_sfmea.json). It records tool failure modes, triggers, effects,
controls, verification references, and residual risks. Release review must update it
when discovery, model use, execution, evidence, reporting, packaging, or provenance
boundaries change.

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

The golden baseline is source-aware and enumerates all candidates in its scope. A release passes when recall and precision both remain `1.0`, no expected candidate is missing, no unexpected candidate appears, repeated scans preserve source/input digests, and domain-specific guidance profiles remain isolated.

This synthetic corpus validates deterministic behavior; it does not establish real-world completeness, regulatory qualification, certification credit, or performance on unseen repositories. Any intentional scanner change must be independently reviewed before updating `expected.json`.

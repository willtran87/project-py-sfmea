# PySFMEA tool-validation corpus

PySFMEA's governed registry contains 39 targets in fifteen complementary evidence
families:

| Evidence family | Governed targets | Decision supported |
|---|---|---|
| Direct SFMEA semantics | Python SFMEA semantic corpus | Finding, call, control, and semantic-claim accuracy |
| Causal propagation | Python SFMEA causal-propagation corpus | Ordered cascades, effects, deadlines, circuit breakers, and recovery |
| Modern Python dynamics | Python 3.12-3.14 dynamic-resolution corpus | Decorator, descriptor, protocol, dispatch, plugin, framework, reflection, and async resolution |
| Distributed resilience | Multi-service temporal failure corpus | Retry, backoff, breaker, queue, cancellation, idempotency, failover, overload, and recovery behavior |
| Interoperability and drift | Assurance interchange conformance and longitudinal revision corpora | Official-schema/consumer preservation plus semantic, confidence, incremental, runtime, and memory regression |
| Mutation proficiency | Controlled mutation corpus | Failure-mode-derived test sensitivity and surviving-mutant accounting |
| Fuzz ground truth | Seeded parser targets | Crash, hang, sanitizer, replay, and seeded-fault discovery evidence |
| Negative controls and platform matrix | Framework near-misses and supported Python/platform combinations | False-positive pressure plus declared runtime portability |
| Hidden holdout and proficiency | Temporal holdout protocol and cross-organization scheme | Drift-resistant evaluation and interlaboratory z-score/agreement evidence |
| Static/dynamic graph evidence | PyCG, JARVIS, DyPyBench | Call-edge precision/recall, unresolved calls, and runtime-observed coverage |
| Generated-test effectiveness | Pynguin/SBFT, TestExplora, TestGenEval, TDD-Bench Verified, SWE-bench Verified | Proactive defect exposure, search-based comparison, executability, regression safety, coverage, mutation, and cost |
| Security and real defects | OWASP Benchmark Python, BugsInPy, RealVuln, PySASTBench, PatchEval, NIST SARD control | Classification, localization, repair, and cross-language interoperability |
| LLM and agent security | CyberSecEval 4, AgentDojo | Insecure code, injection, tool abuse, autonomous operation, defense effectiveness, and utility/security tradeoffs |
| Repository-context generation | CrossCodeEval Python, CrossCodeLongEval Python, SWE-PolyBench Verified Python | Cross-file retrieval, long-range context, and cross-project repository-level generation |
| Nondeterminism and concurrency | Python nondeterminism/concurrency corpus, IDoFT Python | Controlled mechanisms plus independently maintained real-world flakiness and order-dependence evidence |

Registry presence is not an executed result. Every external run requires a reviewed immutable
snapshot and license record, an independently reviewed adapter, a digest-pinned network-denied
container, complete case accounting, content-addressed evidence, and distinct execution, label,
review, and approval authorities. The PySFMEA semantic and causal fixtures remain internal
regression controls until an external authority supplies representative repositories and labels.

The fifteen bundled corpus/protocol roots are themselves governed. Inventory them without trusting
directory metadata, then verify the exact bytes:

```powershell
sfmea benchmark-corpus-inventory benchmarks --authority "Benchmark custodian" -o corpus.json
sfmea benchmark-corpus-verify corpus.json --root benchmarks --json
```

For an independent round-robin, create and edit the proficiency source, seal it, assess it, and
require exact replay. Quantitative items use declared assigned values and proficiency standard
deviations; qualitative items use declared agreement thresholds. Homogeneity, stability,
multi-organization participation, and provider/reviewer/approval separation fail closed.

```powershell
sfmea benchmark-proficiency-init --authority "Scheme provider" -o proficiency.source.json
sfmea benchmark-proficiency-seal proficiency.source.json -o proficiency.sealed.json
sfmea benchmark-proficiency-assess proficiency.sealed.json -o proficiency.assessment.json
sfmea benchmark-proficiency-verify proficiency.assessment.json --source proficiency.sealed.json --json
```

This checked-in multi-file corpus provides a reproducible regression baseline for the
deterministic scanner. Its sources intentionally contain calculation, untrusted-data,
serialization, external-interface, persistence, subprocess, configuration, state, timing,
masked-failure, declarative-model, decorated web-route, asynchronous branch/exception, background
task, message-publishing, typed receiver, nested-call ordering, and multi-component internal
cascade constructs. The current baseline contains 75 exact source-aware cases. Framework imports
are static fixtures and are never
executed or required as installed dependencies.
It also contains four exact circuit-breaker control records inside a seven-component exhaustive
control scope. Three documentation, electrical-circuit, and generic-counter near-misses are
explicit negative components, so a false control classification reduces precision and fails the
release gate.
Ten exact semantic-output cases add 78 curated field claims across representative calculation,
serialization, interface, persistence, subprocess, masked-failure, data-model, logic, timing, and
response rules. These bind deterministic scanner text, assurance methods, citations, adapters,
confidence, and priority—not reviewer-owned system effects or ratings.

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

The optional `call_cases` collection is exhaustive for every component it names. Each record
labels the raw call reference, resolved reference, resolution provenance, expected external
candidate confidence, source line, evaluation order, await state, and lexical control context.
The location/context identity prevents repeated identical references at different call sites from
collapsing into one case. Evaluation reports exact call-resolution recall and precision overall
and by provenance source; missing or unexpected calls make the CLI evaluation fail.

The optional `control_scope` collection is exhaustive for control detection independently of the
finding and call scopes. `control_cases` label exact positive kind/role records; every other
component in `control_scope` is negative. Evaluation reports overall and per-kind control recall
and false-positive-aware precision together with positive/negative component counts. It measures
static recognition only and does not credit runtime control effectiveness.

The optional `semantic_cases` collection binds a source/component/rule identity to selected exact
deterministic outputs. Evaluation reports exact-case and field-claim recall/precision, missing
cases, field mismatches, and per-field/per-rule populations. Ordered causes/actions remain
order-sensitive; citation and adapter arrays are normalized sets and may be empty to assert that
no link is expected. Any mismatch makes the CLI evaluation fail.

`expected.json` follows the closed `pysfmea-golden-corpus-1` contract. Evaluation requires a
stable regular non-link UTF-8 JSON input, applies byte/structure/record limits, rejects duplicate
keys and cases, and reports the canonical corpus digest in `pysfmea-evaluation-result-1`. Retain
that digest with release evidence so an approved baseline update is explicit.

This synthetic corpus validates deterministic behavior; it does not establish real-world completeness, regulatory qualification, certification credit, or performance on unseen repositories. Any intentional scanner change must be independently reviewed before updating `expected.json`.

For representative repositories, retain the evaluation JSON and convert a structurally reconciled result into
a program-compatible cohort record with `scripts/evaluation_to_cohort.py`. The converter verifies
reported rates against expected-side and actual-side match counts and binds the canonical result
digest, exact retained-file digest, artifact path, and verifier version. Enabled call-resolution
results retain their own count evidence.
Program verification reports both macro and population-weighted micro metrics and can require all
cohorts to be count-backed and artifact-verified. Use distinct named producer and reviewer identities, and retain the
governed corpus and evaluation JSON separately. PySFMEA validates record consistency but does not
authenticate those identities or establish reviewer competence.

Use `scripts/benchmark_scan.py` to record repeat count, scan durations, peak traced Python
allocations, repository size, component/candidate counts, environment, and baseline stability.
Performance thresholds must be approved for the intended machine and repository class.

The project also maintains a machine-readable SFMEA of PySFMEA itself in
[`tool_sfmea.json`](tool_sfmea.json). It records tool failure modes, triggers, effects,
controls, verification references, and residual risks. Release review must update it
when discovery, model use, execution, evidence, reporting, packaging, or provenance
boundaries change.

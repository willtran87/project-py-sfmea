# Operator workflow

This guide is the shortest repeatable path from a Python repository to a reviewed,
evidence-backed SFMEA handoff. The governed analysis JSON is the source of truth. HTML, diagrams,
coverage views, assurance queues, and review packages are projections of that state rather than
independent analyses.

For a diagram-led overview of scanning, failure cascades, evidence credit, finding lifecycle, and
multi-repository assurance, see the [visual guide](VISUAL_GUIDE.md).

```mermaid
flowchart LR
    R["Repository + sfmea.toml"] --> D["Doctor"]
    D --> S["Governed scan"]
    S --> A["sfmea-analysis.json"]
    A --> V["Engineering review"]
    V --> C["Validation + assurance obligations"]
    C --> T["Automated hardening tests + evidence"]
    C --> H["HTML/PDF + diagrams"]
    T --> P["Verified review package"]
    H --> P
```

## 1. Create an isolated artifact directory

Keep generated evidence out of source directories and retain each run separately. From the target
repository in PowerShell:

```powershell
$run = Get-Date -Format "yyyyMMdd-HHmmss"
$artifacts = Join-Path (Get-Location) ".artifacts\$run"
New-Item -ItemType Directory -Path $artifacts | Out-Null
```

Do not commit generated analyses or assurance evidence unless the repository has an explicit
policy for doing so. Analyses can contain machine-local paths and engineering review content.

## 2. Define the system before scanning

Create the configuration once, replace every generated example, and run the read-only preflight:

```powershell
sfmea init .
sfmea doctor .
sfmea doctor . --json
```

At minimum, review the mission, system boundary, operating modes and states, hazards, critical
functions, safe/degraded behavior, humans, timing/resource constraints, assumptions, exclusions,
and rating policy in `sfmea.toml`. `doctor` deliberately rejects an untouched template. A scan can
still be useful with incomplete context, but the missing context remains an explicit limitation
and can block a governed handoff.
The JSON response includes `suggested_actions` for missing or unconfigured coverage and
test evidence. A public scan without `sfmea.toml` is refused unless the operator explicitly
selects discovery-only mode with `--allow-ungoverned`.

## 3. Capture optional test coverage and scan

Coverage is useful attribution evidence, but it is not proof of test adequacy or control
effectiveness.

```powershell
coverage run -m pytest
coverage json -o (Join-Path $artifacts "coverage.json")

sfmea scan . `
  --coverage-json (Join-Path $artifacts "coverage.json") `
  --review-depth focused `
  -o (Join-Path $artifacts "sfmea-analysis.json")
```

Without coverage:

```powershell
sfmea scan . -o (Join-Path $artifacts "sfmea-analysis.json")
```

Scanning parses repository evidence without importing or executing repository code. Treat
`sfmea-analysis.json` as governed state: preserve it, review changes to it, and pass the same file
to every downstream command.
CLI scans use compact JSON to reduce governed-artifact size; add `--pretty-analysis` only for
manual JSON inspection. Review depth changes the family-grouped human queue, not the complete
candidate register. Use `sfmea queue ... --all-records` when exhaustive item-by-item triage is
required.

The configured persistent fact cache makes unchanged Python parsing reusable across CLI
processes. It is content-addressed and performance-only; source, configuration, dependency,
contract, coverage, and repository snapshots remain authoritative. Use `--no-cache` when capturing
a cold performance baseline. Use `.json.gz` for the governed analysis when artifact transfer or
retention size matters; every downstream loader accepts the bounded deterministic gzip form.

The default focused queue admits at most three ordinary families per component and 1,000 total
records per projection. Revalidation, manual, and hazard-linked records remain eligible despite
the per-component cap. Configure `review_queue_max_per_component` and
`review_queue_max_total`, or use `--all-records` for an uncapped exhaustive projection.

## 4. Triage and perform engineering review

Start with the workflow cockpit and concise projections:

```powershell
$analysis = Join-Path $artifacts "sfmea-analysis.json"

sfmea status . --analysis $analysis
sfmea summary $analysis
sfmea validate $analysis
sfmea queue $analysis --limit 25
sfmea review $analysis
```

The local reviewer is the primary place to confirm or revise functions, failure modes, causes,
local/next-higher/end effects, controls, ratings, dispositions, owners, actions, and evidence.
Scanner findings and model suggestions are candidates until a qualified reviewer records a
decision. Use `sfmea validate --strict` and `sfmea status --require-handoff-ready` as automation
gates only when the project intends to enforce the complete workflow.

Validation includes standalone run-manifest digest and cross-binding checks. A manifest whose hash
was recomputed after changing its timestamp, baseline, or resolved-input claims remains an error;
regenerate the analysis from the intended source and configuration instead of editing provenance.

After a rescan, review changed functions and revalidation flags before relying on previous
decisions. Stable IDs preserve applicable reviewer work and keep removed-source history visible.

## 5. Generate the review views

Create human and machine-readable views from the same analysis:

```powershell
sfmea inventory $analysis -o (Join-Path $artifacts "repository-inventory.md")
sfmea coverage $analysis --format markdown -o (Join-Path $artifacts "sfmea-coverage.md")
sfmea coverage $analysis --format json -o (Join-Path $artifacts "sfmea-coverage.json")
sfmea citations $analysis --format json -o (Join-Path $artifacts "guidance-citations.json")
sfmea diagram $analysis -o (Join-Path $artifacts "diagrams.json")
sfmea report $analysis -o (Join-Path $artifacts "sfmea-report.html") `
  --max-output-bytes 52428800 --json
sfmea report-verify (Join-Path $artifacts "sfmea-report.html") --analysis $analysis
```

The self-contained HTML report is the best navigation surface for most reviewers. It contains
searchable findings, evidence, repository accounting, assurance obligations, architecture,
interfaces, propagation, sequences, traceability, circuit-breaker models, and stable record links.
The canonical diagram bundle is renderer-neutral JSON for other tools; the report renders the same
general model without a hosted service.

For release candidates, exercise every report view in a real headless browser and retain the
machine-readable receipt:

```powershell
pip install -e .[browser]
playwright install chromium
python scripts/report_browser_gate.py (Join-Path $artifacts "sfmea-report.html") `
  --analysis $analysis --max-bytes 52428800 --max-load-seconds 5 `
  -o (Join-Path $artifacts "report-browser-quality.json")
```

Set repository-specific budgets from a reviewed baseline; the example values are not universal
acceptance criteria.

Sequence views reconcile bounded static and imported runtime relations. Treat
`runtime_corroborated` as supporting execution evidence, `not_observed` as an instrumentation or
test-selection question rather than proof of unreachability, and `runtime_only` as a prompt to
review dynamic dispatch, mapping, and static bounds. Guidance governance metrics similarly
distinguish maintainer curation from independent project or regulatory approval.

### Repository accounting states

Inventory, coverage, summary, and HTML outputs use the same record-derived projection:

| State | Meaning | Operator action |
|---|---|---|
| `reconciled` | Stored totals agree with the complete bounded entry and region records. | Continue review. |
| `recomputed` | Stored totals were stale or inconsistent; safe counts were recalculated from records. | Use the view for diagnosis, then rescan before handoff. |
| `unavailable` | Complete records were unavailable, so totals would be misleading. | Restore evidence or perform a current scan. |

Semantic artifact coverage describes how much of the bounded repository inventory received a
meaningful accounting status. It is not statement coverage, behavioral coverage, fault-injection
coverage, or evidence that a safety control works.

## 6. Turn accepted findings into hardening tests

Export the verification-obligation register, review its planning decisions, and generate a
deliberately failing pytest scaffold for accepted pending obligations:

```powershell
sfmea assurance $analysis --format markdown -o (Join-Path $artifacts "assurance-register.md")
sfmea assurance $analysis --format work-json -o (Join-Path $artifacts "assurance-work.json")
sfmea assurance-work-verify (Join-Path $artifacts "assurance-work.json") --analysis $analysis

$tests = Join-Path $artifacts "assurance-tests"
sfmea assurance-scaffold $analysis -o $tests --limit 25
sfmea assurance-scaffold-verify $analysis $tests
```

Each obligation carries stimuli, operating context, expected safe/degraded/recovery behavior,
oracles, acceptance criteria, and required evidence. Replace the generated failing bodies with
meaningful repository-specific tests. A scaffold name, textual test reference, or passing status
alone does not satisfy an obligation. Record implemented test bindings and independently review
as-run evidence where the assurance policy requires it.

For a high-value dependency or resilience obligation, generate and verify an explicit
fault-injection plan before implementing the corresponding test:

```powershell
sfmea assurance-fault-plugins
sfmea assurance-fault-plan $analysis VO-... `
  --plugin builtin.sequence.v1 `
  -o (Join-Path $tests "fault-plan.json")
sfmea assurance-fault-complete (Join-Path $tests "fault-plan.json") `
  (Join-Path $tests "fault-case.json") --analysis $analysis `
  -o (Join-Path $tests "fault-plan.ready.json")
sfmea assurance-fault-verify (Join-Path $tests "fault-plan.ready.json") `
  --analysis $analysis --json
sfmea assurance-fault-scaffold (Join-Path $tests "fault-plan.ready.json") `
  --analysis $analysis -o (Join-Path $tests "test_bound_fault.py")
```

The initial verification must report `binding_required`. Put the exact subject, dependency patch
target, fault sequence, expected results, and optional duration bounds in `fault-case.json`.
Completion refuses an unsafe policy or stale/missing obligation binding. Register the generated
pytest bridge and execute it through `sfmea assurance-run`; the execution API refuses an environment
without the runner's approved-sandbox marker. That marker prevents accidental host execution but is
not an authentication credential or a substitute for the container boundary.

Use guarded refresh only for an intact scaffold whose generated starting files remain untouched:

```powershell
sfmea assurance-scaffold-refresh $analysis $tests
```

If implementation work exists, create a new queue or reconcile it manually; the guarded command
will not overwrite that work.

## 7. Build and verify the handoff package

Create a portable checksum-manifested ZIP only after the analysis, reports, and assurance state
are current:

```powershell
$package = Join-Path $artifacts "sfmea-review-package.zip"
sfmea package $analysis --portable -o $package --json
sfmea verify-package $package
sfmea verify-package $package --json
sfmea status . --analysis $analysis --require-handoff-ready
```

Current packages include the governed analysis, human review views, diagram and traceability
projections, assurance registers and work queues, provenance, verification results, and the public
schemas needed for offline validation. Package integrity proves that checked bytes have not
changed; it does not prove authorship, approval, risk acceptance, or engineering correctness.
Use optional detached signing when the handoff also requires authenticity.

## 8. Federate multiple repositories when the system crosses service boundaries

Keep each repository analysis independently governed, then bind them into a separate assurance
program. The initializer captures the exact baseline and complete governed-analysis digest for
every input:

```powershell
$program = Join-Path $artifacts "system-assurance-program.json"
sfmea program-init `
  --analysis api=C:\path\to\api\.artifacts\sfmea-analysis.json `
  --analysis worker=C:\path\to\worker\.artifacts\sfmea-analysis.json `
  -o $program
```

Add cross-repository component relationships, temporal and circuit-breaker contracts, externally
sourced requirements, content-addressed test evidence, independently produced and reviewed
validation cohorts, model-quality evaluations, and named approvals. Use
`REPOSITORY_ID:RECORD_ID` for finding and hazard references. The generated file is intentionally
not handoff-ready; its default quality policy exposes missing external validation and governance.

Convert governed evaluation evidence into the program's closed record shapes:

```powershell
python scripts/evaluation_to_cohort.py evaluation.json `
  --id VAL-API-1 --repository api --framework FastAPI `
  --producer "Benchmark team" --reviewer "Independent assurance team" `
  --artifact-path evidence/evaluation.json `
  -o validation-cohort.json
python scripts/llm_quality_record.py llm-quality-corpus.json `
  --id LLM-API-1 --provider approved-provider --model approved-model `
  --prompt-version pysfmea-discovery-v1 `
  --producer "Model evaluation team" --reviewer "Independent assurance team" `
  --artifact-path evidence/llm-quality-corpus.json `
  -o llm-evaluation.json
```

Insert the resulting records into `validation_cohorts` and `llm_evaluations`. The converters
enforce structural and metric consistency plus named separation, while organizational identity and
authority remain outside PySFMEA. A validation record binds the exact evaluation-result digest and
verifier version and preserves expected-side and actual-side match counts. Enabled call evaluation
additionally carries `call_case_count`, `call_matched_count`, `call_actual_matched_count`, and
`call_actual_count`. Imperfect evaluations are retained when their counts and missing/unexpected
records reconcile. Configure
`require_count_backed_validation`, `require_evaluation_result_artifacts`, `min_micro_recall`,
`min_micro_precision`, and the corresponding
`min_micro_call_resolution_*` gates to require recomputable population-weighted metrics. Legacy
records without counts remain readable only when those new gates are disabled.

`--artifact-path` is interpreted relative to the assurance-program file after inserting the
record. Preserve that exact evaluation JSON at the declared location. The verifier uses strict,
bounded, identity-stable non-link ingestion; checks the raw artifact and canonical result digests;
and reconciles the evaluator, corpus, rates, counts, and missing/unexpected records. A digest string
without an available matching artifact receives no credit under the default policy.

LLM records carry grounded/citation-correct sample counts and total/unsupported claim counts plus
an exact-byte `corpus_artifact`. Enable `require_llm_count_backing` and
`require_llm_corpus_artifacts` (the template defaults) to require sample-level replay. Use
`pysfmea-llm-quality-corpus-2` and include a closed `subject` object matching the converter's
provider, model, and prompt version. `require_llm_subject_binding` rejects substituted or legacy
subjects. The program
aggregates grounding and citation decisions over samples and unsupported claims over total claims;
legacy records remain readable with an explicit `legacy-sample-weighted` aggregation label only
when those gates are disabled.

Corpus credit is unique across the complete program. Validation uses `corpus_sha256`; replayed LLM
evidence uses a canonical `evidence_fingerprint_sha256` over format, subject, and normalized
sample records, so metadata, whitespace, or sample reordering cannot create a second population.
A repeated or semantically equivalent corpus is retained as a declared record for audit visibility
but produces a blocking
`validation.duplicate_corpus_evidence` or `llm.duplicate_corpus_evidence` finding. It receives no
second credit toward repositories, cases, samples, claims, independence totals, artifacts, or
quality metrics. Review `credited_cohorts`, `credited_evaluations`, `duplicate_evidence`, and
`semantic_fingerprinted_evaluations` in the machine verdict, or the corresponding Markdown/HTML
metrics, before accepting population claims.

After intentional edits, refresh the program digest and generate both machine and human views:

```powershell
sfmea program-seal $program
sfmea program-verify $program
sfmea program-verify $program --format json -o (Join-Path $artifacts "program-verification.json")
sfmea program-verify $program --format markdown -o (Join-Path $artifacts "program-verification.md")
sfmea program-verify $program --format html -o (Join-Path $artifacts "program-report.html")
$publicationReceipt = sfmea program-verify $program --format html `
  -o (Join-Path $artifacts "program-report.html") --publication-json | ConvertFrom-Json
sfmea program-report-verify (Join-Path $artifacts "program-report.html") `
  --expect-sha256 $publicationReceipt.artifact_sha256 --program $program `
  -o (Join-Path $artifacts "program-report-verification.json")
```

The verifier consumes the program and completed evidence artifacts through bounded regular-file,
non-link, identity-stable reads. Only digest-verified completed evidence can support timing or
resilience claims. Program HTML is privately staged, self-verified, identity/digest rechecked,
and atomically published only while the destination retains its inspected state.
Use the publication receipt in automation: exit `0` is verified and assurance-ready, exit `1` is
verified but not ready, and exit `2` is a publication/integrity failure. A rejected pre-replace
operation reports whether the prior report was preserved. The report path cannot be the source
program path. Retain `artifact_sha256` with the report to bind downstream review or archival to
the exact published HTML bytes.
Use `--expect-sha256` when consuming a copied, downloaded, or restored report. The verdict keeps
artifact binding separate from exact program regeneration so automation can distinguish transport
drift, stale program semantics, and an unreadable artifact.
Use `--output` for durable JSON receipts. It performs bounded UTF-8 atomic publication, refuses a
destination equal to the report or program source, and detects a concurrent receipt replacement.
Use `--json` only when the pipeline intentionally consumes stdout; the two modes are mutually
exclusive. Durable receipt staging is strictly parsed and canonically compared with the exact
verdict before its identity, size, and bytes are rechecked for atomic replacement. The verdict is
also closed-contract validated before staging, so contradictory status, checks, binding, or
publication claims cannot be persisted through the library exporter.
Failed evidence blocks readiness; inconclusive and unrun records remain visible but
uncredited. It verifies analysis and artifact digests, relationship endpoints, qualified
requirement/finding/hazard references, deadlines and observed maxima, circuit-breaker opening and
recovery, cohort and LLM thresholds, distinct evaluation producer/reviewer identities, known
approval subjects, program-level required roles, and evidence-review independence. The HTML view
adds a bounded repository topology and searchable timing/resilience findings. It does not make an
enterprise identity claim: SSO, RBAC, certificate policy, record retention, and legally controlled
signatures remain external organizational controls.

## 9. Repeat after repository or context changes

Run `doctor`, scan back into the governed analysis path, review changed/revalidation records,
refresh derived views, execute applicable hardening tests, review new evidence, and publish a new
package. Never make an old report or package appear current by copying it or changing timestamps;
the verifiers bind artifacts to the exact governed analysis state.

## Evidence and automation boundaries

- Static caller paths describe potential exposure, not proven causal propagation.
- Runtime traces strengthen observed relationships but do not prove that a failure effect occurred.
- Circuit-breaker timing, state, isolation, fallback, and containment remain uncredited until
  controlled fault-injection and recovery evidence is reviewed.
- NASA, FAA, and organizational citations explain why a rule or obligation is relevant; they do
  not declare compliance or nonconformance automatically.
- LLM discovery and summaries are optional, provider-neutral suggestions grounded in supplied
  evidence. They cannot silently accept findings, change risk, or approve evidence.
- Repository truncation, opaque artifacts, unresolved context, and checks that did not run must
  remain visible through review and handoff.

For deeper behavior and claim boundaries, see [Methodology](METHODOLOGY.md),
[Canonical diagram model](DIAGRAMS.md), [Public schemas](SCHEMAS.md), and the
[NASA/FAA guidance coverage audit](GAP_AUDIT.md).

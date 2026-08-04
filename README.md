# PySFMEA

PySFMEA scans a Python repository and creates a local, reviewable Software Failure Modes and Effects Analysis starter. It inventories functions and methods, recognizes risk-relevant code signals, proposes software-specific failure modes, and opens a browser workspace for engineering review.

It is designed to help begin and maintain an SFMEA. It does not claim that static analysis can determine system consequences or replace a cross-functional review.

## What it produces

- Stable components linked to file and line locations
- Candidate software failure modes derived from public NASA and FAA guidance
- Versioned, applicability-profiled guidance-to-finding citations with typed relationship metadata and source/artifact integrity hashes
- Separate scanner-priority and engineering-risk fields
- Editable functions, requirements, causes, local effects, next-higher effects, and end effects
- Optional severity, occurrence, detection, and RPN fields
- Prevention controls, detection controls, actions, owners, verification evidence, and status
- Persistent decisions across rescans, including removed-source traceability
- Source fingerprints, changed-function flags, and explicit review revalidation
- Generator name, PySFMEA version, and analysis-schema provenance
- Project hazards, critical-function mappings, and domain-specific failure rules
- Optional coverage.py line evidence and more precise internal-caller evidence
- Actual actions, residual/post-action ratings, approvals, and audit timestamps
- Configurable completeness gates with CLI, browser, CSV, and Markdown findings
- Functional propagation and system/component inventory worksheets
- Static/observed Mermaid exports plus canonical renderer-neutral architecture,
  interface, traceability, failure-propagation, control, sequence, state, and custom diagrams
- SFMEA linkage and review-coverage reports
- Self-contained interactive HTML reports with executive metrics, filters, record
  drill-down, architecture, traceability, sequences, notes, CSV extraction, and print styling
- Paginated PDF reports rendered from the same self-contained workspace through a locally installed Edge, Chrome, or Chromium browser
- Dependency baselines, common-cause records, categorical severity, and review audit history
- Lockfile and recursively included requirements baselines
- FastAPI, Flask, Django, Celery, Kafka, RabbitMQ, Click, and Typer entrypoint metadata
- OpenAPI, Swagger, JSON Schema, and protobuf contract inventory with compatibility failure prompts
- Simple and OpenTelemetry JSON runtime-span evidence import
- Provider-neutral, grounded machine discovery and summarization with explicit suggestion review
- A baseline-aware Verification Obligation Register generated from every active finding
- Automation-ready pytest scaffolds that fail until meaningful assurance tests are implemented
- CSV and Markdown exports
- Immutable scan manifests with source/configuration/guidance/adapter/dependency/contract digests and a typed, health-reporting adapter registry
- A local browser reviewer with no hosted service or repository upload

## Install

Python 3.11 or newer is required. From this directory:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\Activate.ps1
```

No runtime third-party packages are required.

Detached package signing is optional and uses the maintained `cryptography` library:

```powershell
python -m pip install -e ".[signing]"
```

## Quick start

Create a project configuration and edit its system boundary, hazards, rating policy,
critical functions, and domain rules:

```powershell
sfmea init C:\path\to\python-repo
sfmea doctor C:\path\to\python-repo
```

`sfmea doctor` is a read-only preflight. It checks the repository, configuration,
system context, analysis revision and ground rules, review team, catalogs, mappings,
and optional coverage evidence before a governed scan. It rejects an untouched
generated example template rather than presenting placeholder inputs as ready. Use
`--json` in automation.

Scan a repository:

```powershell
sfmea scan C:\path\to\python-repo -o C:\path\to\python-repo\sfmea-analysis.json
```

When `-o` is omitted, the analysis is written to
`REPOSITORY/sfmea-analysis.json`, independent of the caller's working directory.

Open the review workspace:

```powershell
sfmea review C:\path\to\python-repo\sfmea-analysis.json
```

The reviewer binds only to `127.0.0.1` and saves changes into the analysis JSON file.

Export the worksheet:

```powershell
sfmea export C:\path\to\python-repo\sfmea-analysis.json --format csv
sfmea export C:\path\to\python-repo\sfmea-analysis.json --format markdown
sfmea report C:\path\to\python-repo\sfmea-analysis.json
sfmea pdf C:\path\to\python-repo\sfmea-analysis.json -o C:\path\to\python-repo\sfmea-report.pdf
sfmea diagram C:\path\to\python-repo\sfmea-analysis.json -o diagrams.json
sfmea inventory C:\path\to\python-repo\sfmea-analysis.json
sfmea architecture C:\path\to\python-repo\sfmea-analysis.json
sfmea audit C:\path\to\python-repo\sfmea-analysis.json
sfmea queue C:\path\to\python-repo\sfmea-analysis.json --limit 25
sfmea sequence C:\path\to\python-repo\sfmea-analysis.json --entrypoint "src/api.py:create_payment"
sfmea traceability C:\path\to\python-repo\sfmea-analysis.json
sfmea coverage C:\path\to\python-repo\sfmea-analysis.json
sfmea citations C:\path\to\python-repo\sfmea-analysis.json --format json
sfmea citations C:\path\to\python-repo\sfmea-analysis.json --format csv
sfmea assurance C:\path\to\python-repo\sfmea-analysis.json --format json
sfmea assurance C:\path\to\python-repo\sfmea-analysis.json --format csv
sfmea assurance-scaffold C:\path\to\python-repo\sfmea-analysis.json -o assurance-tests --limit 25
sfmea package C:\path\to\python-repo\sfmea-analysis.json
sfmea package C:\path\to\python-repo\sfmea-analysis.json --portable
sfmea package C:\path\to\python-repo\sfmea-analysis.json --portable --zip
sfmea verify-package C:\path\to\python-repo\sfmea-analysis-review-package
sfmea verify-package C:\path\to\python-repo\sfmea-analysis-review-package.zip
sfmea verify-package C:\path\to\python-repo\sfmea-analysis-review-package --json
```

`sfmea report` creates one portable HTML file that can be opened directly in a
modern browser without a web server or network connection. The report includes an
executive overview, validation and coverage charts, a searchable and filterable
failure-mode explorer, record evidence drill-down, configured interface flows,
subsystem summaries, requirement/hazard traceability, automatically selected bounded
sequence views, and methodology limitations. It also supports a printer-friendly
layout and filtered CSV download.

Include a separate engineering-notes file and choose an explicit output path when
preparing a review handoff:

```powershell
sfmea report sfmea-analysis.json `
  --notes engineering-review-notes.md `
  -o .artifacts\sfmea-report.html
```

All styles, scripts, and report data are embedded. Repository-controlled text is
inserted as data and rendered through safe DOM text operations; a restrictive content
security policy prevents the report from loading remote scripts, styles, fonts, or
objects. Reports embed up to 10,000 records by default. Use `--max-records` to set a
different bound, up to 50,000; the report states when its record set is truncated.
The HTML is a review aid and is not included in the checksum-manifested review package.

The report includes a guidance-citation workspace with source status, exact section/page
locators, mapping applicability, usage counts, and one-click filtering to affected findings.
It also contains a general inline-SVG diagram explorer. PySFMEA generates
canonical architecture, interface-flow, requirement/hazard traceability,
failure-propagation, control/action coverage, and bounded sequence models. The
explorer provides deterministic layout, node/edge counts, element-type filtering,
text search, zoom/fit, keyboard-accessible node inspection, evidence details, and
SVG download.

Project-specific diagrams can represent state machines, deployment flows,
cause/effect chains, data flow, or another directed relationship model. Include one
or more validated JSON files with repeatable `--diagram` arguments:

```powershell
sfmea report sfmea-analysis.json `
  --diagram workflow-states.json `
  --diagram deployment-flow.json `
  -o sfmea-report.html
```

Use `sfmea diagram --type TYPE` to export generated models for reuse by other
renderers or engineering tools. The complete schema, limits, import formats, and
example state diagram are documented in [Canonical diagrams](docs/DIAGRAMS.md).

`sfmea package` creates a complete review directory containing the governed analysis
snapshot, CSV and Markdown worksheets, inventory, architecture, traceability,
coverage, validation, summary, audit history, and a SHA-256 manifest. A non-empty
destination is protected unless `--force` is supplied.
Packages are generated in a staging directory and published only after every report
and checksum succeeds. `--force` refreshes recognized package files but refuses a
directory containing unrecognized files, protecting reviewer-added material.
`--portable` keeps repository-relative source evidence while removing machine-local
absolute repository, configuration, coverage, trace, and source-analysis paths from
the packaged snapshot. The governed working analysis is not modified.

`sfmea verify-package` independently checks the package format, complete artifact
set, path safety, regular-file boundaries, byte sizes, SHA-256 checksums, baseline,
schema, and generator provenance. It rejects traversal paths, symbolic links,
missing or extra files, malformed metadata, and content tampering, and returns a
nonzero exit code when the package is invalid. This establishes consistency with the
manifest; it is not a digital signature, engineering approval, or semantic review.

`--zip` atomically publishes the same complete package as a single ZIP file. The
verifier reads ZIP packages through a guarded temporary staging area: entry names
must be unique, canonical root-level paths; directories, symbolic links, encrypted
members, unknown files, oversized entries, excessive expanded size, and suspicious
decompression ratios are rejected before content verification. It does not use
general-purpose archive extraction. A successful ZIP result also reports the SHA-256
of the archive itself for transfer-log comparison. The current safety limits are 100
entries, 100 MB per expanded member, and 500 MB total expanded content.

Optionally authenticate a verified package with an organization-controlled Ed25519
PEM key. Keep the detached signature beside—not inside—the package:

```powershell
$env:SFMEA_SIGNING_PASSPHRASE = "injected-by-your-secret-store"
sfmea sign-package sfmea-analysis-review-package.zip `
  --private-key quality-release-private.pem `
  --passphrase-env SFMEA_SIGNING_PASSPHRASE `
  --signer "Quality Engineering Release"

sfmea verify-package sfmea-analysis-review-package.zip `
  --signature sfmea-analysis-review-package.zip.sig.json `
  --public-key quality-release-public.pem
```

`sign-package` first requires the package to pass normal integrity verification. The
signed statement binds the exact ZIP bytes—or, for a directory, its manifest
bytes—to the package format, project, baseline, schema version, generation time,
signer label, and signing time. Verification requires both `--signature` and an
explicitly trusted `--public-key`; it reports the SHA-256 fingerprint of that key.
Use your approved key-generation, storage, rotation, revocation, and release process.
This proves possession of the matching private key, not that the signer was authorized
or that the SFMEA was technically approved.

Check whether the review meets the configured completeness gates:

```powershell
sfmea validate C:\path\to\python-repo\sfmea-analysis.json
sfmea validate C:\path\to\python-repo\sfmea-analysis.json --strict
```

The normal command exits nonzero for errors. By default, missing system context,
ground rules, revision, review team, review dispositions, and required worksheet
fields are errors. `--strict` also exits nonzero for warnings, making it suitable
for a CI review gate. Use `--json` for automation.

When `sfmea.toml` exists at the repository root it is loaded automatically. After code or analysis context changes, run the same scan command again. Human review fields and field-level history are preserved. Reviewed items require revalidation when their callable body, module/class context, dependency baseline, applicable hazards/requirements/interfaces, or identity changes. Unambiguous moves and renames retain predecessor IDs; removed candidates remain traceable.

Useful scan options:

```text
--exclude-private   Exclude underscore-prefixed functions (included by default)
--exclude-nested    Exclude nested functions and closures (included by default)
--include-tests     Treat test functions as analyzed components
--coverage-json     Add line evidence from coverage.py JSON output
--exclude GLOB      Exclude matching relative paths (repeatable)
--focus GLOB        Analyze matching path:qualified-name components (repeatable)
--config PATH       Use a specific project configuration
--fresh             Replace, rather than merge, an existing analysis
```

Generate coverage evidence with your normal test command, for example:

```powershell
coverage run -m pytest
coverage json -o coverage.json
sfmea scan . --coverage-json coverage.json -o sfmea-analysis.json
```

Coverage is evidence of observed execution, not proof that a detection control is effective.

## Interface contracts

OpenAPI/Swagger JSON or YAML, `*.schema.json`, and protobuf files are discovered
automatically. Each file becomes a stable interface-contract component with extracted
operations and data types, a content hash, and a contract-compatibility failure-mode
prompt. Contract changes participate in the repository baseline and therefore trigger
normal review revalidation. The built-in YAML extraction is intentionally conservative;
generated, templated, or externally hosted specifications should be supplied as local
artifacts or represented through configured system interfaces.

Contracts use the normal `path:qualified-name` mapping syntax. For example,
`openapi.json:Interface contract *` can allocate an API contract to a subsystem,
requirements, hazards, and configured system interfaces. Those mappings seed the
contract worksheet and participate in context-change revalidation.

## Runtime evidence and sequences

Import either a simple span list or OpenTelemetry Protocol JSON export:

```powershell
sfmea trace-import sfmea-analysis.json trace.json --label "payment integration test"
sfmea sequence sfmea-analysis.json --entrypoint "src/api.py:create_payment"
```

Runtime spans are mapped by `sfmea.component`, `code.function`,
`code.function.name`, or an unambiguous span/function name. Sequence edges are
labelled as static or observed. Observed edges prove only that the captured execution
occurred; they do not establish path completeness. Imports retain their file hash,
source baseline, timestamp, mapping counts, mapping method, and audit event. Reimporting
the same trace is idempotent. Code-file plus function attributes resolve otherwise
ambiguous span names, and the CLI reports mapped and unmapped totals.

## Grounded machine discovery

Inspect exactly what would be sent before contacting a model:

```powershell
sfmea discover sfmea-analysis.json --scope "src/payments/**" --limit 10 --dry-run
```

PySFMEA sends bounded scanner metadata, configured context, existing candidates, and
runtime relationships. It does not read arbitrary source bodies for model discovery.
Repository text is represented as untrusted evidence data. Each packet also supplies a
closed catalog of authoritative section/page locators. A model may propose only those
citation IDs; invented IDs reject the response. Accepted links are labeled
`reviewer_accepted` and remain distinct from deterministic, curated rule mappings.

Use an explicitly selected OpenAI-compatible chat-completions endpoint:

```powershell
$env:SFMEA_LLM_API_KEY = "your-provider-key"
sfmea discover sfmea-analysis.json `
  --scope "src/payments/**" `
  --endpoint "https://provider.example/v1/chat/completions" `
  --model "approved-model"
```

For a local compatible server, an API key is not required:

```powershell
sfmea discover sfmea-analysis.json `
  --endpoint "http://127.0.0.1:11434/v1/chat/completions" `
  --model "local-approved-model"
```

Remote endpoints must use HTTPS. Plain HTTP is accepted only for the exact loopback
hosts `localhost`, `127.0.0.1`, and `::1`; URL-embedded credentials and redirects are
rejected so evidence and authorization headers cannot be redirected elsewhere.

List and adjudicate suggestions:

```powershell
sfmea suggestions sfmea-analysis.json
sfmea suggestion-review sfmea-analysis.json SUG-... `
  --decision accept `
  --reviewer "Jordan Lee" `
  --rationale "Credible interface failure not covered by the deterministic rules."
```

The browser reviewer provides the same accept/reject workflow. Acceptance creates a
new **unreviewed** worksheet record. Generated content cannot set ratings,
disposition, workflow status, approval, or closure fields, and it cannot overwrite an
existing record. Suggestions record provider/model identity, prompt version, source
baseline, evidence IDs, uncertainties, questions, response hash, and review history.
Proposed suggestions become stale after a baseline change.

## Executable assurance checklist

Every active SFMEA finding receives one stable verification obligation. The obligation
records the failure condition, preconditions, recommended verification method, stimulus,
local and system oracles, acceptance criteria, required environment, repeatability,
evidence requirements, and an approved-sandbox command contract. Methods are selected
deterministically from the failure class and rule: property testing for data/calculation,
contract or integration testing for interfaces, state-transition testing, concurrency,
stress, fault injection, security testing, configuration inspection, or architecture
review as appropriate.

Export the complete Failure Mode Assurance Matrix:

```powershell
sfmea assurance sfmea-analysis.json --format json -o assurance-register.json
sfmea assurance sfmea-analysis.json --format csv -o assurance-register.csv
sfmea assurance sfmea-analysis.json --format markdown -o assurance-register.md
```

Create a bounded pytest implementation queue for a component or finding glob:

```powershell
sfmea assurance-scaffold sfmea-analysis.json `
  --scope "src/payments/**" `
  --limit 25 `
  -o assurance-tests
```

The generated pytest cases fail intentionally until an engineer implements the recorded
stimulus, oracles, and acceptance criteria. Empty, skipped, or assertion-free tests cannot
silently satisfy the checklist. The scaffold, a named test, coverage, or a passing result is
not evidence by itself. Verification and closure require current execution artifacts,
proof that the failure was triggered, acceptance-criterion evaluation, independent review,
and any required approval. `assurance-review` can govern planning states but cannot directly
set `verified`, `accepted_risk`, or `closed`.

Register a completed test, preview its exact container contract, and execute it only after
explicit approval:

```powershell
sfmea assurance-test-register sfmea-analysis.json VO-... `
  --test-path tests/test_failure_control.py `
  --author "Verification Engineer" `
  --origin human

sfmea assurance-run sfmea-analysis.json VO-... `
  --image "organization/assurance-python@sha256:..." `
  --initiated-by "Execution Operator" `
  --dry-run

sfmea assurance-run sfmea-analysis.json VO-... `
  --image "organization/assurance-python@sha256:..." `
  --initiated-by "Execution Operator" `
  --approve-execution
```

The Docker/Podman runner does not pull images. It disables networking and IPC, mounts
source read-only, drops capabilities, sets no-new-privileges, uses an unprivileged user,
does not forward credentials, and applies CPU, memory, process, file-descriptor, temporary
filesystem, output, and time limits. The command, image identity, test hash, baseline,
repository state, logs, JUnit result, and artifact hashes are recorded in a managed evidence
directory. A dry run validates the same preconditions and prints the exact command without
executing repository code.

Existing CI evidence can be imported without re-executing it:

```powershell
sfmea assurance-evidence-import sfmea-analysis.json VO-... `
  --manifest ci-evidence/manifest.json `
  --initiated-by "CI Evidence Importer"
```

The versioned import manifest identifies the current `baseline_id`, repository revision,
test path and SHA-256, shell-free `command_argv`, outcome, environment, dependency-lock
metadata, and one or more manifest-relative artifacts with optional SHA-256 claims. Import
is idempotent, rejects traversal and symlinks, enforces size limits, re-hashes and copies the
artifacts, and labels them `externally_supplied_unattested`. An organization may therefore
apply its own CI attestation policy without PySFMEA silently treating the import as trusted.

Finally, a different identity evaluates every original acceptance criterion:

```powershell
sfmea assurance-evidence-review sfmea-analysis.json EXEC-... `
  --reviewer "Independent Reviewer" `
  --decision sufficient `
  --stimulus-observed yes `
  --criterion-result 1=pass `
  --criterion-result 2=pass `
  --criterion-result 3=pass `
  --rationale "Failure stimulus occurred and each criterion is supported by intact evidence."
```

The review verifies the execution statement and every artifact again. `sufficient` is
rejected unless the run passed, the intended stimulus was observed, all criteria pass, the
baseline is current, all hashes are intact, and the reviewer is independent. Verification
still does not close the finding or accept residual risk.

## Top-down Software Fault Trees

SFMEA is reconciled with user-defined top-down Software Fault Trees. Add one or more
`[[fault_trees]]` entries to `sfmea.toml`; each tree identifies its hazard and top event,
explicit events, and AND, OR, VOTE, or INHIBIT gates. Events can correlate to findings by
stable finding ID, `path:qualified-name` component glob, and failure-mode text glob. The
configuration validator rejects duplicate IDs, unknown inputs, invalid voting thresholds,
unknown hazards, unsupported node types, and logical cycles.

```powershell
sfmea sfta sfmea-analysis.json --format json -o sfta.json
sfmea sfta sfmea-analysis.json --format csv -o sfta-gaps.csv
sfmea diagram sfmea-analysis.json --type sfta -o sfta-diagrams.json
```

Every configured hazard receives a tree record. When explicit logic is absent, PySFMEA
creates an **undeveloped placeholder**, not inferred gate logic. Reconciliation reports:

- top-down basic or undeveloped events with no bottom-up finding;
- hazard-linked bottom-up findings with no corresponding tree event; and
- correlations whose finding does not carry the tree's hazard link.

The self-contained report provides a hazard/SFTA workspace and links each tree to its
renderer-neutral inline-SVG diagram. Gate logic remains a preliminary engineering model:
correlation does not establish causation, independence, minimal cut sets, probability, or
hazard-analysis completeness.

The browser warns before discarding edited fields, constrains numeric ratings to
1–10, supports Ctrl/Cmd+S to save, Ctrl/Cmd+Enter or **Save & next** to advance,
and focuses the search box with `/`. Large result sets render in bounded 200-record
batches so searching and review remain responsive. The **Analysis health** dialog
summarizes review coverage, trace linkage, runtime mapping, contracts, and project-level
quality-gate findings without presenting them as correctness claims.

Generate a deterministic index summary or a grounded narrative:

```powershell
sfmea summarize sfmea-analysis.json --by hazard --key HZ-PAYMENT --json
sfmea summarize sfmea-analysis.json --by subsystem --key Payments --llm `
  --endpoint "https://provider.example/v1/chat/completions" `
  --model "approved-model"
```

Machine summaries are bounded to cited worksheet records, stored separately, and
marked stale after a baseline change. They are not risk-acceptance conclusions.

## Evaluation hook

The repository includes a checked-in synthetic validation corpus under
`benchmarks/python_sfmea_corpus`. It enumerates every expected candidate in scope,
requires recall and precision of `1.0`, checks repeated-scan input digest stability,
and verifies regulatory-profile isolation. See [benchmark instructions](benchmarks/README.md).

## Standards-oriented interchange and change analysis

Export screening candidates to SARIF 2.1.0 and the declared dependency inventory to
CycloneDX 1.6:

```powershell
sfmea sarif sfmea-analysis.json -o findings.sarif
sfmea sbom sfmea-analysis.json -o components.cdx.json
```

SARIF results are explicitly labeled SFMEA **candidates**, use stable partial fingerprints
and repository-relative locations, and remain notes unless an accepted high-priority item
warrants warning presentation. The CycloneDX BOM includes declaration sources and hashed
manifests, but labels unresolved declarations as `declared-not-resolved`; it does not invent
installed versions or transitive dependencies.

Compare canonical runs with:

```powershell
sfmea diff previous-analysis.json current-analysis.json -o analysis-diff.json
```

The differential output lists new, removed, and materially changed findings; changed causes,
effects, severity, controls, hazards, requirements, citations, disposition, and source
fingerprints; changed assumptions/configuration/dependencies; and previously sufficient
evidence that is no longer sufficient. It is an impact-analysis input, not proof of
behavioral equivalence. SARIF, CycloneDX, SFTA JSON/CSV, assurance, and evidence catalogs are
also included in the checksum-manifested review package.

Maintain a golden JSON corpus of expected component/rule pairs:

```json
{
  "scope": ["src/payments/**:*"],
  "cases": [
    {
      "source": "src/payments/service.py",
      "component": "PaymentService.submit",
      "rule_id": "interface.unavailable"
    }
  ]
}
```

Run the exact-key regression check with:

```powershell
sfmea evaluate sfmea-analysis.json expected-sfmea.json
sfmea evaluate sfmea-analysis.json expected-sfmea.json --json
```

Without `scope`, evaluation is limited to components named by the cases. Optional
`path:component` globs define a broader regression boundary. This measures
deterministic candidate regression; semantic correctness of effects, ratings, and
controls still requires qualified review.

`source` may be omitted when a qualified component name is unique. If the same name
and rule occur in multiple files, evaluation stops and requests a source rather than
silently combining the cases.

## Recommended review sequence

For each candidate:

1. Confirm the intended function and authoritative requirement.
2. Accept, reject, or request more information about the proposed failure mode.
3. Refine the initiating condition and specific causes.
4. Trace the local effect to the next-higher level and system/end effect.
5. Record existing prevention and detection controls with evidence.
6. Apply your organization's documented rating scales.
7. Define actions, an owner, a target date, and verification evidence.
8. Record completed actions and reassess residual/post-action risk.
9. Rescan following design changes and explicitly revalidate changed or removed failure paths.

Start with a mission-, safety-, business-, or data-critical vertical slice. Code-level SFMEA can generate a large number of candidates, while the system effect normally cannot be inferred from code alone.

## Scanner rules

Every included callable receives two baseline candidates:

- Omitted/no function
- Incorrect, incomplete, inconsistent, or unintended function

Additional candidates are generated when the AST shows relevant signals:

| Signal | Candidate failure families |
|---|---|
| Function parameters and nontrivial behavior | Missing, malformed, out-of-range, stale, duplicated, or inconsistent input |
| HTTP, sockets, queues, or service clients | Dependency unavailable/late and successful-but-wrong response |
| Database or filesystem use | Lost, partial, duplicated, reordered, or corrupt state |
| Environment/configuration access | Missing, inherited, stale, or wrong configuration |
| Serialization | Corrupt, truncated, ambiguous, or version-incompatible representation |
| Subprocesses | Hang, misleading success, partial action, or wrong target |
| Async/concurrency | Early, late, duplicated, out-of-sequence, cancellation, and race failures |
| Broad or silent exception handlers | Failure masked or not detected |
| Complex loops | Excessive resource use or non-termination |
| Arithmetic and numerical libraries | Equation, sign, unit, rounding, precision, convergence, overflow, or underflow failures |
| Branching and state mutation | Wrong condition, missing sequence, invalid or partial transition |
| Internal calls | Wrong/missing call, invalid parameter, or misunderstood result contract |
| Hardware-access libraries | Missing, wrong, stale, reset, or untimely device response |
| Runtime/dependency manifests | Interpreter, operating system, package, resolver, or build-baseline drift |

`sfmea.toml` can add project-specific rules using `path:qualified-name` globs. This is
the preferred way to represent domain failures such as duplicate transactions,
incorrect control commands, unsafe state transitions, or privacy boundary failures.

The `[quality]` section controls review-completeness expectations, including project
context, named decision reviewers, requirement linkage, hazard linkage, local and
propagated effects, causes, rating rationales, action descriptions and ownership,
verification evidence, residual-risk rationale, and high-severity closure approval.
These checks validate that records are complete; they do not decide that the
engineering judgment is correct.

The implementation and exact starter language are documented in [Methodology](docs/METHODOLOGY.md). The requirement-by-requirement comparison is maintained in the [SFMEA guidance coverage audit](docs/GAP_AUDIT.md).

## Ratings and prioritization

`screening_priority` is a triage signal based on observable code characteristics such as interfaces, persistence, concurrency, complexity, broad exception handling, and approximate fan-in. It is not Severity, Occurrence, Detection, Action Priority, SIL, ASIL, DAL, or another safety classification.

- Severity should be based on the credible system/end effect.
- Occurrence, if used, needs an agreed interpretation and evidence. Software does not wear out like hardware.
- Detection should assess the effectiveness of actual controls, not simply whether a test file exists.
- Severity can use a governed categorical scale or a numeric 1–10 scale. RPN is calculated only when numeric S/O/D values are all supplied. PySFMEA does not implement the proprietary AIAG/VDA Action Priority table.

Organizations using automotive, aerospace, medical, nuclear, or other regulated processes must apply the relevant licensed standards, rating tables, independence, tool-qualification, and approval requirements themselves.

Select guidance applicability explicitly in `[analysis]`:

```toml
guidance_profiles = ["core_sfmea", "faa_commercial_space"]
```

Available built-in profiles are `core_sfmea` (default), `nasa_assurance`,
`faa_commercial_space`, `faa_airworthiness`, `security`, and `legacy_reference`.
Only selected profiles contribute citations to findings. Selecting a profile records
the intended analytical context; it does not determine legal applicability or compliance.

## Public guidance basis

- [NASA Software Engineering Handbook — Software FMEA](https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis): bottom-up propagation; data, event, interface, timing, state, detection, corrective action, and change-impact guidance.
- [NASA-STD-8739.8B](https://standards.nasa.gov/sites/default/files/standards/NASA/B/0/NASA-STD-87398-Revision-B_1.pdf): software hazard contributions, requirements traceability, assurance, and verification for applicable NASA work.
- [NASA NPR 7150.2D](https://nodis3.gsfc.nasa.gov/displayDir.cfm?c=7150&s=2D&t=NPR): NASA software-engineering lifecycle and bidirectional-traceability requirements. Applicability is NASA- or contract-specific.
- [FAA software and computing-system safety guide](https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf): detailed SFMEA classifications and worksheet examples. FAA now lists this as [legacy licensing guidance](https://www.faa.gov/space/licenses/legacy-regulations), so PySFMEA labels its mappings `legacy_methodological` rather than current compliance.

Additional current and historical public sources are profile-gated:

- [NASA Software Safety Guidebook, NASA-GB-8719.13](https://standards.nasa.gov/sites/default/files/standards/NASA/Baseline/0/nasa-gb-871913.pdf): detailed legacy-method reference for SFMEA, SFTA, and data/event prompts.
- [FAA AC 450.141-1A, Computing System Safety](https://www.faa.gov/regulations_policies/advisory_circulars/index.cfm/go/document.information/documentNumber/450.141-1A): active commercial-space guidance covering SFMEA, SFTA, verification independence, and evidence traceability.
- [FAA AC 20-115D](https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D): airworthiness development-assurance context for lifecycle objectives/data, change impact, and tool qualification; licensed normative references are not bundled.

Every built-in source, locator, profile, and rule mapping is stored in the analysis under
`guidance` with catalog and selection SHA-256 digests. Public PDF records include exact
downloaded artifact byte counts and hashes where captured. Each scanner record contains typed citation links under
`scanner.citations`. `sfmea citations` emits the complete source → locator → rule → finding
graph as JSON or a flat review-ready CSV. These relationships explain methodology or review
relevance; they do not prove a defect, regulatory applicability, or compliance.
- [IEC 60812:2018](https://webstore.iec.ch/en/publication/26359): general FMEA/FMECA process applicable to software and interfaces. The standard is not included with this project.

## Known limitations

- Python's dynamic imports, monkey-patching, dependency injection, reflection, decorators, and runtime dispatch make the call graph approximate; this is not whole-program semantic analysis.
- Textual test references and optional line coverage are evidence hints only; they do not establish test adequacy or control effectiveness.
- Project context and hazards must be supplied by people. A configured hazard may seed an end effect and severity, but its applicability still requires confirmation.
- Suggested causes and actions are prompts, not findings proven to exist.
- Rule output can be repetitive. Scope and review disposition are expected to reduce the working set.
- Project-defined common causes and explicit SFTA are supported, but the tool does not infer or approve arbitrary fault-tree logic, prove independence, perform STPA, or automatically execute runtime fault injection or mutation analysis.
- The local reviewer detects external file changes and refuses stale writes, but it has no identity provider, electronic-signature control, role enforcement, or enterprise approval workflow.
- Hosted-model use is opt-in and requires an explicit endpoint. Organizations remain responsible for provider approval, retention policy, regional processing, and sensitive-data controls.
- CSV exports neutralize formula-like reviewer text for safer spreadsheet opening, but exported files still need the recipient organization's document controls.
- No safety certification, compliance determination, probabilistic failure estimate, or tool qualification is provided.

## Development

Run the tests without installing:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

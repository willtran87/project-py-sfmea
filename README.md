# PySFMEA

[![CI](https://github.com/willtran87/project-py-sfmea/actions/workflows/ci.yml/badge.svg)](https://github.com/willtran87/project-py-sfmea/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

PySFMEA scans a Python repository and creates a local, reviewable Software Failure Modes and Effects Analysis starter. It inventories functions and methods, recognizes risk-relevant code signals, proposes software-specific failure modes, and opens a browser workspace for engineering review.

It is designed to help begin and maintain an SFMEA. It does not claim that static analysis can determine system consequences or replace a cross-functional review.

## What it produces

- Stable components linked to file and line locations
- A hashed system-context manifest covering mission, modes, states, must-work and
  prohibited functions, safe/degraded states, humans, timing/resources, deployment,
  criticality, assumptions, and exclusions—with unresolved questions kept explicit
- A bounded repository artifact inventory that distinguishes analyzed, indexed,
  excluded, unresolved, and opaque files/regions without executing repository code
- Candidate software failure modes derived from public NASA and FAA guidance
- Versioned, applicability-profiled guidance-to-finding citations with typed relationship metadata and source/artifact integrity hashes
- Governed organizational guidance packs for licensed/internal source metadata,
  exact locators, quote policies, applicability, tailoring, and rule mappings
- Separate scanner-priority and engineering-risk fields
- Editable functions, requirements, modes/states, causes, local/next-higher/end
  effects, safe/degraded/recovery behavior, and residual risk
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
  interface, traceability, failure-propagation, control, circuit-breaker state,
  sequence, state, and custom diagrams
- Bounded failure-cascade paths that trace potential caller exposure, distinguish
  conservative static links from runtime-observed relations, and place timing and
  uncredited circuit-breaker containment boundaries in the propagation view;
  repeated finding paths and breaker infrastructure are shared by component/control
  scope while every failure mode retains an independent trace edge. Bounded views
  select one priority-ordered finding per component before using remaining capacity,
  preventing a few finding-heavy components from crowding out the system overview.
  Scanner and report metadata disclose path-count and depth limits, omitted paths and
  segments, and whether the underlying static caller-path inventory was itself truncated
- SFMEA linkage and review-coverage reports
- Self-contained interactive HTML reports with executive metrics, filters, record
  drill-down, architecture, traceability, sequences, notes, CSV extraction, and print styling
- Paginated PDF reports rendered from the same self-contained workspace through a locally installed Edge, Chrome, or Chromium browser
- Dependency baselines, common-cause records, categorical severity, and review audit history
- Lockfile and recursively included requirements baselines
- FastAPI, Flask, Django, Celery, Kafka, RabbitMQ, Click, and Typer entrypoint metadata
- First-class circuit-breaker candidates with extracted roles, CLOSED/OPEN/HALF-OPEN
  state models, trip/cooldown expressions, clock and synchronization evidence,
  isolation keys, degraded fallback contracts, class-wide method correlation,
  observed-versus-conceptual state labeling, explicit model-review gaps, and
  failure-mode-specific fault-injection obligations
- OpenAPI, Swagger, JSON Schema, and protobuf contract inventory with compatibility failure prompts
- Simple and OpenTelemetry JSON runtime-span evidence import
- Provider-neutral, grounded machine discovery and summarization with explicit suggestion review
- A baseline-aware Verification Obligation Register generated from every active finding,
  with structured direct-caller and bounded upstream-path observation context, inventory
  completeness metadata, and compensating-evidence criteria when discovery is truncated
- Automation-ready pytest scaffolds that fail until meaningful assurance tests are implemented
- CSV and Markdown exports
- Immutable scan manifests with source/configuration/guidance/adapter/dependency/contract digests, a typed health-reporting adapter registry, and a hashed per-adapter contribution ledger
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

Public interchange contracts are discoverable without network access or optional packages:

```powershell
sfmea schema --list
sfmea schema --list --json
sfmea schema diagram-bundle -o diagram-bundle.schema.json
sfmea schema html-report-verification -o report-verdict.schema.json
sfmea schema workflow-status -o workflow-status.schema.json
sfmea schema assurance-work-queue -o assurance-work-queue.schema.json
sfmea schema --bundle offline-contracts
sfmea schema --verify-bundle offline-contracts
sfmea schema --verify-bundle offline-contracts --json
```

The catalog publishes deterministic SHA-256 identifiers for self-contained JSON Schema
Draft 2020-12 documents. See [docs/SCHEMAS.md](docs/SCHEMAS.md) for compatibility and
semantic-validation boundaries.

## Quick start

Create a project configuration and edit its system boundary, hazards, rating policy,
critical functions, and domain rules:

```powershell
sfmea init C:\path\to\python-repo
sfmea doctor C:\path\to\python-repo
sfmea status C:\path\to\python-repo
```

`sfmea doctor` is a read-only preflight. It checks the repository, configuration,
system context, analysis revision and ground rules, review team, catalogs, mappings,
and optional coverage evidence before a governed scan. It rejects an untouched
generated example template rather than presenting placeholder inputs as ready. Use
`--json` in automation.

`sfmea status` is the read-only workflow cockpit. It auto-discovers configuration and
analysis files in the repository root or `.artifacts`, classifies the current lifecycle
stage, reports review and validation counts, identifies missing or stale HTML/PDF/package
artifacts, verifies discovered review-package checksums and provenance, and prints ordered
next commands. The stage names the primary phase; a separate eight-gate checklist exposes
all simultaneous handoff blockers for repository readiness, analysis availability,
validation, finding review, revalidation, assurance planning, report currency, and package
currency. Every blocked gate includes concrete evidence and a remediation action ID that
maps to the ordered command list. It separately reports assurance-plan, test-implementation, execution,
evidence-review, and verification progress for accepted findings. If an assurance scaffold
exists beside the analysis, status also verifies its manifest and governed-analysis binding,
reports expected implementation edits separately, distinguishes unrelated analysis changes
from changed verification contracts, and recommends a guarded in-place refresh only when
the scaffold manifest is intact and its generated starting files remain untouched. Invalid
queues and queues containing implementation edits are directed to inspection and a new
destination so work is preserved. A scaffold remains optional and does not become a handoff
gate merely because it exists. New packages carry a
canonical governed-analysis digest; status compares
that digest, baseline, and schema with the current analysis so a copied or timestamp-touched
package cannot appear current. Handoff readiness requires a fresh, valid, exactly matched
package. Its JSON form is stable for automation:

```powershell
sfmea status C:\path\to\python-repo --json
sfmea status C:\path\to\python-repo --require-handoff-ready
sfmea status C:\path\to\python-repo --assurance-scaffold D:\review-queues\payments
sfmea status C:\path\to\python-repo `
  --assurance-scaffold D:\review-queues\payments `
  --assurance-scaffold D:\review-queues\platform
```

Validate that payload offline with the published `workflow-status` JSON Schema; gate-count,
readiness, and remediation relationships remain semantic checks supplied by PySFMEA.

HTML reports carry a canonical analysis-state declaration plus independent embedded-data
and whole-document digests. Status verifies them before treating a report as current, so
copying, touching, or modifying an old report does not satisfy the handoff gate. These
checks detect staleness and unreconciled content changes; unlike an optional detached
package signature, they are not an authentication mechanism. Suggested refresh commands use the discovered output paths
and replacement flags so they can be run directly. `--require-handoff-ready` returns a
nonzero exit code until all eight gates pass, making the cockpit usable in CI without
changing normal interactive behavior.
Conventional `assurance-tests` directories are discovered automatically; use
`--assurance-scaffold PATH` when a queue is stored elsewhere, repeating the option for
subsystem- or team-specific queues. Paths are normalized and deduplicated in request order.
Workflow-status v2 exposes the complete list under `assurance_scaffolds` and
`paths.assurance_scaffolds`, while the original singular artifact/path fields continue to
reference the first queue for consumers migrating from v1. For each explicitly requested
path that is missing while accepted obligations still need tests, status prints a distinct
generation command and continues to treat every queue as optional.

When one or more queues are present, status also emits an
`assurance_scaffold_portfolio`. It measures accepted pending-obligation coverage using only
currently bound queues, identifies obligations assigned to more than one queue, lists
uncovered accepted obligations, reports unowned current queues and duplicate stable queue
IDs, and provides a JSON inspection action for overlaps. Duplicate assignments name each
queue ID, owner, and path. This is an ownership and workload-coordination aid—not evidence,
approval, risk acceptance, or a handoff gate.

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
sfmea assurance-scaffold-refresh C:\path\to\python-repo\sfmea-analysis.json assurance-tests
sfmea assurance-scaffold-archive C:\path\to\python-repo\sfmea-analysis.json assurance-tests
sfmea assurance-scaffold-verify C:\path\to\python-repo\sfmea-analysis.json assurance-tests
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
sequence views, system-context completeness, repository coverage/opaque-region
accounting, stable record deep links, column controls, and methodology limitations.
Finding details support previous/next traversal across the current filtered result set,
Alt+Left/Alt+Right keyboard navigation, copyable stable deep links, and direct jumps to
the exact failure-propagation node or assurance checklist entry. Diagram nodes link back
to their governed finding and checklist, and stable diagram/node hashes restore the same
trace location when shared. If a bounded projection omitted a requested finding, the report
states that explicitly and preserves a return path to the full finding record. The report also
offers deterministic review-order, priority, RPN, severity, source, component, and
disposition sorting plus one-click view reset. It supports a printer-friendly layout
and filtered CSV download.

Include a separate engineering-notes file and choose an explicit output path when
preparing a review handoff:

```powershell
sfmea report sfmea-analysis.json `
  --notes engineering-review-notes.md `
  -o .artifacts\sfmea-report.html
```

Verify the complete standalone document and optionally require an exact analysis match:

```powershell
sfmea report-verify .artifacts\sfmea-report.html `
  --analysis sfmea-analysis.json
sfmea report-verify .artifacts\sfmea-report.html `
  --analysis sfmea-analysis.json `
  --json
```

Without `--analysis`, integrity is checked but the binding is explicitly reported as not
checked. Reports generated before whole-document protection remain identifiable as legacy
payload-only artifacts rather than being represented as fully protected.

JSON mode always emits a versioned verdict, including when the report is missing, malformed,
unsafe to follow, or fails verification. `failed_checks` identifies completed negative checks,
`unchecked_checks` distinguishes checks that could not run, and `errors` carries stable codes
plus diagnostic messages. `binding_requested` and `binding_checked` preserve whether an exact
analysis comparison was requested and whether it actually ran. Exit status is `0` for a valid verdict, `1` when the artifact or
binding is rejected, and `2` when a requested analysis input cannot be loaded.

Failure-propagation coverage can be expanded or simplified without changing code:

```powershell
sfmea report sfmea-analysis.json `
  --propagation-record-limit 75 `
  --propagation-path-limit 2 `
  --propagation-depth 6 `
  --propagation-include-finding FM-EXAMPLE-001 `
  -o .artifacts\sfmea-report.html
```

The same options are available on `sfmea pdf` and `sfmea diagram`. Defaults remain
40 findings, three caller paths per component, and six caller levels. Values are
individually bounded and their combination must fit the canonical 2,000-node diagram
budget. To show more findings, reduce path count or depth; selected limits are stored
in report data, diagram metadata, and JSON bundle generation provenance.
Use repeatable `--propagation-include-finding FINDING_ID` options when named active
findings must appear regardless of their global priority. Pinned findings are embedded
first, duplicate IDs are collapsed, and remaining capacity keeps the component-first
selection policy. The distinct pin count cannot exceed the record limit.
The report's diagram status and inspector show the effective selection policy, pinned
scope, configured finding/path/depth limits, conservative node-budget use, projection
status, and machine-readable omission reasons. Custom propagation settings are rejected
for unrelated `sfmea diagram --type` values instead of being silently ignored.
The propagation view also presents a copyable regeneration command bound visually to the
report's analysis-state SHA-256, making a reviewed projection straightforward to reproduce.

All styles, scripts, and report data are embedded. Repository-controlled text is
inserted as data and rendered through safe DOM text operations; a restrictive content
security policy prevents the report from loading remote scripts, styles, fonts, or
objects. Reports embed up to 10,000 records by default. Use `--max-records` to set a
different bound, up to 50,000; the report states when its record set is truncated.
To keep large standalone reports responsive, the assurance workspace embeds at most
250 full obligations and 100 recent executions, while each SFTA reconciliation class
embeds at most 250 gaps. Every bounded view states its embedded and total counts and
points to the complete governed JSON register in the portable review package. Finding
details still retain their obligation IDs and lifecycle summaries.
The HTML is a review aid and is not included in the checksum-manifested review package.

The report includes a guidance-citation workspace with source status, exact section/page
locators, mapping applicability, usage counts, and one-click filtering to affected findings.
It also contains a general inline-SVG diagram explorer. PySFMEA generates
canonical architecture, interface-flow, requirement/hazard traceability,
failure-propagation, control/action coverage, and bounded sequence models. The
explorer provides deterministic layout, node/edge counts, element-type filtering,
text search, zoom/fit, keyboard-accessible node inspection, evidence details,
bidirectional finding/checklist navigation, stable node links, and SVG download.
Exported JSON diagram bundles bind the exact governed analysis-state digest and schema,
carry a canonical content digest, verify that digest when re-imported, and publish
atomically so a failed write cannot replace the previous artifact.

Verify a standalone bundle before consuming it, optionally requiring an exact match to
the current governed analysis:

```powershell
sfmea diagram-verify diagrams.json --analysis sfmea-analysis.json
sfmea diagram-verify diagrams.json --analysis sfmea-analysis.json --json
```

Verification checks the bundle digest, every embedded canonical diagram schema, unique
diagram IDs, and—when `--analysis` is supplied—the schema, baseline, and complete analysis
state binding. Omitting `--analysis` is reported as “not checked,” never as a match.
Human and JSON output use the same versioned verdict contract. JSON remains parseable for
rejected, malformed, missing, oversized, and symbolic-link inputs, with completed failures
kept distinct from checks that could not run. Exit statuses follow the report verifier's
`0` valid, `1` rejected artifact/binding, and `2` analysis-input error convention.

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

To add an organization-controlled or licensed standard without modifying PySFMEA,
configure a governed JSON guidance pack. The schema, integrity behavior, licensing
boundary, and complete example are documented in
[Organizational guidance packs](docs/GUIDANCE_PACKS.md).

The implementation-to-acceptance audit is maintained in
[Workbench requirements traceability](docs/REQUIREMENTS_TRACEABILITY.md); it identifies
the executable evidence for each capability and keeps the remaining authority boundary
explicit.

`sfmea package` creates a complete review directory containing the governed analysis
snapshot, resolved context, repository coverage, adapter-run provenance, CSV and
Markdown worksheets, inventory, architecture, traceability,
coverage, validation, summary, audit history, the exact offline public-schema catalog,
twelve self-contained assurance, diagram, workflow, package, catalog, signature, and verifier
schema documents, a standalone `assurance-work.json` hardening queue,
and a SHA-256 manifest. A non-empty destination is protected unless `--force` is supplied.
The manifest explicitly declares `analysis_diagnostics_projection_v1`,
`assurance_register_projection`, and `assurance_work_queue_projection` capabilities so offline
consumers can discover these contracts without guessing from filenames or tool versions.
Packages are generated in a staging directory and published only after every report
and checksum succeeds. `--force` refreshes recognized package files but refuses a
directory containing unrecognized files, protecting reviewer-added material.
`--portable` keeps repository-relative source evidence while removing machine-local
absolute repository, configuration, coverage, trace, and source-analysis paths from
the packaged snapshot. The governed working analysis is not modified.

`sfmea verify-package` independently checks the package format, complete artifact
set, path safety, regular-file boundaries, byte sizes, SHA-256 checksums, baseline,
analysis schema, generator provenance, schema-catalog completeness, schema identities,
canonical schema digests, and the manifest/verdict contract boundary. It also verifies the
work queue's own digest and recomputes its exact projection from packaged `analysis.json`, so
rewriting the queue and updating the manifest checksum is still rejected. The verifier also
regenerates the full `assurance-register.json`, verifies its embedded queue,
and requires that embedded and standalone queues agree exactly. It also regenerates the
summary, validation findings, resolved system context, repository inventory, and adapter-run
ledger from packaged analysis. A changed diagnostic artifact remains invalid even if its
manifest checksum is recomputed; the validation generation timestamp is treated as provenance
while counts and findings match exactly. Producer version is verified as
provenance but excluded from semantic queue matching, so compatible format-2 artifacts remain
valid across verifier upgrades. JSON verdicts carry a dedicated
`pysfmea-review-package-verification-1` discriminator independently of the artifact
format they observe. The verifier rejects traversal paths, symbolic links,
missing or extra files, malformed metadata, and content tampering, and returns a
nonzero exit code when the package is invalid. This establishes consistency with the
manifest and the declared deterministic projections; it is not a digital signature, engineering
approval, or proof that planned controls and tests are sufficient.
Directory verification is flat and bounded: it does not recursively traverse unexpected trees,
hashes manifested files as streams, and reapplies byte limits before every semantic JSON parse.
Pre-0.37 format-1 packages without the additive schema bundle remain supported; a package
that declares or contains schema files must carry a complete internally consistent set. The
complete 0.37 four-contract, 0.38 six-contract, 0.39 eight-contract, 0.40–0.42
nine-contract, 0.43–0.44 ten-contract, and 0.45 eleven-contract profiles remain verifiable;
mixed, partial, duplicated, and unknown profiles are rejected.
ZIP verifier output identifies embedded artifacts with stable logical references such as
`package.zip!/assurance-work.json`; it never exposes a deleted temporary extraction path.

`--zip` atomically publishes the same complete package as a single ZIP file. The
verifier reads ZIP packages through a guarded temporary staging area: entry names
must be unique, canonical root-level paths; directories, symbolic links, encrypted
members, unknown files, oversized entries, excessive expanded size, and suspicious
decompression ratios are rejected before content verification. It does not use
general-purpose archive extraction. A successful ZIP result also reports the SHA-256
of the archive itself for transfer-log comparison. Directory and ZIP verification share a
100-entry boundary, a 100 MB per-file limit, and a 500 MB total-content limit.

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

The `detached-signature` public schema defines the complete envelope and can be exported with
`sfmea schema detached-signature`. Structural validity does not replace cryptographic
verification against the exact package and a separately trusted public key.

For offline CI integrations, `sfmea schema --bundle DIRECTORY` atomically exports the catalog
and every contract in one operation. `sfmea schema --verify-bundle DIRECTORY` independently
checks the complete known profile, root-level regular-file boundary, JSON structure, identities,
and catalog digests. Use `--json` for the stable machine verdict. Refreshing a non-empty bundle
requires `--force` and is refused if the directory contains unrecognized or non-file entries.

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
sfmea assurance sfmea-analysis.json --format work-json -o assurance-work.json
sfmea assurance sfmea-analysis.json --format csv -o assurance-register.csv
sfmea assurance sfmea-analysis.json --format markdown -o assurance-register.md
```

Every export also carries a deterministic work-queue projection for accepted findings. It
separates definition and plan-review blockers from implementation-ready tests,
execution-ready tests, failed execution remediation, evidence review/remediation, final
verification review, and resolved obligations. Each entry includes stable finding/obligation
IDs, priority, component, blockers, automation eligibility, the latest execution state, and a
next-action ID. JSON contains the complete `pysfmea-assurance-work-queue-2` object; CSV and
Markdown expose the same state alongside each obligation. These are lifecycle directions—not
approval to execute repository code and not evidence that a test is effective.

Use `--format work-json` when CI, an issue importer, or a portfolio dashboard needs only the
queue. It carries generator provenance, exact baseline/schema/analysis-state binding, and a
canonical content digest. Validate its structure offline with
`sfmea schema assurance-work-queue`, then verify integrity and freshness before consuming it:

```powershell
sfmea assurance-work-verify assurance-work.json
sfmea assurance-work-verify assurance-work.json --analysis sfmea-analysis.json --json
```

The first command detects content drift. Supplying the analysis additionally recomputes the
entire deterministic projection, so a stale queue or an edited queue with a recomputed digest
is rejected. Verification establishes consistency, not authorship, approval, or authorization
to execute tests.

The local browser reviewer also exposes an **Assurance plan** workspace for accepted
findings. It presents the derived stimulus, acceptance criteria, definition gaps,
implementation/evidence state, explicit work state and next action, and lifecycle progress without requiring users to copy
obligation IDs into CLI commands. A named reviewer and rationale are mandatory for every
planning decision. Evidence-derived and approval-controlled states remain read-only, and
every mutation carries the loaded analysis ETag as an `If-Match` precondition. External
file edits and saves from another browser tab therefore produce a conflict and offer to
reload the latest revision instead of silently overwriting newer work. The reviewer may
keep the unsaved form visible for comparison or copy-out before choosing to reload; unsaved
assurance-plan fields also warn on dialog dismissal and page exit.

For large analyses, the browser loads a purpose-built reviewer projection rather than
transferring report- and package-only collections it cannot display. The complete
governed analysis remains unchanged on disk and is still available from the full API.
JSON responses are gzip-compressed when the browser advertises support, keeping local
review startup responsive without creating a second source of truth.
Reviewer data, validation results, and assurance planning are delivered as one
revision-consistent workspace snapshot. Serialization occurs while the state is locked,
but network transfer does not hold that lock, so a slow browser cannot block unrelated
review operations. A failed load produces an explicit retry screen and never mutates the
analysis.

Validation findings are indexed once when the workspace loads, so gate filtering and
sorting scale with the records being reviewed instead of repeatedly scanning the complete
validation register for every item. Selecting a finding also adds
its stable ID to the local reviewer URL, providing a bookmarkable deep link without
changing the governed analysis.

After an item or assurance-plan save, the reviewer now retains the unchanged local
inventory and refreshes only validation and assurance state. Both responses must match
the mutation ETag; any missing or divergent revision automatically falls back to a full
workspace reload. This reduces routine save traffic without allowing a mixed-revision UI.
Finding, assurance-plan, suggestion, and manual-item mutations are single-flight: their
buttons remain disabled until the request and cleanup finish. Network and validation
failures leave the draft state intact and surface explicit retryable feedback instead of
creating duplicate self-conflicts or unhandled browser errors.

The review server binds to loopback and rejects non-loopback `Host` headers to limit
DNS-rebinding exposure. Mutations are revision-checked again immediately before their
atomic save; if persistence fails, the server reloads the governed disk record and
discards the unpersisted in-memory mutation instead of exposing a phantom review state.
The local-only bind restriction is enforced by the Python entry point as well as the CLI.
If the governed JSON becomes unreadable while review is open, reads and mutations return
a retryable service-unavailable response instead of serving stale state or dropping the
connection.

Create a bounded pytest implementation queue for a component or finding glob:

```powershell
sfmea assurance-scaffold sfmea-analysis.json `
  --scope "src/payments/**" `
  --limit 25 `
  --queue-id payments-critical `
  --owner "Payments Assurance" `
  --purpose "Critical payment failure hardening" `
  -o assurance-tests
```

The scaffold defaults to findings whose engineering disposition is `accepted` and skips
obligations already bound to implemented tests. This prevents unreviewed scanner prompts
or rejected candidates from silently becoming a hardening backlog. Use
`--disposition unreviewed` or `--disposition all` only when deliberately prototyping from
planning drafts, and `--include-implemented` only when reproducing an existing queue.
`--queue-id` supplies a stable organizational identity; when omitted, a deterministic ID is
derived from the selection and metadata. Optional `--owner` and `--purpose` values are
bounded, stored inside the integrity-protected manifest, displayed by verification/status,
and carried into portfolio overlap records.

Scaffold directories are assembled in a sibling staging directory and published with one
atomic rename, so an interrupted generation does not present a partial checklist as
complete. The manifest binds the source baseline, schema, and canonical governed-analysis
state, and records starting hashes for the generated pytest module and operator README.
It also records a minimal digest of the selected verification contracts, dispositions,
source status, and implementation state, together with the scope, disposition, limit, and
implemented-test inclusion policy that produced the queue. During collection, the pytest
module verifies the immutable manifest; editing placeholders into substantive tests remains
possible and expected. Register implemented source with
`sfmea assurance-test-register` to content-hash bind it to its obligation. These digests
detect accidental manifest drift and stale provenance; they are not approval signatures or
substitutes for the governed analysis.

Verify integrity and freshness before consuming or continuing work from a scaffold:

```powershell
sfmea assurance-scaffold-verify sfmea-analysis.json assurance-tests
sfmea assurance-scaffold-verify sfmea-analysis.json assurance-tests --json
```

If an untouched queue becomes stale, refresh it without reconstructing its selection or
identity:

```powershell
sfmea assurance-scaffold-refresh sfmea-analysis.json assurance-tests
```

Refresh preserves the recorded scope, disposition, limit, implemented-test policy, queue
ID, owner, and purpose. It proceeds only when the current-format manifest is intact and
every declared generated file still matches its starting hash. Publication moves the old
queue to a temporary sibling backup, atomically installs the regenerated queue, and restores
the prior queue if installation fails. Any edited or removed generated file causes a closed
failure; verify the queue and generate into a new destination instead of risking test work.
If replaying the selection finds no pending obligations, verification labels the queue a
`retirement_candidate`. Workflow status recommends the guarded archive command rather than
a refresh that must fail:

```powershell
sfmea assurance-scaffold-archive sfmea-analysis.json assurance-tests
```

Archival proceeds only for an intact retirement candidate whose generated files still match
their starting hashes. It writes an integrity-protected retirement record containing the
queue identity, prior manifest digest, current analysis binding, and full contract-removal
diff, then atomically moves the entire directory under the sibling `.sfmea-archive` folder.
An explicit `--output` may select another location on the same filesystem volume. Existing
destinations are never overwritten, active queues are refused, and a failed move removes the
provisional retirement record so the active path remains unchanged. The operation preserves
the manifest and generated files rather than deleting the audit record. Scaffold verification
checks the retirement-record digest and its queue, prior-manifest, and archive-path bindings;
archived queues are immutable and cannot later be refreshed or replaced in place.

Verification distinguishes an invalid manifest, materially changed verification contracts,
and an analysis whose unrelated state advanced while every selected contract remained
current. It replays the saved selection and emits an obligation-level diff for added,
removed, and changed contracts, including the exact fields responsible. Placeholder edits
are reported as informational because test implementation is expected; they become governed
when registered against an obligation.

The generated pytest cases fail intentionally until an engineer implements the recorded
stimulus, oracles, and acceptance criteria. Empty, skipped, or assertion-free tests cannot
silently satisfy the checklist. The scaffold, a named test, coverage, or a passing result is
not evidence by itself. Verification and closure require current execution artifacts,
proof that the failure was triggered, acceptance-criterion evaluation, independent review,
and any required approval. `assurance-review` can govern planning states but cannot directly
set `verified`, `accepted_risk`, or `closed`.

Each derived obligation carries a canonical verification-contract digest. Editing the
governed failure condition, operating context, effects, controls, safe/degraded/recovery
expectations, stimulus, or acceptance contract regenerates the obligation and automatically
reopens previously planned or verified work with stale evidence. JSON and Markdown assurance
exports include explicit planning, implementation, execution, and verification progress.

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
quality-gate findings without presenting them as correctness claims. The **Assurance
plan** dialog is limited to accepted findings and governed planning transitions; test
execution, evidence sufficiency, verification, closure, and risk acceptance continue
through their dedicated auditable workflows.

The reviewer includes a keyboard-visible skip link, associated form labels, explicit
dialog names, announced result/save status, and selected-record semantics for assistive
technology. These semantics complement the keyboard shortcuts; they do not replace the
organization's accessibility acceptance testing in its supported browser and platform.

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
- The local reviewer uses strong ETag/`If-Match` revision checks to refuse stale writes from external edits or concurrent browser sessions, but it has no identity provider, electronic-signature control, role enforcement, or enterprise approval workflow.
- Hosted-model use is opt-in and requires an explicit endpoint. Organizations remain responsible for provider approval, retention policy, regional processing, and sensitive-data controls.
- CSV exports neutralize formula-like reviewer text for safer spreadsheet opening, but exported files still need the recipient organization's document controls.
- No safety certification, compliance determination, probabilistic failure estimate, or tool qualification is provided.

## Development

Install the development tools and run the same core checks as CI:

```powershell
python -m pip install -e ".[dev,signing]"
python -m compileall -q src
python -m ruff check src tests
python -m pytest -q
python -m build
```

Project policies and maintenance references:

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release checklist](docs/RELEASE.md)
- [Changelog](CHANGELOG.md)
- [Requirements traceability](docs/REQUIREMENTS_TRACEABILITY.md)

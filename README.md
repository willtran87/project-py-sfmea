# PySFMEA

[![CI](https://github.com/willtran87/project-py-sfmea/actions/workflows/ci.yml/badge.svg)](https://github.com/willtran87/project-py-sfmea/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

PySFMEA scans a Python repository and creates a local, reviewable Software Failure Modes and Effects Analysis starter. It inventories functions and methods, recognizes risk-relevant code signals, proposes software-specific failure modes, and opens a browser workspace for engineering review.

It is designed to help begin and maintain an SFMEA. It does not claim that static analysis can determine system consequences or replace a cross-functional review.

## Documentation map

- [Quick start and end-to-end workflow](#quick-start)
- [Methodology and assurance boundaries](docs/METHODOLOGY.md)
- [Canonical diagram model](docs/DIAGRAMS.md)
- [Public interchange schemas](docs/SCHEMAS.md)
- [Organizational guidance packs](docs/GUIDANCE_PACKS.md)
- [Requirements traceability](docs/REQUIREMENTS_TRACEABILITY.md)
- [NASA/FAA guidance coverage audit](docs/GAP_AUDIT.md)
- [Contributing](CONTRIBUTING.md), [security](SECURITY.md), and the
  [release checklist](docs/RELEASE.md)

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
- SFMEA linkage and review-coverage reports with reconciled repository artifact accounting
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
sfmea publication-catalog
sfmea publication-catalog --json
sfmea publication-catalog --output publication-catalog.json
sfmea publication-catalog --output publication-catalog.json --json
sfmea publication-catalog --verify publication-catalog.json
sfmea publication-catalog --verify publication-catalog.json --json
```

The catalog publishes deterministic SHA-256 identifiers for self-contained JSON Schema
Draft 2020-12 documents. See [docs/SCHEMAS.md](docs/SCHEMAS.md) for compatibility and
semantic-validation boundaries.
The focused publication catalog provides human and schema-validated JSON discovery for package
failure codes, valid phases, stable findings, and remediation actions.
`--output FILE` publishes deterministic UTF-8 JSON through a verified temporary sibling and atomic
replacement. Existing files are protected; `--force` refreshes only a recognized catalog and
will not replace unrelated, malformed, non-file, or symbolic-link content.
Add `--json` to receive the schema-backed verification verdict for the exact exported file instead
of human progress text. Forced refresh requires the existing file to have the supported format,
integrity metadata, and complete structural envelope; the format string alone is insufficient.
`--verify FILE` performs bounded regular-file, UTF-8 JSON, structure, digest, and exact-taxonomy
verification. JSON mode emits the public catalog-verification verdict and returns nonzero when the
received catalog is unavailable, malformed, drifted, or not the catalog shipped by that verifier.

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

Project configuration is consumed as an identity-revalidated regular non-symbolic-link UTF-8 TOML
file under a 5 MB byte limit. Relative coverage and organizational guidance paths are normalized against the
configuration directory without resolving their final entry, preserving link identity for each
downstream safety check. `sfmea init` publishes templates atomically, refuses linked/non-file
destinations, and preserves prior content if forced replacement cannot complete.

Repository scanning does not import or execute Python code. Each Python source or test-evidence
file must be a regular non-link file and is captured through a 20 MB exact-byte boundary whose
inspected, opened, and final identities agree before PEP 263 decoding. Each selected source is read
once; AST parsing, included-test indexing, and baseline hashing reuse the same immutable bytes.
Eligible test-reference evidence is likewise read once before baseline construction and reused for
reference attribution and inventory hashing; configured/default/hidden exclusions apply equally.
Source discovery stops explicitly at 100,000 selected files; the optional textual test-reference
index stops at 10,000 files or 100 MB. The baseline records accepted/rejected source counts, total
accepted bytes, and separate canonical source/test-evidence snapshot-set SHA-256 values that are
also bound into the immutable run manifest. Rejected files remain visible through
repository-inventory state and stable warnings while other files continue through analysis.

Dependency evidence is also treated as untrusted repository input. PySFMEA reads pyproject,
requirements/constraints include chains, and supported lockfiles once through an exact-byte
regular non-link boundary whose inspected, opened, and final identities must agree: 20 MB per file,
1,000 attempted files, and 100 MB total. Requirement text must be UTF-8, include paths must remain
inside the repository, and supported pyproject dependency containers must have their declared TOML
shapes. Each manifest record exposes its accepted byte count and SHA-256, and parsed claims reuse
that same snapshot. Lockfile formats without an explicit parser remain content-addressed evidence;
PySFMEA does not infer package claims from unfamiliar syntax. The complete dependency inventory is
bound into the baseline and immutable run manifest; rejected content produces stable warnings.

The complete repository inventory reuses the exact accepted Python analysis, test-evidence,
dependency-manifest, interface-contract, and in-repository coverage snapshots and hashes every other regular non-linked artifact through an
inspected/opened/final identity-stable boundary
with a separate 20 MB per-artifact and 500 MB aggregate consumption budget. Each entry identifies
its snapshot source; non-regular filesystem objects are never opened. If the aggregate budget is
exhausted, metadata and already-authorized semantic analysis continue, but the inventory records a
digest-protected unresolved region and is explicitly marked truncated. File and
excluded/opaque-region traversal are each capped at 100,000 records.
The inventory's `snapshot_source` values and summary accounting are defined in
[Repository snapshot provenance](docs/METHODOLOGY.md#repository-snapshot-provenance).

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

Governed analysis JSON is consumed from a regular non-symbolic-link file through a 100 MB
byte limit with inspected/opened/final identity checks. Parsing requires duplicate-free,
finite UTF-8 JSON and applies the same iterative 100-level/2,000,000-node contract used by
package verification before migrations or derived-state work. Saves serialize through the
same byte limit, retain final-path identity, revalidate the destination immediately before
atomic replacement, preserve prior content on rejection, and remove private staging residue.
The browser reviewer's revision fingerprint uses the same bounded streaming file contract.

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
sfmea package C:\path\to\python-repo\sfmea-analysis.json -o review-package.zip --json
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
sfmea report sfmea-analysis.json `
  -o .artifacts\sfmea-report.html `
  --json
```

Engineering notes must be a regular, non-symbolic-link UTF-8 file. PySFMEA applies the
two-megabyte limit to bytes consumed from the open stream and canonicalizes CRLF/CR to LF after
decoding. Missing, linked, malformed, or oversized notes fail before publication; JSON mode emits
a sanitized generation rejection and preserves any previous report. PDF generation inherits the
same notes boundary through the self-contained HTML renderer. Browser output is consumed through
a 250 MB regular-file boundary, copied into a flushed and independently verified private sibling,
and atomically published only if the final destination is still the same regular file (or remains
absent). Linked destinations, renderer identity changes, concurrent replacements, and failed
publication preserve the previous report and remove staging residue.

With `--json`, report generation writes a private sibling, verifies whole-document and
embedded-payload integrity against the exact loaded analysis, and atomically publishes only after
that verdict passes. The public receipt identifies `published/complete` or the precise
`not_published` phase and records whether a pre-existing destination was preserved. Missing input,
generation, verification, and publication failures remain sanitized, schema-valid JSON on stdout
with a nonzero status, so CI does not need a fragile generation-then-verification sequence. The
analysis JSON itself is never accepted as the HTML destination. Existing destination directories,
symbolic links, and other non-regular objects are rejected before generation; PySFMEA never
resolves an output link and overwrites its target.

The same bounded publication contract now covers standalone CSV, Markdown, JSON, SARIF,
CycloneDX, SFTA, architecture, sequence, traceability, coverage, audit, guidance, diagram-bundle,
assurance-register/work-queue, individual JSON Schema, publication-catalog, and HTML outputs. Each
complete encoded artifact is limited to 256 MiB (or the artifact's stricter public limit), written to a private
sibling, flushed and synchronized, and published only if the inspected destination remains
unchanged. A rejected link, concurrent edit, short/failed write, or replacement failure preserves
the prior file and removes staging residue. Catalog refresh retains the destination state inspected
before envelope validation, so a newly appeared or concurrently edited file is never treated as an
approved replacement target.

Verify the complete standalone document and optionally require an exact analysis match:

```powershell
sfmea report-verify .artifacts\sfmea-report.html `
  --analysis sfmea-analysis.json
sfmea report-verify .artifacts\sfmea-report.html `
  --analysis sfmea-analysis.json `
  --json
```

Current report, diagram-bundle, and assurance-work-queue JSON verification verdicts include the
exact PySFMEA verifier name and package version. Persist this field with CI evidence so a later
review can distinguish the artifact's producer from the implementation that performed the
verification. The public v1 schemas keep this additive field optional only so genuine older
receipts remain readable.

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
Custom diagram inputs use the same exact-byte, inspected/opened/final identity-stable boundary as
standalone diagram verification. Each regular non-link file is limited to 5 MB and strict
duplicate-free finite UTF-8 JSON under 100-level/250,000-node structure limits. One report accepts
at most 50 files and 25 MB in aggregate, in addition to the canonical 50-diagram limits. Every
imported model records the exact source byte count and SHA-256; those provenance fields are covered
by the report's integrity binding. This does not authenticate the diagram author or validate its
engineering claims.

To add an organization-controlled or licensed standard without modifying PySFMEA,
configure a governed JSON guidance pack. The schema, integrity behavior, licensing
boundary, and complete example are documented in
[Organizational guidance packs](docs/GUIDANCE_PACKS.md).
Configured packs must be regular, non-symbolic-link UTF-8 JSON files. Their five-megabyte limit is
enforced on bytes consumed from one inspected/opened/final identity-stable stream. Strict decoding
rejects duplicate keys, non-finite literals, numeric overflow, malformed UTF-8, and structures over
100 levels or 250,000 nodes. Provenance hashes those exact validated bytes before any source,
locator, applicability profile, or rule mapping can influence findings.

The implementation-to-acceptance audit is maintained in
[Workbench requirements traceability](docs/REQUIREMENTS_TRACEABILITY.md); it identifies
the executable evidence for each capability and keeps the remaining authority boundary
explicit.

`sfmea package` creates a complete review directory containing the governed analysis
snapshot, resolved context, repository coverage, adapter-run provenance, CSV and
Markdown worksheets, inventory, architecture, traceability,
coverage, validation, summary, audit history, the exact offline public-schema catalog,
fourteen self-contained assurance, diagram, workflow, package, catalog, signature, and verifier
schema documents, a standalone `assurance-work.json` hardening queue,
and a SHA-256 manifest. A non-empty destination is protected unless `--force` is supplied.
The manifest explicitly declares `analysis_diagnostics_projection_v1`,
`assurance_register_projection`, `assurance_work_queue_projection`,
`evidence_catalog_projection_v1`, `guidance_traceability_projection_v1`,
`interchange_artifacts_projection_v1`, `package_provenance_projection_v1`,
`review_views_projection_v1`, and
`sfta_projection_v1` capabilities so offline
consumers can discover these contracts without
guessing from filenames or tool versions.
The exporter first deep-copies the requested analysis and materializes deterministic assurance
and SFTA derived state on that private copy. `analysis.json`, its state digest, and every report
projection therefore share one frozen snapshot even when the input omitted or malformed a
derived assurance container; the caller's governed analysis remains unchanged.
Packages are generated in a staging directory and published only after every report and
checksum succeeds and the independent semantic package verifier accepts the complete staged
artifact set. A rejected generation reports bounded verifier rule IDs, removes its staging
content, and leaves any existing destination unchanged. `--force` refreshes recognized package files but refuses a
directory containing unrecognized files, protecting reviewer-added material.
`--json` suppresses human progress text and emits the same schema-backed
`pysfmea-review-package-verification-1` verdict as `verify-package --json` after publication.
This gives CI a single machine-readable receipt with the resolved path, container, artifact
count, capabilities, state binding, and every nested projection check; an invalid receipt returns
a nonzero exit status. Pre-publication failures use the same public schema with stable
`package.publication.*` rule IDs, zero checked files, and the requested output identity, so JSON-mode
automation never needs to fall back to parsing stderr. Expected operational details are bounded;
unexpected runtime details are sanitized. Every verdict identifies the `PySFMEA` verifier and
exact tool version. Pre-publication findings use stable categories for missing, unreadable, or
invalid analysis input; unavailable destinations; rejected generation; and internal failures.
Their messages never echo raw exception text, preventing machine-local paths or sensitive runtime
details from leaking into CI logs while preserving phase and remediation semantics.
Not-published receipts expose the primary category directly as `publication.failure_code`. The
schema restricts each code to its valid phase and requires a matching error finding; published
receipts cannot carry a failure code. Automation can therefore switch on one bounded field while
retaining the richer finding for human review.
Each failed receipt also carries `publication.failure_rule_id` and
`publication.catalog_format`. `publication.catalog_sha256` content-addresses the exact catalog
used by the producer. These fields bind a stored result directly to its canonical
`package.publication.*` rule and `pysfmea-publication-failure-catalog-1` taxonomy without requiring
the consumer to infer either value from the failure code or search the findings array.
The digest equals SHA-256 of the catalog's canonical UTF-8 JSON after removing
`content_sha256`: keys sorted, no insignificant whitespace, and non-ASCII text retained. The
human and JSON catalog commands expose the same digest for offline comparison.
The catalog declares these rules programmatically as `algorithm: sha256` and
`canonicalization: json-sort-keys-compact-utf8`; failed receipts repeat them as
`catalog_algorithm` and `catalog_canonicalization`. Both declarations are included in the hashed
catalog content, preventing a digest from being detached from its interpretation method.
Each failure also provides `publication.next_action`, such as `provide_analysis`,
`repair_analysis`, or `choose_writable_destination`. Failure code, phase, action, rule ID, and
path-safe message come from one immutable catalog used by both runtime classification and public
schema generation, preventing producer/contract drift.
`publication.retry_policy` is `after_remediation` for input, destination, and rejected-generation
failures, and `manual_diagnostics` for internal failures. Neither value authorizes an automatic
retry: consumers must complete the named action or diagnostic review before invoking publication
again. Published receipts cannot carry retry metadata.
Catalog format, algorithm, canonicalization, and digest, plus rule identity, failure code, phase,
action, and retry policy, are one schema-bound tuple; altering any member independently makes the
receipt invalid.
Package receipts also carry a schema-defined `publication` state. `published/complete` identifies
a successful handoff, `not_published/analysis_load` and `not_published/generation` are safe retry
states, and `published/post_publication_verification` tells automation that an artifact became
visible but failed the final receipt check and must not be handed off.
The public schema enforces these combinations across `valid`, `checked_files`, status, and phase:
a producer cannot issue a schema-valid receipt that simultaneously claims success and
non-publication, completion and failure, or checked files for an output that was never published.
The same contract also requires valid package verdicts to report at least one checked file and
zero errors, and invalid verdicts to report one or more errors. This prevents a consumer from
receiving a schema-valid success with no verification work or a rejection with no failure signal.
Every valid verdict carries `manifest_sha256`, a content address for the exact bounded manifest
bytes that were parsed and verified. Valid ZIP verdicts additionally require `archive_sha256`,
so a stored or transmitted receipt can be matched to both the package contents and its precise
container without trusting a path. Error and warning count presence is also reconciled with the
corresponding finding levels, preventing internally contradictory diagnostic envelopes.
`--portable` keeps repository-relative source evidence while removing machine-local
absolute repository, configuration, coverage, trace, and source-analysis paths from
the packaged snapshot. The governed working analysis is not modified.

`sfmea verify-package` independently checks the package format, complete artifact
set, path safety, regular-file boundaries, byte sizes, SHA-256 checksums, baseline,
analysis schema, generator provenance, schema-catalog completeness, schema identities,
canonical schema digests, and the manifest/verdict contract boundary. Before hashing or
regenerating projections, it iteratively bounds `analysis.json` to 100 levels and 2,000,000
JSON nodes, validates projection-critical container types, and reports all three checks in the
`analysis_structure` verdict. Malformed core objects and collections are withheld from every
semantic projector; parser recursion, complexity, and core-contract failures become stable
invalid-package findings rather than uncaught exceptions. This gate protects verifier
availability and does not claim complete analysis-schema validation. A final sanitized exception
boundary returns `package.semantic_verification_aborted` if an unforeseen semantic projector
failure escapes these checks; internal exception text is not included in the verdict. It also verifies the
work queue's own digest and recomputes its exact projection from packaged `analysis.json`, so
rewriting the queue and updating the manifest checksum is still rejected. The verifier also
regenerates the full `assurance-register.json`, verifies its embedded queue,
and requires that embedded and standalone queues agree exactly. It also regenerates the
summary, validation findings, resolved system context, repository inventory, and adapter-run
ledger from packaged analysis. A changed diagnostic artifact remains invalid even if its
manifest checksum is recomputed; the validation generation timestamp is treated as provenance
while counts and findings match exactly. The full guidance trace and standalone citation catalog
are also regenerated and required to agree, so citation evidence cannot be silently rewritten
behind updated checksums. The top-down SFTA model and flat reconciliation-gap register are
regenerated together and their counts reconciled, protecting the SFMEA/SFTA handoff from the same
class of checksum rewrite. The execution-evidence catalog is reconciled to the packaged baseline,
execution records, and evidence-artifact inventory, preventing package metadata from overstating
recorded verification evidence. SARIF findings and the CycloneDX declared-component inventory
are regenerated from the same packaged analysis and required to share its baseline identity;
rewriting either interchange view behind updated checksums is rejected.
The ten reviewer-facing worksheet, system-view, audit, guidance, and assurance exports are also
regenerated from one isolated analysis snapshot and compared as canonical UTF-8 text, preventing a human-readable
conclusion from drifting away from the governed analysis behind a refreshed checksum while
remaining portable across LF/CRLF platforms. The package-time audit manifest and reviewer README
are regenerated as a separate provenance projection with explicit timestamp and baseline checks.
The outer manifest still checks every transferred byte exactly. Producer version is
verified as provenance but excluded from semantic queue matching. Exact SARIF and CycloneDX
reconciliation also uses the package's declared producer version, so compatible historical
artifacts remain valid across verifier upgrades. JSON verdicts carry a dedicated
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

`--zip` atomically publishes the same complete package as a single ZIP file. An explicit
case-insensitive `.zip` output suffix also selects archive publication, so
`sfmea package analysis.json -o review-package.zip` is sufficient and cannot silently create
a directory that merely looks like an archive. The
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
Private/public keys and detached envelopes must be regular non-symbolic-link files and
are consumed under one-megabyte byte limits with inspected/opened/final identity checks.
Detached envelopes are strict duplicate-free finite UTF-8 JSON bounded to 20 levels and
10,000 nodes; ambiguous keys, non-finite literals, numeric overflow, and structure exhaustion
fail before cryptographic verification. The verified package manifest is independently reread
under a 10 MB/100-level/250,000-node strict boundary and must retain the exact digest established
by a fresh package verification; caller-supplied or stale verification results cannot bypass this
step. Signature publication is atomic and
refuses a destination whose identity changes before replacement. Exact ZIP-container
bytes are rehashed through a 550 MB streaming boundary and reconciled to the fresh verdict.
Use your approved key-generation, storage, rotation, revocation, and release process.
This proves possession of the matching private key, not that the signer was authorized
or that the SFMEA was technically approved.

The `detached-signature` public schema defines the complete envelope and can be exported with
`sfmea schema detached-signature`. Structural validity does not replace cryptographic
verification against the exact package and a separately trusted public key.

For offline CI integrations, `sfmea schema --bundle DIRECTORY` atomically exports the catalog
and every contract in one operation. `sfmea schema --verify-bundle DIRECTORY` independently
checks the complete known profile, root-level regular-file boundary, JSON structure, identities,
and catalog digests. Every allowed entry is read once with a two-megabyte consumption-time bound
and strict UTF-8 JSON decoding; inspected, opened, and final identities must match. Duplicate
keys, non-finite numbers, excessive depth or node count, malformed encoding, oversized content,
and linked/non-file entries remain structured rejections before canonical hashing. The
publication-catalog verifier uses the same boundary with its stricter one-megabyte and catalog
structure limits. Use
`--json` for the stable machine verdict. Refreshing a non-empty bundle
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
Coverage JSON is treated as untrusted evidence input: PySFMEA reads at most 100 MB, refuses
symbolic links and non-files, requires the inspected/opened/final file identity to remain stable,
and strictly validates duplicate-free finite UTF-8 JSON under 100-level and 2,000,000-node limits.
At most 100,000 file records are traversed and file paths are bounded to 4,096 characters. Paths
outside the analyzed repository and parent traversal are ignored; only typed positive line/source
coordinates and nonzero branch destinations are accepted. Unsafe paths, malformed records, and
duplicate normalized file keys are omitted and reported as stable `CoverageError` warnings; they
do not abort the rest of the repository scan. The accepted snapshot's exact byte count, SHA-256,
supplied file count, and accepted file count are retained in scan settings, and its digest is bound
into the immutable run manifest.

## Interface contracts

OpenAPI/Swagger JSON or YAML, `*.schema.json`, and protobuf files are discovered
automatically. Each file becomes a stable interface-contract component with extracted
operations and data types, a content hash, and a contract-compatibility failure-mode
prompt. Contract changes participate in the repository baseline and therefore trigger
normal review revalidation. Contract bytes are captured from one bounded regular non-link
snapshot whose inspected, opened, and final identities must agree. JSON contracts additionally
reject duplicate keys and non-finite or overflowed numbers and enforce 100-level/1,000,000-node
structure limits. Malformed contracts remain visible with an exact byte count and SHA-256 but
cannot contribute parsed operation or data-type claims; the inventory is bound into the immutable
run manifest. The built-in YAML extraction is intentionally conservative;
generated, templated, or externally hosted specifications should be supplied as local
artifacts or represented through configured system interfaces.

Contracts use the normal `path:qualified-name` mapping syntax. For example,
`openapi.json:Interface contract *` can allocate an API contract to a subsystem,
requirements, hazards, and configured system interfaces. Those mappings seed the
contract worksheet and participate in context-change revalidation.

Contract files are consumed as untrusted evidence through a regular-file, non-symbolic-link
boundary: 20 MB per file, 1,000 discovered files, and 100 MB total. Paths must remain inside the
repository and text must be UTF-8. JSON roots and nested extraction containers are type-checked;
malformed structure is reported without aborting the scan. Operation and data-type extraction is
limited during traversal to 500 distinct values per category, and the exact accepted bytes remain
represented by their SHA-256 even when semantic extraction is rejected or truncated.

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

Trace ingestion requires a regular non-symbolic-link file, applies the 100 MB limit to bytes
consumed from an inspected/opened/final identity-stable stream, and strictly decodes duplicate-free
finite UTF-8 JSON with an object or array root. The decoded document is capped at 100 levels and
2,000,000 nodes before traversal. The simple/OTLP walker is iterative and type-safe, caps each
import at 50,000 spans, and limits nested
attribute normalization to 32 levels. Empty, malformed, linked, oversized, or excessively nested
inputs leave the analysis unchanged. Runtime spans, edges, import provenance, history, and summary
are committed together; an unexpected finalization failure restores the complete prior analysis.

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
Provider requests are capped at 3 MB and responses at 10 MB; nested JSON is strict, bounded by
depth and node count, and must match the exact discovery or summary field set. Generated text,
lists, identities, and per-component suggestion counts also have explicit limits. Discovery stages
every requested component before committing, and acceptance rolls back completely if worksheet
materialization fails. Proposed suggestions become stale after a baseline change.

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
to execute tests. Queue verification uses a strict 100 MiB, 100-level, 1,000,000-node JSON
boundary with regular non-link and inspected/opened/final identity reconciliation. Duplicate
keys, non-finite literals, numeric overflow, malformed UTF-8, and concurrent replacement are
rejected before integrity or projection checks.

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
The operation carries forward the exact bounded manifest snapshot it verified, rechecks the
queue immediately before replacement, and requires the manifest identity to remain unchanged.
A concurrent but independently valid queue replacement is refused, the current queue is
preserved, and staged output is removed.
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
Archive performs the same publication-boundary identity comparison before writing its retirement
record, so concurrent queue replacement leaves both the active source and retirement state
untouched.

Verification distinguishes an invalid manifest, materially changed verification contracts,
and an analysis whose unrelated state advanced while every selected contract remained
current. It replays the saved selection and emits an obligation-level diff for added,
removed, and changed contracts, including the exact fields responsible. Placeholder edits
are reported as informational because test implementation is expected; they become governed
when registered against an obligation. Verification consumes the manifest and optional
retirement record through a 64 MiB byte boundary and streams generated-file hashes through
an independent 64 MiB boundary. Manifest and retirement inputs must be regular,
non-symbolic-link files whose inspected, opened, and final identities agree. Strict decoding
rejects duplicate keys, non-finite literals, numeric overflow, malformed UTF-8, structures beyond
100 levels or 500,000 nodes, concurrent replacement, growth beyond a boundary, and broken
retirement links as structured verification findings. Generated files are never
followed through links: an unavailable, linked, or oversized placeholder is reported separately
as changed and cannot pass the untouched-file precondition for guarded refresh or archival.

The generated pytest cases fail intentionally until an engineer implements the recorded
stimulus, oracles, and acceptance criteria. Empty, skipped, or assertion-free tests cannot
silently satisfy the checklist. The scaffold, a named test, coverage, or a passing result is
not evidence by itself. Verification and closure require current execution artifacts,
proof that the failure was triggered, acceptance-criterion evaluation, independent review,
and any required approval. `assurance-review` can govern planning states but cannot directly
set `verified`, `accepted_risk`, or `closed`.

The emitted pytest module remains self-contained, but collection does not trust its adjacent
manifest blindly. It requires a regular non-symbolic-link file, consumes at most 64 MiB from the
opened binary stream, strictly decodes duplicate-free finite UTF-8 JSON, iteratively enforces the
same 100-level/500,000-node structure limit, checks the object/format/integrity envelope, and
requires a usable obligation list before parameterization. Unsafe or ambiguous manifests stop
collection with a bounded remediation message rather than being followed or buffered without limit.

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
is idempotent and rejects traversal, symbolic links, non-files, malformed or ambiguous UTF-8 JSON,
duplicate keys, non-finite values or numeric overflow, structures beyond 100 levels or 100,000
nodes, excessive manifest bytes, per-artifact bytes, and aggregate evidence bytes. The manifest's
inspected, opened, and final file identities must agree, and limits are enforced while bytes are
consumed rather than from a pre-read size observation. Every artifact is first streamed into a
bounded hash and then copied through an independently bounded hashing stream; a source that changes
between validation and copy is refused and private staging is removed. Imported test registration
and evidence recording occur only after successful publication. A recording failure restores the
complete prior analysis and removes the new evidence directory. Accepted imports remain labeled
`externally_supplied_unattested`, allowing an organization to apply its own CI attestation policy
without PySFMEA silently treating the import as trusted.

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

The review verifies the execution statement and every artifact again through the same regular-file,
link-safe, consumption-time byte boundaries. `sufficient` is
rejected unless the run passed, the intended stimulus was observed, all criteria pass, the
baseline is current, all hashes are intact, and the reviewer is independent. Verification
still does not close the finding or accept residual risk.

## Top-down Software Fault Trees

SFMEA is reconciled with user-defined top-down Software Fault Trees. Add one or more
`[[fault_trees]]` entries to `sfmea.toml`; each tree identifies its hazard and top event,
explicit events, and AND, OR, VOTE, or INHIBIT gates. Events can correlate to findings by
stable finding ID, `path:qualified-name` component glob, and failure-mode text glob. The
selector relationship is explicit IDs **or** configured glob matches; when both component and
failure-mode globs are present, a finding must satisfy both glob dimensions. Unknown explicit
IDs remain unmatched and surface through the top-down reconciliation gap rather than widening
the match. The
configuration validator rejects duplicate IDs, unknown inputs, invalid voting thresholds,
unknown hazards, unsupported node types, and logical cycles.
Package verification replays the selector semantics declared by the producing version for SFTA
artifacts, validation findings, and validation-bearing CSV/Markdown worksheets, so a genuine
older package remains verifiable while newly generated models use exact ID matching.

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

Golden corpora use the closed `pysfmea-golden-corpus-1` contract. The CLI consumes at most 20 MB
from a stable regular, non-symbolic-link file; strict UTF-8 JSON rejects duplicate keys,
non-finite numbers, unsupported fields, and excessive depth or node count. Case, scope-pattern,
field-length, and active-candidate ceilings keep evaluation bounded. Results identify
`pysfmea-evaluation-result-1`, the exact verifier version, and a canonical corpus SHA-256 digest,
so retained release evidence can distinguish a scanner change from a changed golden baseline.

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

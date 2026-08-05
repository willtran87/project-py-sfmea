# PySFMEA methodology

## Purpose and boundary

PySFMEA automates repository decomposition, evidence gathering, candidate generation, persistence, and reporting. It does not automate acceptance of failure modes, consequence analysis, risk acceptance, or approval.

## Governed analysis persistence

The analysis JSON is the editable source of truth. Loading consumes at most 100 MB from a
regular non-symbolic-link file and reconciles its inspected, opened, and final identity plus
size/change metadata. Strict UTF-8 JSON rejects duplicate object keys and non-finite numbers;
an iterative 100-level/2,000,000-node check runs before schema migration or derived-state
materialization. Package verification uses the same shared structure metric.

Saving applies the structure limit before bounded UTF-8 serialization, preserves the final
destination path instead of resolving through it, and compares the original destination
identity/change metadata immediately before atomic replacement. Revision-conditioned saves
add a bounded identity-stable streaming digest. Rejected output, concurrent replacement, and
filesystem failure preserve the prior governed file and remove the private sibling stage.
No-op timestamp reconciliation and browser-review ETags use the same bounded input contract.

## Guidance traceability and citations

PySFMEA carries a versioned, hashed guidance catalog in every newly saved analysis. The
catalog separates documents, exact locators, and curated rule mappings. Scanner candidates
inherit typed links such as `failure_taxonomy`, `process_expectation`,
`hazard_traceability`, and `methodology_basis`; relationships also record mapping strength
and applicability. The FAA 2006 software-safety guide is explicitly marked
`legacy_methodological`, while NASA procedural and assurance requirements are marked
`nasa_program_or_contract`.

The mapping chain is document → section/page locator → scanner rule → candidate finding.
`sfmea citations` exports it as normalized JSON or flat CSV, review packages include the
catalog and both traceability formats, and the standalone report exposes source status,
locators, usage counts, affected findings, and a bounded guidance-traceability diagram.
Unknown citation IDs, relationship types, strengths, and applicability values are validation
errors. Catalog hash drift is reported.

Mappings are curated and deterministic. They explain why a rule is relevant to an SFMEA
review; they are not declarations of a defect, a standards violation, regulatory
applicability, or compliance. Machine discovery receives the same closed catalog and may
propose only supplied citation IDs. Those links remain proposals until the suggestion is
accepted by a named reviewer, after which they are recorded as `reviewer_accepted` rather
than being represented as curated mappings.

Local organizational packs use the same relationship model without copying licensed
documents. A strict pack records an `org.*` applicability profile; controlled source
title, revision, scope, access, official-source reference, and quote policy; exact
locator summaries; and typed rule mappings. Pack bytes, source records, merged catalog,
and selection are hashed. Organizational profiles are explicit and automatically active
when configured, but the pack cannot assert compliance. See `GUIDANCE_PACKS.md`.

This boundary follows the central limitation in the public guidance: SFMEA depends on system knowledge, documentation, assumptions, and review by people with different perspectives. Source code can show that a function calls a remote service; it cannot determine whether the end effect of that service returning stale data is an inconvenience, financial loss, environmental release, or loss of life. The project configuration therefore records purpose, boundary, operating context, interfaces, assumptions, hazards, critical functions, and the project's risk policy alongside the scan.

The resolved system-context manifest extends that record to mission, operational modes,
system states, must-work and prohibited functions, safe and degraded states, human
interactions, timing and resource constraints, deployment environments, criticality,
and explicit exclusions. It records field-level provenance, completeness, limitations,
and unresolved questions. Missing context does not stop deterministic discovery, but it
remains visible and constrains claims about effect, hazard, safe-state, and residual-risk
coverage.

## Workflow and handoff gates

`sfmea status` is a read-only lifecycle view. Its `stage` identifies the primary next phase,
but does not imply that only one issue can block delivery. The accompanying handoff checklist
evaluates eight independent conditions: repository readiness, analysis availability, zero
validation errors, complete finding review, cleared revalidation, complete accepted-finding
assurance planning, a current integrity-valid HTML report, and a current integrity-valid
review package exactly bound to the governed analysis.

Overall handoff readiness is derived from the checklist: every required gate must pass. Each
gate records a stable ID, status, explanatory detail, supporting counts or binding evidence,
and the ID of an ordered remediation action. This makes the human display useful as an
engineering checklist and the JSON result suitable for CI policy. Passing these tool gates
means the declared work products are internally consistent and complete under configured
rules; it is not engineering approval, risk acceptance, or certification evidence.

Accepted findings also receive a derived assurance work-queue state. The projection evaluates
obligation cardinality, unresolved definition gaps, attributed plan review, implementation
binding, the latest recorded execution, evidence status/review, and terminal assurance state in
that order. It distinguishes work that is eligible for test implementation or controlled
execution from work that first requires engineering definition, review, or remediation. The
projection is reproducible and export-only: it does not modify the governed obligation, approve
execution, infer evidence sufficiency, or close a finding.

## Analysis structure

The default implementation-level elements are public and private functions, methods, constructors, selected lifecycle methods, nested functions, closures, named lambdas, declarative data models, and executable module initialization. The inventory also contains the declared dependency environment, project-defined common causes, and local OpenAPI, Swagger, JSON Schema, and protobuf interface contracts. Dependency evidence includes parsed declarations, recursively included requirement files, and hashes of common lock/build manifests. Contract evidence includes extracted operations/data types and a content hash. Tests are evidence sources but are not analyzed as production components unless explicitly included.

Each component receives a stable ID derived from its relative path, qualified name, and kind. Each scanner candidate receives a stable ID derived from its component and rule. An unambiguous rename or move is matched through an identity-independent content fingerprint; predecessor IDs and review history are retained and revalidation is required. Ambiguous matches remain new/removed rather than guessing.

Every new analysis records the generator name, PySFMEA version, and analysis schema
version. Older migrated records whose original generator predates this provenance
retain `unknown` rather than being falsely attributed to the version that loaded them.

Repository discovery separately accounts for analyzed, indexed, excluded, unresolved,
and opaque artifacts and regions. Recognized documentation, CI, deployment, dependency,
schema, migration, result, and configuration inputs are hashed and typed even when no
semantic analyzer consumes them. Binary, unclassified, oversized, unreadable, and
symlinked material is never silently represented as analyzed. This inventory is bounded,
does not follow directory links, and does not execute repository code.

Each normalized finding records every specialized analyzer that contributed to it. A
separate adapter-run ledger binds adapter capability/version/trust/isolation metadata to
the run input digest, output digest, status, and exact contribution entity IDs. A
completed adapter with no results, an unconfigured evidence provider, and an optional
capability that was not invoked remain distinct states.

## Failure vocabulary mapping

The scanner maps observable source characteristics onto prompts drawn from NASA and FAA categories:

| Guidance concept | PySFMEA rule examples |
|---|---|
| Function fails or performs incompletely | `functional.omission`, `functional.incorrect` |
| Missing, wrong, out-of-range, overwritten, stale, or out-of-sequence data | `data.invalid_input`, `interface.bad_response`, `data.serialization` |
| Halt or omitted event | `functional.omission`, `interface.unavailable` |
| Incorrect event or logic | `functional.incorrect` |
| Wrong timing or sequence | `timing.late_or_early`, `timing.order_or_race` |
| Interface failure | `interface.unavailable`, `interface.bad_response` |
| Illegal or incorrect command | `process.uncontrolled_failure`, `configuration.missing_or_wrong` |
| Failure not detected or unsafe response | `detection.masked_failure` |
| Resource or execution abnormality | `resource.exhaustion` |
| Calculation, precision, range, or convergence fault | `calculation.precision_or_range` |
| Wrong condition, branch, sequence, or state transition | `logic.condition_or_sequence`, `state.invalid_transition` |
| Internal software contract failure | `interface.internal_contract` |
| External schema/API version incompatibility | `interface.contract_compatibility` |
| Runtime, dependency, or toolchain incompatibility | `environment.runtime_incompatibility`, `environment.dependency_drift` |
| Hardware off-nominal response | `hardware.abnormal_response` |
| Shared/dependent failure | project-defined `common_cause.*` |
| Circuit-breaker containment, recovery, isolation, or fallback failure | `resilience.circuit_breaker_containment`, `resilience.circuit_breaker_recovery`, `resilience.circuit_breaker_isolation`, `resilience.circuit_breaker_fallback` |

The rules intentionally state failure at the functional boundary. A coding defect such as an incorrect comparison is normally a cause; “returns an incorrect authorization decision” is the failure mode; unauthorized access or denial of legitimate access are effects.

## Evidence and confidence

Scanner evidence includes source location, AST signals, approximate internal callers and transitive upstream paths, complexity, decorators, textual test references, dependency declarations, and optional function-level line and branch evidence derived from coverage.py JSON. These are useful for triage and traceability. They are not proof that a failure exists or that a control is effective. Python's runtime dispatch means the caller evidence is deliberately conservative and incomplete.

Confidence describes how directly a rule was triggered by observable syntax. It is not likelihood or occurrence. The two baseline functional rules are generated systematically even when no specialized syntax is present.

Ordered call evidence and common framework decorators identify HTTP routes, background tasks, event handlers, and CLI commands. Framework recognition is metadata and a screening aid; it does not prove the runtime router, dependency injection graph, middleware order, or deployed configuration.

Circuit-breaker extraction recognizes bounded identifier, comparison, clock, lock,
state-mutation, isolation-key, and fallback evidence. It records a candidate control model
and generates dedicated containment, timed-recovery, isolation, and fallback failure modes.
For class-based implementations, method-local evidence is correlated through the containing
class scope so admission, failure accounting, reset, and timed recovery contribute to one
state diagram without moving findings away from their source callable. Naming alone does not
create a candidate; behavioral evidence is also required.
State diagrams distinguish states directly observed in AST evidence from conceptual states
needed to review a complete breaker lifecycle. Missing thresholds, cooldown expressions,
clock sources, recovery transitions, synchronization, isolation keys, and degraded contracts
are emitted as review gaps, not asserted defects. Assurance contracts are tailored by finding:
containment tests threshold/admission, recovery tests controlled time and probe concurrency,
isolation tests independent scopes, and fallback tests caller-visible degraded behavior.
The extracted model is never copied into reviewer-owned prevention or detection controls.
Fault-injection obligations require threshold-boundary call counts, controlled elapsed time,
concurrent HALF-OPEN probes, independent isolation keys, and caller-visible degraded behavior
before the breaker can be credited as effective containment.

Failure-cascade projection follows the scanner's bounded upstream call paths from the failed
component toward potential callers. It records the path and depth in the canonical diagram,
marks imported runtime corroboration separately, and inserts detected timing and containment
boundaries for breaker findings. A static or observed call relation establishes exposure, not
causal propagation; reviewed next-higher and end effects remain the authoritative consequence
fields.
To keep large analyses navigable, caller paths are emitted once per component and breaker
timing/containment nodes once per detected control scope. Failure modes remain separate nodes
with independent edges into the shared infrastructure. Projection metadata records embedded
and total findings, unique paths, runtime-observed links, and deduplicated record-path reuse.
The bounded record selector first takes the highest-priority finding for every component in
the global risk order, then fills remaining capacity with additional findings. This preserves
priority while maximizing component diversity. Finding and component coverage/truncation are
reported separately so the overview cannot be mistaken for a complete register.
The default projection bounds can be tailored at export time for HTML, PDF, and canonical JSON.
Each setting has a hard range and the combined finding/path/depth request is conservatively
estimated before graph construction against the canonical node ceiling. Configuration is
recorded with the output so a larger visual remains reproducible and a rejected combination
fails explicitly rather than producing a partial or unstable graph.
Caller-path discovery also carries its own machine-readable completeness record. It states the
scanner path and component-depth limits, emitted path count, path-limit truncation, and paths
that terminate at the discovery depth. The diagram then accounts separately for discovered
paths omitted by record projection, its per-component path limit, and path segments omitted by
its rendering depth. Report percentages therefore describe coverage of discovered paths, not
whole-program call-graph completeness. Any earlier scanner truncation remains a visible lower-
bound qualification.
The same bounded paths are copied into each deterministic verification obligation and flattened
into CSV exports with their completeness and limitation fields so test authors can select an
exercised path, instrument its caller boundaries, and retain the static-versus-observed and
bounded-inventory limitations with the checklist. An incomplete inventory becomes a planning
gap and requires compensating runtime, integration, or architectural evidence.

Imported simple or OpenTelemetry JSON spans add observed parent-child relations. Each import is hashed, baseline-linked, bounded, and audited. Static and observed relationships remain visibly distinct because one is approximate source evidence and the other is incomplete execution evidence.

Trace import is idempotent by source hash. Mapping prefers explicit `sfmea.component`
and code-function attributes, then unambiguous names, then code-file/function pairs.
Mapped and unmapped counts and mapping methods are retained so reviewers can assess
the strength of the runtime-to-source correlation.

## Machine-assisted discovery boundary

Machine discovery consumes bounded evidence packets rather than unrestricted repository content. Each packet assigns citation IDs to the component, existing candidates, requirements, hazards, interfaces, and runtime relations. Repository-derived strings are explicitly treated as untrusted data, not prompt instructions. Provider requests stop at 3 MB and responses at 10 MB; both network and programmatic providers pass a strict 50-level/100,000-node JSON boundary before response hashing or semantic use. Network envelopes and nested content reject duplicate keys, non-finite numbers, and malformed UTF-8 JSON.

Generated suggestions are stored separately from SFMEA worksheet items. The response schema is closed: unknown fields and severity, occurrence, detection, disposition, workflow status, approval, or closure fields are rejected. Suggestions have bounded text and list fields, stop at 25 per component packet, must cite supplied evidence IDs, may cite only supplied guidance IDs, and record uncertainties and questions. Unknown evidence or guidance IDs reject the provider response instead of being silently retained. Provider, model, prompt version, baseline, timestamp, response hash, and review history are retained. Duplicate failure-mode text for the same component is suppressed. All requested component responses validate before any suggestion/history/summary mutation is committed.

A reviewer may reject a suggestion or materialize it as a new unreviewed worksheet item. Materialization does not accept the failure mode into the governed analysis and never overwrites an existing item. Any failed materialization restores the complete pre-review analysis rather than leaving a partly accepted proposal or manual item. Generated summaries use the same bounded exact-field response contract and retain a response digest. Proposed suggestions and generated summaries are invalidated when the repository/configuration baseline changes.

## Failure Mode Assurance Matrix

The governed failure-mode register is connected to a separate Verification Obligation
Register. Every active finding receives a stable deterministic obligation containing a
failure stimulus, explicit local and system observations, acceptance criteria, a recommended
verification method, sandbox requirements, repeatability expectations, an automation command
contract, and required evidence artifacts. Existing textual test references remain candidate
links only; neither naming similarity nor coverage is treated as proof that the failure path
was exercised.

Verification planning is deliberately separate from implementation and evidence review.
Generated pytest scaffolds fail until meaningful tests are implemented and are labeled as
planning artifacts, not evidence. Planning review cannot directly set `verified`,
`accepted_risk`, or `closed`. Those states require current as-run evidence, proof that the
intended stimulus occurred, acceptance-criterion evaluation, independent sufficiency review,
and applicable approval. Rescans preserve planning decisions but reopen nontrivial obligations
and mark evidence stale when their source fingerprint changes.

Implemented tests may be run by the optional Docker/Podman harness only after explicit
execution approval. The harness requires a locally available image and uses a shell-free
command, disabled network and IPC, a read-only repository mount, an unprivileged user,
dropped capabilities, no-new-privileges, bounded compute/process/files/output/time, and no
credential forwarding. Execution statements bind the analyzed baseline, repository state,
test source hash, command, image identity, outcome, JUnit summary, logs, and artifact hashes.
The manifest itself has a canonical digest and is revalidated along with each artifact at
evidence review time.

CI or other external execution results may instead be imported through a bounded versioned
manifest. Artifact paths must remain under the manifest directory, symlinks are rejected,
claimed hashes are checked, and bytes are copied into the managed evidence store. Such
records are explicitly labeled externally supplied and unattested. Either collection path
sets only `evidence_collected`; a separate identity must record whether the intended failure
stimulus occurred and adjudicate every pre-existing acceptance criterion. A sufficient
decision can set `verified`, but it cannot close a finding or accept residual risk.

## Top-down SFTA and reconciliation

Project configuration may supply formal Software Fault Trees for configured hazards. Tree
inputs are typed events and explicit AND, OR, VOTE, or INHIBIT gates. PySFMEA validates node
identity, references, voting thresholds, and acyclic structure, then preserves that logic in
the canonical analysis and renderer-neutral diagrams. Finding selectors are explicit stable
IDs or glob patterns over component identity and failure-mode text. Exact IDs are unioned with
glob matches; component and failure-mode glob dimensions are conjunctive when both are supplied.
An unknown exact ID remains unmatched rather than broadening the event to unrelated findings.
ID-only events use indexed lookup, while package verification replays the historical matching
rule across SFTA, validation, and validation-bearing worksheet projections only for artifacts
that declare a producer older than the corrected selector contract.

No causal gate is inferred from a call graph or from the presence of linked SFMEA findings.
If a hazard has no supplied tree, the generated model contains one clearly labeled
undeveloped event. Reconciliation independently lists top-down events without correlated
findings, hazard-linked findings without an event, and hazard-link inconsistencies. These
are coverage prompts for qualified review, not proof that either analysis direction is
complete or that a linked event is a necessary or sufficient cause.

## Effects and scoring

The initial local effect is a prompt. Next-higher and end effects remain blank because they require architecture and operational context. Reviewers also record the applicable operational mode/state, required safe state, permitted degraded behavior, recovery behavior, and explicit residual-risk statement. When exactly one project-defined hazard is linked to a critical function, its human-authored end effect and severity may be copied into the starter with an explicit confirmation rationale. Reviewers may edit all FMEA language.

Severity may use a configured categorical scale or a numeric 1–10 scale. S/O/D fields are optional unless the project selects `sod_rpn`. Teams must define the meaning of occurrence for software. FAA guidance notes that SFMEA commonly emphasizes severity because software failures result from latent faults and activation conditions rather than hardware wear-out.

RPN is displayed only as arithmetic convenience. It is not used to accept risk or suppress high-severity items. Separate post-action values allow residual risk to be recorded after actions are actually implemented and verified; they do not overwrite the original assessment.

## Rescan behavior

Scanner-owned evidence refreshes during a rescan. Reviewer-owned fields and field-level audit events are preserved. Fingerprints cover callable behavior, module/class context, applicable SFMEA configuration, dependencies, and the overall source/configuration baseline. Materially reviewed items are marked for revalidation when these change, when an item moves, or when its source disappears. Clearing the flag records the current fingerprint and timestamp. Risk-bearing edits to a verified or closed record return it to review and invalidate prior approval.

The fingerprints are change detectors, not proofs of unchanged behavior: external services, runtime wiring, generated inputs, environment state, and dynamic dispatch may alter behavior without a statically visible change. Teams must also use their normal impact-analysis process.

## Project extensions

Critical-function and component-mapping entries use POSIX-style `path:qualified-name` globs. They link code to subsystems, requirements, hazards, and configured system interfaces. Custom rules and common-cause definitions add domain-specific failure prompts. The architecture export supplies a conservative functional block and propagation view; the inventory export records components, inputs, calls, requirements, hazards, interfaces, dependencies, assumptions, and reviewers.

Hazard definitions, severity values, rating guidance, acceptance policy, approvals, and review decisions are human-owned inputs. PySFMEA validates their basic shape but does not determine whether they satisfy a particular regulated process.

Sequence views combine ordered AST calls, resolved internal relationships, selected external calls, configured interfaces, and imported runtime relations. Traceability views connect requirements, components, failure modes, and hazards. Local interface specifications become stable contract components and contract-compatibility prompts; the lightweight YAML extraction is not a full OpenAPI validator. Coverage reports measure linkage and review disposition only; none of these views claim behavioral or hazard-analysis completeness.

The self-contained HTML report composes the governed analysis, aggregated validation
results, coverage measures, configured boundaries, trace catalogs, and a bounded set
of automatically selected sequences into a portable review interface. The report
retains the distinction between screening priority and engineering risk, labels
candidate prompts as unconfirmed, safely embeds repository-controlled text, and loads
no remote execution dependencies. Its visual summaries reduce navigation effort; they
do not add evidence, confirm causal relationships, establish completeness, or approve
a review decision.

All general report diagrams use a validated renderer-neutral node/edge schema.
Generated models cover bounded component architecture, configured interface flow,
requirement-to-hazard traceability, candidate failure propagation, recorded control
coverage, and ordered static/observed sequences. Projects can import custom flow,
state, traceability, cause/effect, sequence, or directed-graph models. Imported
relationships retain their declared evidence but receive no additional credibility
from validation or rendering.

The failure-propagation projection is explicitly bounded. By default it selects one
priority-ordered finding per component before filling remaining capacity. Operators can
pin named active findings for a review objective; pins consume the same record budget and
are embedded before the component-diversity pass. Requested pins, effective selection
policy, component coverage, caller-path/depth omissions, and the conservative node-budget
estimate remain machine-readable provenance. Pinning changes view composition only: it
does not change finding priority, evidence strength, review state, or causal credibility.
The projection also emits categorical status and reason codes. A “complete” state means
only that no configured report bound omitted material from the scanner-discovered static
inventory; source-inventory bounds remain a distinct, more conservative state. The HTML
report presents the same scope, selection, and budget facts beside the visual model.
It also exposes a copyable regeneration recipe beside the exact report analysis-state
digest. Canonical JSON diagram bundles carry the same state binding plus an internal content
digest, are verified when re-imported, and are atomically published. These mechanisms detect
accidental or unreconciled byte-level change after generation; they do not authenticate an
author, establish approval, or replace detached signatures for governed review packages.
The standalone verifier additionally validates every embedded canonical diagram and can
require an exact schema, baseline, and governed-state match. An omitted analysis argument is
recorded as not checked. Current generated bundles cannot silently downgrade to legacy import
behavior by removing their integrity declaration; genuinely older undeclared bundles retain
import compatibility but are not represented as verified.

Self-contained HTML reports independently protect their exact embedded JSON payload and the
normalized complete document, including local HTML, CSS, and JavaScript. The report verifier
also cross-checks the binding inside the payload against the document metadata and can require
an exact current analysis. Workflow status uses this same verifier. Reports from before the
document-digest requirement may pass at the explicitly labeled payload-only legacy scope;
current reports with a removed document digest fail closed. Neither scope authenticates the
author or establishes approval.
Both standalone verifier commands emit the same versioned human/JSON verdict shape on success
and structured JSON on rejection. Completed negative checks are not conflated with checks that
could not execute, which keeps CI policy decisions deterministic even for malformed or unsafe
inputs.

Public diagram, generated-bundle, and verification-verdict structures are available as
self-contained JSON Schema Draft 2020-12 documents through the deterministic schema catalog.
Each catalog entry carries a canonical content digest so an integration can pin the exact
contract it consumed. Structural schema validation complements but does not replace semantic
verification of content digests, unique identifiers, edge references, or current analysis
bindings.

Traceability graph identities are namespaced by element kind. Human catalog IDs remain
visible as `reference_id`, while a requirement and hazard that happen to share the same
textual ID cannot overwrite one another in JSON or Mermaid output. Configured
requirement-to-hazard relationships are rendered explicitly as mitigation links.

Contract components use the same configured component-mapping vocabulary as Python
components. Requirements, hazards, subsystems, and system interfaces flow into their
worksheet records and analysis-context fingerprints, so mapping changes require
review revalidation.

All sequence interactions—including static internal, selected external, and observed
runtime relationships—share the configured depth and interaction bounds. Truncated
views identify the limiting condition. The review-package export collects the governed
source record and derived reports with per-file SHA-256 checksums; it is a portable
review artifact, not an electronic-signature or document-control system.

The independent package verifier treats the manifest as untrusted input. It accepts
only canonical package-relative POSIX paths and regular files, requires the complete
artifact set, and rejects traversal, aliases, symbolic links, missing or unexpected
files, malformed metadata, byte/checksum changes, and baseline, schema, or generator
provenance mismatches. Current packages also carry the content-addressed public schema
catalog and all diagram/verifier contracts; verification reconciles their file set,
identities, canonical digests, and manifest declaration while retaining compatibility
with older schema-less format-1 packages. A successful result proves internal package consistency only;
it does not authenticate the manifest owner or approve the engineering content.

Single-file review archives use the same package manifest and content rules. Archive
generation is staged and atomically published. Verification first constrains the ZIP
container to unique, canonical root-level regular files and bounded expansion, then
stages only those accepted members and applies the normal manifest verifier. This
prevents archive traversal and common decompression-bomb paths; it does not make ZIP
an authenticated or confidential format, and encrypted archives are intentionally
unsupported.

Optional detached signatures use Ed25519 through the `cryptography` signing extra.
Signing is allowed only after content verification. The canonical signed statement
binds the exact archive digest (or directory-manifest digest) to the project,
baseline, schema, package generation time, signer label, and signing time. The
signature stays outside the package so it does not invalidate the manifest or become
self-referential. Verification is meaningful only when the supplied public key has
been obtained through a separately trusted process; key custody, revocation,
authorization, and formal engineering approval remain organizational controls.
Key and envelope files are consumed through bounded, regular-file, final-link-safe
reads with opened-file identity checks. Signature verification always reruns package
integrity verification, then requires the bounded manifest bytes to match that exact
verification digest. Detached-signature publication revalidates its destination at
the atomic replacement boundary and preserves prior content on rejected publication.
Exact ZIP bytes receive an additional identity-checked 550 MB streaming reconciliation.

Portable-package mode operates on a copy and removes machine-local absolute path
prefixes from the package snapshot and manifest. Relative source locations, hashes,
baseline IDs, audit decisions, and analysis content remain unchanged.

## Review-quality gates

Completeness validation is intentionally separate from scanner candidate generation and risk assessment. Default gates require the system purpose, boundary, operating context, ground rules, analysis revision, and review team. Accepted items must identify a named reviewer, requirement, causes, local/next-higher/end effects, severity and rationale, and actual controls. Action-required items must describe the action and name its owner and date. Rejected prompts require rationale. Closed items must record implemented or explicit no-action resolution, residual assessment and rationale, verification evidence, and applicable named approval. Incomplete scans, malformed configuration or persisted records, unmatched critical patterns, corrupt references, and stale source/context/baseline validation are errors.

A passing validation report means the configured fields and workflow relationships are present. It does not prove that a failure mode is credible, a rating is correct, controls are effective, residual risk is acceptable, or required independence has been achieved. Teams should configure these gates to mirror—not replace—their approved lifecycle process.

The `sfmea doctor` preflight runs before scanning and checks only repository and
configuration readiness. Post-scan `sfmea validate` remains the authoritative
completeness gate for the generated analysis and reviewed worksheet.

## Guidance applicability and integrity

The default `core_sfmea` profile provides general public methodology. NASA assurance,
FAA commercial-space, FAA airworthiness, security, and legacy references are opt-in
profiles selected through `analysis.guidance_profiles`. A rule-to-citation relationship
is emitted only when at least one of its declared profiles is selected. This prevents a
domain reference from being silently presented as generally applicable.

Each source record, citation, rule mapping, catalog, and active-profile selection has a
canonical SHA-256 digest. For captured public PDFs, the catalog also records the exact
downloaded byte count and response-body digest. The immutable scan manifest binds these
guidance inputs to the source, configuration, adapter registry, dependency inventory,
contract inventory, tool version, environment, and VCS state. These controls make the
analysis reproducible; they do not establish regulatory applicability, compliance, or
tool qualification.

## Public references

1. [NASA Software Engineering Handbook: SW Failure Modes and Effects Analysis](https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis)
2. [FAA Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety](https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf)
3. [IEC 60812:2018](https://webstore.iec.ch/en/publication/26359)
4. [NASA Software Safety Guidebook, NASA-GB-8719.13](https://standards.nasa.gov/sites/default/files/standards/NASA/Baseline/0/nasa-gb-871913.pdf)
5. [FAA AC 450.141-1A, Computing System Safety](https://www.faa.gov/regulations_policies/advisory_circulars/index.cfm/go/document.information/documentNumber/450.141-1A)
6. [FAA AC 20-115D, Airborne Software Development Assurance](https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D)

The IEC document is referenced but not reproduced. Users are responsible for obtaining and applying any required licensed standards.

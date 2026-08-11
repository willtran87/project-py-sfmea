# PySFMEA methodology

## Purpose and boundary

PySFMEA automates repository decomposition, evidence gathering, candidate generation, persistence, and reporting. It does not automate acceptance of failure modes, consequence analysis, risk acceptance, or approval.

## Governed analysis persistence

The analysis JSON is the editable source of truth. Loading consumes at most 200 MB from a
regular non-symbolic-link file and reconciles its inspected, opened, and final identity plus
size/change metadata. Strict UTF-8 JSON rejects duplicate object keys and non-finite numbers;
an iterative 100-level/5,000,000-node check runs before schema migration or derived-state
materialization. The analysis-specific node ceiling accommodates the bounded per-finding
projections produced for substantial repositories; all other governed JSON inputs retain their
own smaller, contract-specific limits. Package verification applies the same analysis metric.

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
The trace separately reports any-citation coverage and direct-mapping coverage, classifies
each finding by its strongest direct/supporting/contextual relationship, and lists rules
without a direct mapping. Supporting or contextual mappings are never counted as direct.
Unknown citation IDs, relationship types, strengths, and applicability values are validation
errors. Catalog hash drift is reported.

Built-in and organizational mappings expose a mapping-record SHA-256, review status, review
basis, review timestamp, and independent-approval flag. Citation records also bind the source,
locator, and maintained summary with a locator-summary digest. These digests detect local record
drift; they are not hashes of official prose unless a separately captured artifact hash says so.
Built-in mappings are maintainer-curated and deliberately report no independent regulatory
approval. Older embedded analyses without mapping-record digests remain readable and are counted
as legacy-unverifiable rather than as confirmed integrity failures.

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

External assurance state is parsed before it can influence that lifecycle. Work queues use a
100 MiB/100-level/1,000,000-node strict JSON boundary; scaffold and retirement manifests use a
64 MiB/100-level/500,000-node boundary; imported and recorded execution manifests use a
2 MB/100-level/100,000-node boundary. Each boundary refuses links and non-files, reconciles
inspected/opened/final identity, requires exact UTF-8, and rejects duplicate keys, non-finite
literals, and finite-syntax float overflow before canonical hashing or semantic checks. The
standalone generated pytest loader independently applies the scaffold structure and decoding
rules so its safety does not depend on an installed PySFMEA package.

Optional organizational guidance and runtime observations use the same exact-byte governed JSON
document primitive. A guidance pack is limited to 5 MB/100 levels/250,000 nodes before it can add
sources, locators, applicability, or rule relationships. A simple/OTLP trace is limited to
100 MB/100 levels/2,000,000 nodes before its separately bounded span and attribute traversal can
add observed cascade or timing evidence. Both require inspected/opened/final file identity,
duplicate-free finite UTF-8 JSON, and exact captured-byte hashing. Runtime state, history, and
summary commit together and roll back together. These controls preserve deterministic provenance;
they do not make a trace complete, representative, correctly instrumented, or causally sufficient.

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

Scanner evidence includes source location, AST signals, structured call sites, lexical branch/loop/exception context, await status, approximate internal callers and transitive upstream paths, confidence-labeled unresolved external-call candidates, complexity, decorators, textual test references, dependency declarations, and optional function-level line and branch evidence derived from coverage.py JSON. Call references carry resolution provenance from lexical names, import aliases, parameter or variable annotations, and unambiguous constructor assignments. Nested call sites follow Python expression-evaluation order, and return/yield/raise contexts are retained. This is lightweight evidence, not a complete type system: aliases, protocols, dependency injection, higher-order calls, descriptors, and runtime dispatch can remain unresolved. Lexical context records where a call appears in syntax; it is not a control-flow graph, path-feasibility result, or runtime-ordering proof. Coverage input is accepted from one exact-byte, regular-file, non-link, identity-stable snapshot under 100 MB/100-level/2,000,000-node JSON limits, with 100,000-file and 4,096-character path bounds. Duplicate keys, non-finite values, repository escapes, unsafe aliases, and malformed coordinates cannot silently influence a component. Accepted byte and record provenance remains in scan settings, its SHA-256 is part of the immutable run-manifest inputs, and an input inside the analyzed repository reuses those same bytes for inventory evidence. External coverage remains external evidence rather than being added to repository accounting. These are useful for triage and traceability. They are not proof that a failure exists or that a control is effective. Python's runtime dispatch means the caller and interface evidence is deliberately conservative and incomplete.

Python source uses one exact identity-stable snapshot per selected file. The same immutable bytes
drive PEP 263 decoding, AST construction, included-test reference indexing, and baseline hashing;
the scanner does not reread a selected file after findings have been derived. Eligible textual test
evidence uses a separate single-snapshot set captured before baseline construction and reused for
reference attribution and inventory hashing. Configured/default/hidden exclusions apply to that
index, and rejected link, boundary, identity, or limit cases remain explicit. The baseline records
accepted and rejected counts, accepted bytes, and canonical source and test-evidence digests over
ordered path/status/byte/hash records; the run manifest binds both digests. A successful snapshot
proves which bytes were inspected, not test adequacy or that static analysis resolves runtime
dispatch, generated code, imports, metaprogramming, deployed configuration, or native extensions.

Dependency evidence uses the same exact-snapshot principle. Pyproject, recursive
requirements/constraints, and supported lockfiles are captured from regular non-link files whose
inspected, opened, and final identities agree under 20 MB per-file, 1,000 attempted-file, and
100 MB aggregate limits. Each manifest record retains its byte count and SHA-256; supported parsing,
environment fingerprints, repository-inventory evidence, the repository baseline, and the
immutable run manifest reuse that snapshot. Interface-contract extraction follows the same rule:
operations, data types, contract inventory, and repository coverage bind to one captured byte
stream. Formats without an explicit semantic parser remain content-addressed artifacts. A hash
proves which bytes were analyzed, not that resolution, installation, provenance, licensing,
vulnerability state, or runtime compatibility is correct.

### Repository snapshot provenance

The repository inventory uses `schema_version: pysfmea-repository-inventory-1`. Every file entry
has a `snapshot_source` that explains whether its digest reused evidence already accepted by a
semantic adapter or came from the inventory's own bounded read:

| `snapshot_source` | Meaning |
|---|---|
| `analysis_source_snapshot` | Reuses the exact Python source bytes accepted for decoding, AST analysis, test indexing, and baseline construction. |
| `test_evidence_snapshot` | Reuses accepted textual test-reference evidence captured before baseline construction. |
| `dependency_manifest_snapshot` | Reuses an accepted pyproject, requirements/constraints, or supported lockfile snapshot. |
| `interface_contract_snapshot` | Reuses an accepted OpenAPI, AsyncAPI, Swagger, GraphQL, JSON Schema, Avro, YAML, or protobuf contract snapshot. |
| `coverage_evidence_snapshot` | Reuses accepted coverage.py JSON bytes only when that evidence file is inside the analyzed repository. |
| `identity_stable_inventory_snapshot` | The inventory performed its own bounded regular-file read with inspected/opened/final identity reconciliation. |
| `none` | No accepted content snapshot contributed to the entry, normally because only metadata was safe or available for an opaque, unresolved, excluded, or budget-limited artifact. |

`summary.by_snapshot_source` counts file entries by these values; its counts therefore sum to
`summary.files`. Regions are accounted separately and do not claim a content snapshot. A reused
snapshot means the inventory did not reopen that path, which prevents analysis and inventory from
describing different bytes after a concurrent replacement. It does not establish the origin,
authenticity, completeness, or fitness of those bytes. External coverage evidence remains bound
to scan provenance but is intentionally absent from repository inventory accounting.
Validation recomputes the derived file, region, status, kind, snapshot-source,
opaque/unresolved, and non-empty semantic-coverage values. Unknown or missing provenance produces
`coverage.invalid_snapshot_provenance`; inconsistent derived accounting produces
`coverage.inventory_summary_mismatch`. Historical analyses remain readable, but these errors
require a current rescan before a handoff can claim reconciled repository coverage.
Self-contained reports never visualize the stored summary directly. They recompute displayed
metrics from the complete bounded entry and region records and declare the projection
`reconciled`, `recomputed`, or `unavailable`. A recomputed report remains useful for diagnosis but
does not clear the validation or handoff gate; unavailable records withhold inventory counts.
The same safe projection supplies `sfmea coverage`, `sfmea inventory`, and human/JSON
`sfmea summary`. These views cannot disagree about reconciliation state or reuse stale stored
artifact totals. Review-package verification selects the producer's view contract: packages from
0.57.65 onward require the richer accounting, while genuine older views are regenerated with
their historical layout.

Confidence describes how directly a rule was triggered by observable syntax. It is not likelihood or occurrence. The two baseline functional rules are generated systematically even when no specialized syntax is present.

Ordered call evidence and common framework decorators identify HTTP routes, background tasks, event handlers, and CLI commands. Calls to known external namespaces and unresolved receiver methods with interface-like verbs are preserved as high- or medium-confidence interface candidates. Framework recognition and candidate classification are screening metadata; they do not prove the runtime router, receiver type, dependency injection graph, middleware order, or deployed configuration.

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

Imported simple or OpenTelemetry JSON spans add observed parent-child relations. Each span and derived edge retains an explicit observed/unavailable/invalid timing status and a duration only when non-negative integer timestamps are valid. Each import is hashed, baseline-linked, bounded, and audited. Static and observed relationships remain visibly distinct because one is approximate source evidence and the other is incomplete execution evidence; timestamps do not independently establish synchronized clocks or causal propagation.

Trace import is idempotent by source hash. Mapping prefers explicit `sfmea.component`
and code-function attributes, then unambiguous names, then code-file/function pairs.
Mapped and unmapped counts and mapping methods are retained so reviewers can assess
the strength of the runtime-to-source correlation.

## Curated regression evaluation boundary

The checked-in regression repository spans multiple files and 75 source-aware expectations,
including framework-style routes/tasks, async calls, data models, control-flow constructs,
typed receiver inference, nested-call ordering, and an internal multi-component cascade.
Golden scanner corpora use the closed `pysfmea-golden-corpus-1` contract: bounded metadata,
unique optional scope globs, and unique source/component/rule cases. File ingestion consumes at
most 20 MB from a regular non-symbolic-link input, reconciles path and opened-file identity, and
strictly decodes UTF-8 JSON without duplicate keys or non-finite values. Depth, node, case, scope,
field-length, and active-candidate limits are enforced before matching. Matching indexes exact
source/component/rule identities and refuses ambiguous source-less cases.

Optional semantic cases bind an exact source/component/rule identity to a closed subset of
deterministic generated output: failure mode, trigger, causes, local effect, recommended actions,
assurance verification method, all/direct citation IDs, adapter IDs, confidence, and screening
priority. Ordered narrative arrays compare exactly; citation and adapter arrays compare as
normalized sets and may be empty to express a negative expectation. Results retain missing cases,
field mismatches, exact-case recall/precision, claim recall/precision, and per-field/per-rule
populations. The maintained corpus contains ten cases and 78 claims across representative rule
families.

Control qualification uses an independently bounded `control_scope` of path/component globs.
Exact `control_cases` are positive kind/role labels; scoped components without a positive record
form the negative population. The evaluator reports both populations, counts any detected control
outside the positive labels as unexpected, and makes those false positives reduce precision. The
maintained corpus exercises four circuit-breaker records and three semantic near-misses. These are
static-detector metrics, not evidence that a control works under failure at runtime.

The deterministic `pysfmea-evaluation-result-1` includes verifier provenance and a canonical
corpus digest. Recall, precision, duplicate, localization, citation, traceability, provenance,
source-accounting, and exact semantic-output metrics establish repeatable behavior only within the
declared corpus scope and curated fields. They do not establish the correctness of reviewer-owned
system effects or ratings, performance on unseen systems, runtime behavior, certification credit,
or engineering approval of an updated golden baseline.
The checked-in corpus is synthetic and self-maintained; independent multi-repository validation
is still required before making claims about representative real-world recall or precision.

An optional exhaustive `call_cases` register labels call-reference resolution and interface
confidence for named components. Evaluation reports exact overall and per-provenance recall and
precision and fails on missing or unexpected labeled calls. The maintained synthetic corpus uses
this to prevent annotation/import/lexical resolution regressions. Confidence calibration on unseen
repositories still requires independently labeled cohorts. A bounded conversion utility accepts
only clean evaluation results and emits the closed validation-cohort record used by assurance
programs; distinct identity strings express review separation but are not authenticated.

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
planning artifacts, not evidence. Property-test obligations receive bounded Hypothesis strategy
specifications derived from retained signature annotations and conservative parameter-name
heuristics. Contract-test obligations receive conforming, missing-input, malformed-input,
incompatible-response, and declared-error cases tied to exact candidate contract digests. If no
association is defensible, synthesis emits an explicit failing contract-binding case.

Generated project adapters do not import or execute a subject automatically. They fail until an
engineer connects the exact analyzed component inside an approved sandbox and returns a structured
observation that proves stimulus activation, supplies evidence references, and records a true
result for every oracle and acceptance criterion. Manifest verification independently regenerates
the complete strategy/case projection, so a self-consistently rehashed change still fails exact
analysis binding. These controls establish deterministic design provenance, not oracle validity,
safe invocation, test adequacy, or evidence sufficiency. Planning review cannot directly set `verified`,
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

Qualitative minimal cut sets are calculated only when the latest governed SFTA authoring review is
approved and its stored definition SHA-256 exactly matches the current tree. The calculator expands
explicit AND, OR, VOTE, and INHIBIT logic, absorbs duplicate and strict-superset terms, retains
undeveloped, external, and conditioning event flags, and enforces per-tree count, width, and
operation ceilings. Unapproved, subsequently edited, ambiguous, cyclic, or excessive models return
a closed non-computed state with no partial cut-set list. Results do not calculate probability,
assume independence, establish causal sufficiency, or accept risk.

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
from validation or rendering. Custom files use exact-byte identity-stable strict JSON ingestion
under 5 MB/100-level/250,000-node per-file and 50-file/25 MB aggregate limits. Every imported
diagram retains its accepted source byte count and SHA-256 inside the integrity-protected report;
this supports attribution and reproducibility but does not authenticate authorship or establish
that any represented relationship is correct.

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

Offline schema-bundle and public failure-catalog files are consumed through a shared strict JSON
boundary before canonical hashing. Each file must be a regular non-link whose inspected, opened,
and final identities agree; bytes are bounded during the read; UTF-8 must decode exactly; duplicate
keys and non-finite numbers are rejected; and iterative depth/node ceilings constrain the decoded
structure. Schema files use a 2 MB/100-level/250,000-node limit and the catalog uses a
1 MB/50-level/100,000-node limit. Passing these checks establishes deterministic input handling,
not schema authorship, compatibility approval, or correctness of downstream policy.

Traceability graph identities are namespaced by element kind. Human catalog IDs remain
visible as `reference_id`, while a requirement and hazard that happen to share the same
textual ID cannot overwrite one another in JSON or Mermaid output. Configured
requirement-to-hazard relationships are rendered explicitly as mitigation links.

Contract components use the same configured component-mapping vocabulary as Python
components. Requirements, hazards, subsystems, and system interfaces flow into their
worksheet records and analysis-context fingerprints, so mapping changes require
review revalidation. Contract evidence is captured as one exact bounded regular-file snapshot;
links/non-files and inspected/opened/final identity changes are rejected. JSON contracts use
duplicate-free finite decoding under 100-level/1,000,000-node limits before semantic extraction.
Malformed files remain visible with warnings, exact byte counts, and content hashes but contribute
no unsupported operations or data types. The complete contract inventory is included in the
immutable run-manifest inputs. This integrity establishes attribution to accepted bytes, not that a
contract is authoritative, deployed, compatible, or complete.

All sequence interactions—including static internal, selected external, and observed
runtime relationships—share the configured depth and interaction bounds. Truncated
views identify the limiting condition. The review-package export collects the governed
source record and derived reports with per-file SHA-256 checksums; it is a portable
review artifact, not an electronic-signature or document-control system.

Sequence projections reconcile bounded relation-level static and runtime evidence. Static edges
are marked runtime-corroborated or not observed; observed edges are marked statically predicted or
runtime-only. Timing status and valid duration remain attached to observed interactions, and the
model reports relation counts and static-observation coverage. Absence from an imported trace is
not evidence of unreachability, while a runtime-only edge may reflect dynamic dispatch, a bounded
static view, or instrumentation mapping. The reconciliation is discovery evidence, not causal or
path-completeness proof.

Runtime JSON may carry a closed instrumentation manifest with scenario, producer, clock domain,
sampling policy, expected components, expected relationships, dropped spans, and a completeness
declaration. Import maps references through the same collision-aware component lookup. Component
coverage requires mapped spans; relationship coverage requires mapped parent-child spans with the
declared source and target. “Complete” requires always-on sampling, zero declared dropped spans,
and every resolved expected component and relationship being observed. This reconciles a
producer claim; it cannot prove hook placement, clock synchronization, causal completeness, or
scenario representativeness.

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
Key and envelope files are consumed through bounded regular-file reads whose inspected, opened,
and final identities must agree. Envelopes use strict duplicate-free finite UTF-8 decoding under
a 1 MB/20-level/10,000-node boundary. Signature verification always reruns package integrity
verification, then strictly decodes the independently reread manifest under a
10 MB/100-level/250,000-node boundary and requires those exact bytes to match the verification
digest. Detached-signature publication revalidates its destination at
the atomic replacement boundary and preserves prior content on rejected publication.
Exact ZIP bytes receive an additional identity-checked 550 MB streaming reconciliation.

Standalone engineering exports share a 256 MiB encoded-artifact publication boundary. CSV,
Markdown, JSON, SARIF, CycloneDX, SFTA, architecture, sequence, traceability, coverage, audit,
guidance, assurance-register/work-queue, individual JSON Schema, publication-catalog,
diagram-bundle, and HTML outputs retain the caller's final path identity instead of
resolving through a link. Publication rejects links and non-files, stages a private sibling,
flushes and synchronizes it, compares the destination with its inspected state, and then performs
one atomic replacement. This preserves an existing artifact when rendering, staging, identity
reconciliation, or replacement fails; it does not make the artifact's engineering conclusions
correct or provide durable-storage guarantees beyond the host filesystem contract.
Catalog replacement carries the exact absent/file state across existing-envelope validation and
refuses publication if that state changes before staging or replacement.

Portable-package mode operates on a copy and removes machine-local absolute path
prefixes from the package snapshot and manifest. Relative source locations, hashes,
baseline IDs, audit decisions, and analysis content remain unchanged.

## System assurance program boundary

An assurance program is intentionally separate from every repository analysis. Its repository
records bind a stable program ID to the exact canonical analysis-state digest and repository
baseline. Verification reloads each analysis through the governed 200 MB analysis boundary and
rejects stale bindings; it does not copy findings between repositories or let one service approve
another service's review state.

Relationships connect exact component IDs across repository IDs. Supported relationship kinds
cover calls, publish/subscribe flows, data flow, dependencies, controls, and fallbacks. A temporal
contract can declare deadline, timeout, retry, backoff, concurrency, ordering, and clock semantics.
A deadline is not credited merely because it is configured: the verifier requires an observed
maximum from runtime trace, load, fault-injection, concurrency, or chaos evidence when the policy
enables temporal-evidence gating. Only a completed, semantically valid, digest-verified evidence
artifact can contribute an observation; `not_run`, inconclusive, missing, or digest-mismatched
evidence remains uncredited. Failed evidence blocks readiness and can still expose an observed
contract violation. Timeout values cannot exceed deadlines. A circuit-breaker contract separately
declares its failure threshold, open-state timeout, half-open concurrency, and recovery deadline.
Passing fault-injection, concurrency, or chaos evidence must demonstrate breaker opening,
half-open recovery, and recovery within that deadline before resilience becomes supported. The
result reports
`supported`, `violated`, `unverified`, or `not_configured`; none is a whole-system schedulability or
causal-completeness proof.

Provider-neutral requirement snapshots retain source system, revision, timezone-qualified
retrieval metadata, exact record digest, and links to known repository, hazard, and finding IDs.
Hazard and finding references are repository-qualified as `REPOSITORY_ID:RECORD_ID`, preventing
the same repository-local ID from being silently conflated across analyses. This is the governed
interchange boundary for DOORS, Jama, Polarion, Jira, GitHub, or organization-specific connectors;
PySFMEA does not receive credentials or claim that an external API is authoritative. Completed
external evidence requires a bounded regular non-link artifact, exact SHA-256, technique, subject
links, result state, producer, and independent reviewer where configured. Supported technique
labels include coverage, mutation, property-based, fault-injection, concurrency, load, chaos,
SAST/DAST, runtime trace, formal analysis, and manual inspection. The label does not establish that
the named technique was performed correctly.

Repository-level fault injection uses a versioned plugin boundary rather than generated arbitrary
Python. The deterministic planner recommends built-in exception, return-value, or sequence plugins
from a finding's rule and verification method. A generated plan is content-bound to the exact
obligation contract but remains non-executable until explicit import and patch targets, JSON-safe
arguments, fault events, and expected observations validate. Completion rechecks the starter's
closed structure, integrity, exact obligation provenance, denied-network policy, and disabled
scanner execution before publishing a ready plan and deterministic pytest bridge. Runtime
execution supports dotted synchronous/asynchronous subjects, records patch calls and elapsed time
per invocation, enforces optional timing bounds, and rejects false-pass results. The API also
requires the marker injected by the approved container runner; that marker prevents accidental
host execution but is not an authentication credential. Scanner and report stages never import the
analyzed project, and passing plugin output remains evidence awaiting independent review.

Large orchestration modules depend on extracted typed seams in `interfaces.py`, deterministic
method/stimulus policy in `assurance_planning.py`, and pure container argv policy in
`sandbox_policy.py`. CI applies strict typing to the complete package and selected release-gate
scripts, so new package modules enter the gate automatically. It also enforces module-specific
branch-coverage floors, mutation-tests critical plan/outcome/sandbox verdicts, scans source and
dependencies, and publishes a CycloneDX dependency SBOM alongside coverage evidence.

Validation cohorts aggregate independently reviewed repository labels, content-addressed corpus
identity, case counts, expected-side and actual-side match counts, recall, and precision, with distinct named
producer/reviewer identities. Converted records bind the exact evaluation-result digest, format,
and verifier version. Semantic verification recomputes claimed rates and reports both equal-weight
macro averages and population-weighted micro averages; configurable gates can reject legacy
records that lack count provenance. Micro metrics prevent a small perfect corpus from masking a
larger weak one, while minimum repository counts keep one corpus from silently representing
external validation. Optional LLM evaluations are separately grouped by recorded
provider/model/prompt and corpus provenance, retain independent producer/reviewer claims, and are
count-backed. Grounding and citation accuracy aggregate over labeled samples; unsupported-claim
rate aggregates over total claims, avoiding bias when samples contain different numbers of claims.
Grounding, citation accuracy, unsupported-claim rate, sample, count-backing, retained-corpus, and
independence thresholds are explicit policy gates. Legacy records retain their former
sample-weighted projection behind an explicit aggregation label when new gates are disabled. These
metrics measure only the supplied evaluation records.

New cohorts also reference the retained evaluator JSON and bind both its exact file bytes and its
canonical parsed content. Program verification consumes each unique artifact once through bounded,
identity-stable, regular non-link strict JSON ingestion, enforces per-file and aggregate limits,
and reconciles every projected corpus, verifier, count, rate, missing/unexpected, and call metric.
This establishes artifact-to-claim consistency; it does not prove corpus representativeness,
reviewer authority, or that the evaluator itself is defect-free.

Validation aggregation treats the labeled corpus digest as its evidence-credit identity. LLM
replay additionally constructs a canonical semantic identity from corpus format, the bound subject
when present, and sample records sorted by normalized ID. Descriptive `name`/`purpose`, JSON byte
layout, and sample order are excluded. The converter publishes this value as
`evidence_fingerprint_sha256`; program verification recomputes it from the retained artifact rather
than trusting the claim. Distinct record IDs, reviewers, paths, metadata, or repeated runs do not
turn the same labeled evidence into a larger population. The first declaration remains credited,
later declarations remain visible as blocking duplicate evidence, and population-weighted metrics
use only unique credit identities. This prevents straightforward evidence repackaging from
inflating repository, case, sample, claim, artifact, or independence summaries; it does not prove
that differently labeled corpora are statistically independent or representative.

The `llm_quality_record.py` utility consumes one strict, bounded, content-addressed corpus of
independently labeled samples. Its closed sample contract records grounding and citation decisions
plus total and unsupported claim counts, then calculates the exact program-compatible aggregate.
It rejects duplicate samples, inconsistent counts, and identical producer/reviewer names. New
records bind an exact-byte artifact path; program verification safely replays the closed corpus,
recomputes every count and rate, and enforces per-file and aggregate bounds. The
result measures the supplied provider/model/prompt/corpus tuple only; corpus representativeness,
reviewer competence, identity authentication, and provider drift remain external controls.
Corpus format 2 places that provider/model/prompt tuple inside the retained labeled artifact and
requires an exact match to converter and program provenance. Format 1 remains replayable legacy
evidence but has no defensible subject binding and is rejected by the default subject gate.

Governance policy requires every configured role to approve the exact named program, uses
timezone-qualified decision timestamps, refuses one reviewer identity exercising multiple
required roles, validates known subjects, and requires distinct evidence producer/reviewer
identities. Any unresolved rejection by a required program role blocks readiness. An approval on
a repository, requirement, relationship, or evidence item cannot
satisfy a program-role gate. Names and roles are human-supplied claims. The
program does not implement SSO, RBAC, certificate validation, revocation, retention, or a legally
controlled electronic signature. Organizations can validate the public program/verdict schemas
and place the integrity-bound artifacts inside their approved identity and records system.

Program input uses a 10 MB, 100-level, 500,000-node strict duplicate-free finite UTF-8 JSON
boundary. Evidence artifacts are consumed through identity-stable regular-file reads capped at
100 MB each and 500 MB in aggregate. Program templates, resealing, and JSON/Markdown verdict
publication use bounded atomic final-path-safe replacement. HTML verdicts additionally verify the
embedded receipt on the private stage, then require unchanged staged identity, size, and rendered
digest before the same destination-state-checked replacement. Receipt validation closes nested
verifier/program/finding records, reconciles level counts and validity, and binds the stage to the
exact requested in-memory program/verdict digests so a different self-consistent report cannot be
substituted. Verification findings are capped at a
public-contract-aligned 200,000 records. The searchable HTML view escapes all program-controlled
text, loads no remote resources, and provides accessible navigation, a bounded inline repository
topology, trusted-evidence counts, timing/resilience tables, severity filtering, and print styles.

## Review-quality gates

Completeness validation is intentionally separate from scanner candidate generation and risk assessment. Default gates require the system purpose, boundary, operating context, ground rules, analysis revision, and review team. Accepted items must identify a named reviewer, requirement, causes, local/next-higher/end effects, severity and rationale, and actual controls. Action-required items must describe the action and name its owner and date. Rejected prompts require rationale. Closed items must record implemented or explicit no-action resolution, residual assessment and rationale, verification evidence, and applicable named approval. Incomplete scans, malformed configuration or persisted records, unmatched critical patterns, corrupt references, and stale source/context/baseline validation are errors.

A passing validation report means the configured fields and workflow relationships are present. It does not prove that a failure mode is credible, a rating is correct, controls are effective, residual risk is acceptable, or required independence has been achieved. Teams should configure these gates to mirror—not replace—their approved lifecycle process.

The `sfmea doctor` preflight runs before scanning and checks only repository and
configuration readiness. Post-scan `sfmea validate` remains the authoritative
completeness gate for the generated analysis and reviewed worksheet.

Validation also verifies the immutable scan manifest rather than merely checking for its presence.
It recomputes the manifest and resolved-input digests and cross-checks the declared source,
configuration, guidance, dependency, contract, repository inventory, system context, adapter
ledger, repository baseline, scan time, stable run ID, schema, adapter registry, and non-execution
claim against the governed analysis. A locally edited and rehashed claim remains invalid when it
no longer matches those sources. Portable package root redaction is accepted only with its explicit
redaction record. This is consistency verification, not a signature or identity assertion.

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

Mapping-review expiry uses the persisted scan time only when the manifest content and timestamp
binding verify. If either check fails, traceability retains the audit result for diagnosis but
grants zero effective independent-approval credit until the analysis provenance is restored.

## Advanced review authority boundaries

Report saved views are local presentation state keyed to a baseline; URL fragments contain only
bounded filters. Accessibility automation covers a named WCAG subset, while exact-report manual
evidence separately records keyboard, zoom/reflow, display-preference, and screen-reader results.
Neither presentation state nor an automated browser check changes the governed analysis.

LLM suggestions remain evidence-constrained proposals. Deterministic lexical relationships expose
possible duplicates, contradictions, and divergent claims without deciding which is correct. A
sealed synthesis workspace binds the original suggestion and analysis, records human edits, and
requires a named reviewer and rationale for accept/reject. Accepted proposals remain unreviewed
worksheet findings.

Pull-request orchestration compares exact committed archives without checking out the working tree
or executing repository code. Process plugins are explicit, semantic-versioned, bounded
observation producers. Their separate process and reduced environment are not an operating-system
sandbox, and their output receives no reviewer authority automatically. See
[advanced review workflows](ADVANCED_REVIEW.md) for commands and operational controls.

## Public references

1. [NASA Software Engineering Handbook: SW Failure Modes and Effects Analysis](https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis)
2. [FAA Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety](https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf)
3. [IEC 60812:2018](https://webstore.iec.ch/en/publication/26359)
4. [NASA Software Safety Guidebook, NASA-GB-8719.13](https://standards.nasa.gov/sites/default/files/standards/NASA/Baseline/0/nasa-gb-871913.pdf)
5. [FAA AC 450.141-1A, Computing System Safety](https://www.faa.gov/regulations_policies/advisory_circulars/index.cfm/go/document.information/documentNumber/450.141-1A)
6. [FAA AC 20-115D, Airborne Software Development Assurance](https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D)

The IEC document is referenced but not reproduced. Users are responsible for obtaining and applying any required licensed standards.

# Public interchange schemas

PySFMEA publishes self-contained JSON Schema Draft 2020-12 documents for integrations that
need to validate public assurance, workflow, diagram, package, signature, and verifier
structures without importing PySFMEA internals or using a network service.

## Discover and export

```powershell
sfmea schema --list
sfmea schema --list --json
sfmea schema diagram
sfmea schema diagram -o pysfmea-diagram.schema.json
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

`sfmea schema NAME` writes the selected schema to standard output. `-o` publishes deterministic
UTF-8 JSON through a temporary sibling and atomic replacement. The machine-readable catalog
contains the schema name, URN, JSON Schema draft, description, and canonical SHA-256 digest.
The publication catalog command provides a concise operational view of the schema-backed failure
and remediation catalog; JSON mode emits the complete deterministic catalog document.
`--output FILE` publishes deterministic UTF-8 JSON through a verified temporary sibling and atomic
replacement. Existing destinations require `--force`, which accepts only a regular recognized
catalog and refuses unrelated, malformed, directory, or symbolic-link targets. A failed staged
verification or replacement leaves the prior destination unchanged and removes temporary residue.
With `--json`, a successful export emits the public catalog-verification verdict bound to the exact
output path. Forced refresh requires the prior file to pass format, integrity-metadata, and closed
failure-entry structural checks; a matching format string by itself never authorizes replacement.
`--verify FILE` performs bounded regular-file and UTF-8 JSON loading, canonical digest checks, and
exact comparison with the verifier's shipped taxonomy. Its JSON verdict uses the public
`publication-failure-catalog-verification` contract and returns nonzero on rejection.

`--bundle DIRECTORY` atomically publishes the catalog and complete schema set after verifying
the staged output. A non-empty recognized bundle requires `--force`; unknown files, symbolic
links, and non-file entries prevent replacement so local material is not silently discarded.
`--verify-bundle DIRECTORY` performs bounded standalone verification and returns nonzero for a
missing, partial, mixed, malformed, or digest-mismatched bundle. `--json` emits the public
schema-bundle verification contract for CI policy and evidence capture. The verifier reads each
allowed regular non-symbolic-link entry once, stops after two megabytes plus the rejection byte,
and explicitly decodes UTF-8 JSON before catalog, identity, and digest checks.

Available names:

| Name | Contract |
|---|---|
| `accessibility-evidence` | Sealed, exact-report-bound manual accessibility qualification evidence |
| `accessibility-evidence-draft` | Editable required-scenario accessibility qualification checklist |
| `accessibility-evidence-verification` | Integrity, completeness, outcome, and optional exact-report binding verdict |
| `activation-apply-receipt` | Exact source/workspace/result bindings and applied-decision accounting |
| `activation-records` | Exact-workspace-bound bulk assignment and decision interchange |
| `activation-records-import-receipt` | Transactional import counts plus source-record and resulting-workspace digests |
| `activation-workspace` | Editable evidence onboarding, test attribution, review/calibration, guidance, SFTA, architecture, and interface work package |
| `activation-workspace-verification` | Bounded integrity, decision semantics, uniqueness, and optional exact-analysis binding verdict |
| `configuration-authoring` | Sealed exact-analysis-and-configuration-bound reviewed configuration additions |
| `configuration-authoring-apply-receipt` | Validated TOML publication and addition-count receipt |
| `configuration-authoring-draft` | Editable guidance, architecture, and interface proposal workspace |
| `configuration-authoring-verification` | Integrity, semantics, and optional exact-binding verdict |
| `cross-reference` | Typed entity/relationship fabric, fused scanner channels, semantic-exposure, verification-readiness, review-governance, adapter-run, repository-source, non-authoritative machine-assistance, guidance/context/lifecycle provenance, analysis-output projection coverage, finding chains, quality diagnostics, compound-model/claim intersections, and prioritized review leads |
| `cross-reference-verification` | Fabric integrity, semantic/readiness/governance/repository/machine/guidance/context/lifecycle/output-projection consistency, diagnostic scope/identity, accounting, and optional exact-analysis regeneration verdict |
| `sfta-authoring` | Sealed exact-analysis-bound fault-tree definitions with named engineering approvals |
| `sfta-authoring-apply-receipt` | Applied hazard replacements and source/result analysis bindings |
| `sfta-authoring-draft` | Editable one-entry-per-hazard fault-tree engineering workspace |
| `sfta-authoring-verification` | Integrity, structure, logic, review, and optional exact-analysis binding verdict |
| `assurance-program` | Multi-repository analysis bindings, external requirements/evidence, temporal and circuit-breaker relationships, independent validation/model metrics, and governance policy |
| `assurance-program-report-verification` | Standalone program-HTML integrity and optional exact-program regeneration verdicts |
| `assurance-program-verification` | Program integrity, binding, trusted-evidence, timing/resilience, quality-gate, relationship, and governance verdicts |
| `assurance-scaffold` | Exact-analysis-bound pytest starting points, property strategies, contract cases, and generated-file identities |
| `assurance-scaffold-verification` | Manifest, synthesized-design, generated-file, lifecycle, and exact analysis-binding verdict |
| `assurance-work-queue` | Accepted-finding work states, blockers, automation eligibility, and next actions |
| `assurance-work-queue-verification` | Queue integrity, analysis binding, and deterministic-projection verdicts |
| `detached-signature` | Ed25519 signature envelope, signed statement, and package subject |
| `diagram` | Renderer-neutral `pysfmea-diagram-1` object |
| `diagram-bundle` | Generated, integrity-declaring `pysfmea-diagram-bundle-1` object |
| `fault-injection-plan` | Obligation-bound, integrity-declaring plan for a governed built-in fault-injection plugin |
| `fault-injection-plan-verification` | Plan integrity, readiness, closed policy, plugin, case, and mandatory exact obligation-binding verdicts |
| `diagram-bundle-verification` | Success, rejection, and incomplete diagram-verifier verdicts |
| `enhancement-workbench` | Bounded capability register, evidence recipes, review clusters, assurance portfolio, static surface models, and governed disposition queues |
| `enhancement-workbench-verification` | Workbench integrity, register completeness, optional analysis binding, and exact-regeneration verdicts |
| `enhancement-scope-preview` | Read-only bounded file-metadata preview for proposed evidence-only scope changes |
| `evidence-preflight` | Read-only analysis-bound evidence readiness and remediation receipt |
| `evidence-onboarding-receipt` | Selected-artifact identities, source/result bindings, import accounting, and verified assurance queue |
| `evidence-onboarding-receipt-verification` | Receipt integrity and optional exact resulting-analysis binding verdict |
| `html-report-verification` | Success, rejection, and incomplete HTML-verifier verdicts |
| `plugin-manifest` | Closed SDK identity, compatibility, capability, entry point, trust, and execution-limit declaration |
| `plugin-request` | Versioned, exact-analysis-bound isolated-process request envelope |
| `plugin-response` | Strict observation-only plugin response envelope |
| `plugin-run` | Content-addressed plugin execution receipt and process-boundary disclosure |
| `plugin-run-verification` | Run integrity plus optional exact analysis and manifest binding verdict |
| `publication-failure-catalog` | Package-publication failure codes, phases, stable findings, remediation actions, and retry policy |
| `publication-failure-catalog-verification` | Bounded catalog integrity and exact-taxonomy success/rejection verdicts |
| `pull-request-analysis` | Exact-commit base/head bundle receipt with artifact and security declarations |
| `pull-request-analysis-verification` | File-set, digest, regeneration, report, commit, configuration, and security verdict |
| `qualification-campaign-manifest` | Closed governance, thresholds, repository segments, and relative retained-artifact references |
| `qualification-campaign-result` | Exact-regenerated finding, call-resolution, and false-positive-aware control metrics plus positive/negative control populations by repository, rule, framework, and domain |
| `qualification-campaign-verification` | Internal integrity plus optional exact manifest/artifact regeneration verdict |
| `qualification-report-verification` | Self-contained HTML document, embedded campaign result, and optional exact-result binding verdict |
| `report-browser-quality` | Content-addressed Chromium navigation, progressive per-section rendering, performance, responsive-layout, accessibility, and UI-contract receipt |
| `report-browser-quality-verification` | Receipt integrity, semantic consistency, and optional exact-report binding verdict |
| `review-package-manifest` | Package file inventory, checksums, provenance, and state binding |
| `review-package-verification` | Success and rejection verdicts from `verify-package --json`, plus success, pre-publication failure, and post-publication rejection receipts from `package --json` |
| `schema-bundle-verification` | Success and rejection verdicts for the offline schema set |
| `schema-catalog` | Content-addressed discovery metadata for the complete public contract set |
| `synthesis-apply-receipt` | Source/result analysis and sealed-workspace bindings for applied decisions |
| `synthesis-apply-receipt-verification` | Receipt integrity plus complete source/workspace/result and decision-accounting reconciliation verdict |
| `synthesis-workspace` | Sealed, exact-analysis-bound suggestion and contradiction-review workspace |
| `synthesis-workspace-draft` | Editable, human-controlled suggestion synthesis workspace |
| `synthesis-workspace-verification` | Integrity, decision, contradiction, and optional exact-analysis binding verdict |
| `workflow-status` | Lifecycle stage, handoff gates, evidence, summaries, and remediation actions |

The schemas use stable `urn:pysfmea:schema:…:1` identifiers and have no external `$ref`
dependencies. A consumer can pin the catalog digest and retain the exported schema beside its
CI policy or evidence record.

The cross-reference pair is intended for automation as well as report rendering:

```powershell
sfmea cross-reference analysis.json -o cross-reference.json
sfmea cross-reference-verify cross-reference.json --analysis analysis.json --json
sfmea schema cross-reference -o pysfmea-cross-reference.schema.json
sfmea schema cross-reference-verification -o pysfmea-cross-reference-verification.schema.json
```

Every semantic profile binds one component to exact embedded analyzer-record entities and
relationships across ten closed dimensions. Finding chains copy that profile binding and expose
deterministically derived `compound_exposure_kinds`. The verifier reconciles profile identity,
dimension booleans, record references, compound rules, and all summary counts even when the source
analysis is not supplied; `--analysis` additionally requires exact regeneration.

`analysis_projection_coverage` makes output integration inspectable rather than implicit. Every
top-level source section has a stable `analysis_section` entity, canonical source digest, source
record count, declaration mode, coverage status, and sampled/digested projection identity sets.
The complete entity and relationship sets are recomputed from declared kinds and channels during
standalone verification. Unknown populated sections are `unmapped`; registered semantic sections
with source records but no material link are `registered_without_projection`. Supplying
`--analysis` additionally proves each source digest through exact regeneration. Section-level
declared and material coverage percentages remain separate.

`record_profiles` closes the nested-output accounting gap. Every bounded projectable record in a
semantic section carries a stable section/path/locator identity, canonical source digest, bounded
field-qualified identity tokens, a `semantically_projected` or `unresolved_projection` state,
complete target-set counts and digests, and bounded graph witnesses. Section profiles reconcile
projected, unresolved, and bound-omitted record counts; `record_coverage_percent` uses all semantic
source records as its denominator. Standalone verification rebuilds every target set from declared
kinds/channels and identity tokens and rejects witness drift. Exact verification additionally
regenerates the tokens and source digests from the retained analysis. Identity equality establishes
a navigable traceability witness, not analytical correctness or semantic equivalence.

`repository_provenance` binds the analysis scope to its integrity-declaring inventory, every
inventoried artifact and excluded region, dependency and contract declarations, the resolved
configuration input, and exact component/finding source relationships. Finding chains copy the source path, inventory
status, analysis depth, digest, adapter IDs, and relationship IDs. The verifier reconciles every
typed entity and relationship, opaque-artifact partition, unaccounted source ID, and summary count.

`machine_assistance_provenance` projects governed suggestions and generated summaries as separate
typed entities. Suggestion profiles retain component, allowlisted evidence, proposed citation,
human-materialization, status, confidence, and lexical-comparison links. Summary profiles retain
scope, evidence, staleness, and provider/model/prompt metadata. The standalone verifier reconciles
profile/entity identity, exact relationship sets and shapes, unresolved references, stale records,
claim counts, finding-chain copies, and summary accounting. These links never convert generated
text or token similarity into an approved finding, authoritative citation, sufficient evidence, or
compliance conclusion.

`guidance_provenance` joins the recorded methodology to its selected versioned source records,
ordered review checks, exact citation locator records, and every citing finding. Source and
citation profiles embed their bounded records and canonical digests; finding chains copy only the
source entities and two-hop relationship IDs relevant to that finding. The standalone verifier
recomputes catalog-record and locator-summary digests, entity identities, typed relationship sets,
unresolved source partitions, chain copies, and summary counts. Complete lineage proves only that
the recorded identifiers reconcile; it does not authenticate an official document or establish
applicability, compliance, or approval.

`system_context_provenance` binds the analysis scope and run-manifest configuration input to the
resolved context record, field profiles, and exact configured values. Finding review context is
preserved as separate claim entities with one of `matched`, `outside_catalog`,
`catalog_unresolved`, or `not_cataloged`. Matching uses only the declared review-to-context field
map and case-folded whitespace-normalized equality. The verifier reconstructs entity partitions,
relationship shapes, match targets, unmatched partitions, chain copies, and summary counts.

`lifecycle_provenance` projects ordered analysis history and per-finding `review_history` into
digest-bound event profiles. Parent scope, sequence, timestamp, event kind, changed fields,
recorded actor labels, exact typed subject links, unresolved references, chain copies, and counts
are independently reconciled. Actor labels are intentionally not identity, approval, or reviewer-
independence evidence.

Entity references are bounded non-empty strings rather than slug-only identifiers because exact
repository-artifact identities intentionally retain normalized relative paths such as
`src/package/module.py`; relationship IDs and typed kind/channel names remain identifier-shaped.
Configuration-derived common-cause findings retain the run manifest's configuration digest rather
than being misclassified as missing repository files. An `indexed` or `opaque` status remains
repository accounting only, not semantic-analysis credit.

Every finding also has one `verification_readiness_profile`. It references candidate tests,
coverage observations, registered test implementations, executions, evidence artifacts, and
assignments as separately typed entities; records lifecycle state, blockers, next action, and a
closed evidence posture; and emits gaps only for active accepted findings. Candidate references
and coverage are never promoted to execution evidence or verification success. The verifier
recomputes the evidence signals and posture from the referenced entities, reconciles the copied
finding-chain fields, and checks every readiness summary count.

Every finding also has one `review_governance_profile`. It binds source-change and revalidation
state, disposition, workflow status, finding-local quality diagnostics, blocking diagnostics, the
verification-readiness profile, and the deterministic next review action. The separate
`quality_gate_projection` anchors global diagnostics to the exact analysis state. Diagnostic IDs
include a deterministic occurrence ordinal so byte-identical repeats remain distinct. Standalone
verification reconstructs those identities, partitions global and local diagnostics, checks
counts and relationships, derives governance state/action, and reconciles every chain copy.
Diagnostics express workflow completeness and consistency; they do not establish a software
failure, safety, or compliance.

Without `--analysis`, verification checks the fabric's own digest, identities, references,
fusions, chains, and summary accounting. Supplying the governed analysis additionally requires
its state binding and byte-independent exact deterministic regeneration.

### Repository inventory programmatic output

The governed analysis and review package also carry a versioned
`pysfmea-repository-inventory-1` object (the analysis JSON's top-level
`repository_inventory` field and the package's `repository-inventory.json`). This object is
programmatic output, but it is not currently a
separately published `sfmea schema` contract. Consumers should require its `schema_version`,
tolerate additive fields, and treat unknown values conservatively.

Each file entry includes `snapshot_source`; `summary.by_snapshot_source` aggregates the same
values for the producing release. Counts cover file entries, while `regions` remain separate. See
[Repository snapshot provenance](METHODOLOGY.md#repository-snapshot-provenance) for the value
definitions and trust boundary. Package verification regenerates this projection from the
packaged governed analysis, so the manifest checksum alone is not its only integrity check.
Quality validation also recomputes the inventory summary and rejects missing or unknown snapshot
provenance. This protects consumers from trusting altered derived counts, which are intentionally
not part of `inventory_sha256`.
The HTML report payload independently includes `summary_reconciliation.status` with
`reconciled`, `recomputed`, or `unavailable`. Its displayed `summary` is always derived from the
embedded analysis records or empty when safe derivation is impossible; it is never copied from an
unreconciled stored summary. This report-only diagnostic is additive output, not a public schema
catalog contract or a repair of the governed analysis.
Coverage JSON and `sfmea summary --json` expose the same additive safe projection. Their
repository accounting is programmatic output rather than a cataloged public schema: consumers
must branch on `reconciliation_status`/`status`, accept `null` totals when unavailable, and avoid
interpreting semantic accounting coverage as behavioral or test adequacy.

### Architecture analysis programmatic outputs

The governed analysis carries three additive, versioned top-level architecture objects:

| Field | Format | Meaning |
|---|---|---|
| `deployment_topology` | `pysfmea-deployment-topology-1` | Provenance-bearing declared deployment nodes/edges and bounded candidate component placements |
| `shared_fate_analysis` | `pysfmea-shared-fate-analysis-1` | Multi-component deployment, subsystem, and external-dependency common-cause review leads |
| `architecture_hierarchy` | `pysfmea-architecture-hierarchy-1` | Repository/subsystem/source-package nesting, memberships, and upward trace aggregation |
| `graphify_reconciliation` | `pysfmea-graphify-reconciliation-1` | Optional bounded Graphify provenance plus component-mapped typed static edges, native-call comparison, and explicit Graphify-only review leads |
| `exception_propagation` | `pysfmea-exception-propagation-2` | Ordered, inheritance-aware raise/handler/finalizer records and resolved-call propagation edges with bounded branch outcomes, outcome certainty, active-binding rethrow identity, explicit handler/finalizer provenance, suppression/replacement disposition, uncertainty, and component/finding exposure. Format 2 makes the outcome and rethrow-identity fields part of the validated contract |
| `static_control_flow_model` | `pysfmea-static-control-flow-model-1` | Count-reconciled, component-linked safe decisions for literal/boolean/`TYPE_CHECKING` branches, bounded literal sequence/mapping structural-pattern cases and guards, constant loops, empty literal iteration, exhaustive `try`/terminal-`finally` paths, terminal blocks, and short-circuit operands pruned before downstream call, exception, sequence, and failure-mode composition |

These are programmatic analysis outputs rather than separately cataloged `sfmea schema` names.
Consumers should require the exact `format`, validate the full analysis, reconcile each summary to
its records, follow component backlinks to the top-level objects, and preserve limitations and
authority fields. Unknown additive fields should be tolerated. The HTML payload embeds a bounded
100-record navigation projection; the analysis JSON remains the complete bounded source.

### System assurance program contracts

`pysfmea-assurance-program-1` is a separate system-level artifact. It references one or more
governed analysis files by path, exact canonical state SHA-256, and baseline ID; it does not merge
or mutate those analyses. Closed, bounded collections represent cross-repository component
relationships and temporal/circuit-breaker policies, requirements-source snapshots, external
evidence artifacts, validation cohorts, LLM quality evaluations, governance approvals, and
configurable quality gates. Completed evidence requires an artifact path and digest. Cohort and LLM
records include corpus digests plus distinct producer/reviewer identities. Converted validation
cohorts also retain expected-side and actual-side match counts for failure-mode, call-resolution,
and optional exact semantic-output cases, evaluation-result format and digest,
evaluator version, and an exact-byte artifact reference. The verifier safely consumes the retained
JSON, reconciles its complete projection, recomputes claimed rates, reports cohort-macro and population-weighted
micro metrics, and can require every failure-mode, call-resolution, and semantic-output cohort to be count-backed.
Legacy cohorts without count provenance remain schema-compatible so older programs can be read,
but new program templates enable count-backed, retained-artifact, and micro gates. Finding and hazard references are semantically
resolved as `REPOSITORY_ID:RECORD_ID`.

Qualification campaign results retain a bounded `semantic_diagnostics` record for each repository.
Its `missing` examples carry identity only; its `mismatch` examples must carry a field plus exact
expected and actual values. The public schema enforces those mutually exclusive shapes, while the
full retained evaluation artifact remains the source of record.
Converted LLM evaluations preserve grounded and citation-correct sample counts plus total and
unsupported claim counts. `corpus_artifact` binds the exact labeled JSON bytes. Default policy
requires both count backing and artifact replay; verdicts state whether aggregation is
`count-backed`, `legacy-sample-weighted`, or unavailable. Unsupported-claim rate is aggregated by
claims rather than samples.
`pysfmea-llm-quality-corpus-2` additionally binds a closed provider/model/prompt-version subject.
Program verification reconciles that subject to the evaluation record and reports subject-bound
coverage. Version-1 corpora remain consumable for compatibility but cannot satisfy the default
`require_llm_subject_binding` policy.
Validation aggregation uses `corpus_sha256` as its evidence-credit identity. Replayed LLM
aggregation uses `evidence_fingerprint_sha256`, canonically derived from corpus format, bound
subject, and normalized ID-sorted samples; display metadata, byte formatting, and sample ordering
are excluded. The field is optional for older records, but current conversion emits it and the
verifier always recomputes it when artifact replay succeeds. Repeated declarations remain visible,
are rejected as duplicate evidence, and receive no repository, case, sample, claim, artifact,
independence, or quality-metric credit. Verification projections expose `cohorts`/`evaluations`,
`credited_cohorts`/`credited_evaluations`, `duplicate_evidence`, and
`semantic_fingerprinted_evaluations`.
Program integrity hashes every field outside the integrity declaration using canonical sorted-key
compact UTF-8 JSON. Run `sfmea program-seal` only after intentional edits.

`pysfmea-assurance-program-verification-1` is emitted for success and rejection. It separates
individual checks for input, format, program contract, integrity, repository binding,
relationships, requirements, external evidence, validation, LLM quality, and governance. JSON,
Markdown, and self-contained HTML views are projections of that same verdict. Timing and
circuit-breaker support use only completed content-addressed evidence; failed results block a valid
verdict, while unrun and inconclusive records receive no claim credit. A valid verdict confirms
that configured references, digests, thresholds, roles, and independence constraints reconcile;
it does not authenticate an identity, approve risk, or establish certification.

Program HTML carries an embedded copy of that exact machine verdict plus independent digests for
the payload bytes, canonical verdict, source program, and normalized whole document.
`sfmea program-report-verify REPORT --json` validates the self-contained receipt;
`--program PROGRAM` additionally reruns program verification and requires exact content and
verdict-semantic matches while excluding only the local program path. The public
`assurance-program-report-verification` schema distinguishes
`valid_binding_not_checked`, `matched`, `mismatched`, and `invalid`. Standalone integrity is useful
for accidental-corruption detection but is not authenticity: a recipient seeking substantive
binding should retain the program and use exact regeneration.
`program-verify --format html --output REPORT --publication-json` adds the optional closed
`publication` record to that same verdict. A completed publication must be exactly program-bound
and valid; a rejected publication is invalid and records `input_validation`,
`program_verification`, `generation`, or `publication`. A rare published artifact that fails the
final read-back is explicitly `published` at `post_publication_verification`, never mislabeled as
preserved. `destination_existed` and `prior_destination_preserved` reconcile for every rejection.
Every readable report verdict carries `artifact_sha256`, the SHA-256 of the exact HTML byte
sequence. Input/publication rejections carry an empty digest and zero bytes; a completed
publication requires a non-empty exact-byte digest. This external receipt digest complements the
normalized whole-document digest embedded inside the self-referential HTML.
Supplying `program-report-verify --expect-sha256 DIGEST` populates
`expected_artifact_sha256`, `artifact_binding_requested`, `artifact_binding_checked`, and the
`artifact_identity` check. A mismatch makes the verdict invalid. If the report cannot be read, the
request remains visible but `artifact_binding_checked` is false and the check is `null`; the
verifier does not claim a comparison it could not perform.
`program-report-verify --output RECEIPT.json` atomically writes this same schema-backed verdict as
bounded UTF-8 JSON. It rejects report/program source collisions and destination-state races;
invalid report verdicts are still retained with exit `1`, while receipt-publication failure exits
`2` and preserves the prior or concurrent destination.
The private stage is strictly parsed under byte/depth/node limits and must reproduce the canonical
semantic digest of the exact in-memory verdict before replacement. Identity, size, and exact byte
digest are rechecked afterward, so a malformed, non-finite, or semantically substituted stage is
rejected and cleaned up.
Before staging, the current producer applies a closed runtime contract that reconciles exact
fields and types, check-derived failed/unchecked lists, artifact and program binding state,
status/validity, and optional publication state. This prevents the atomic exporter from faithfully
publishing an internally contradictory caller-supplied dictionary.
Program HTML export verifies this receipt on a private sibling before publication, then requires
the staged file to retain its regular-file identity, size, and rendered-content digest. The final
destination must still match its inspected absent/file state immediately before atomic
replacement. Rejection or concurrent change preserves the previous report.
The embedded payload check enforces the closed verdict envelope, exact nested verifier/program
records, the exact current producer check set, and closed summary, relationship, validation, LLM,
and finding projections. It reconciles finding counts and validity; repository, relationship, and
evidence totals; timing/resilience configuration state; cohort credit and duplicate counts;
artifact-credit bounds; and LLM aggregation/claim totals. Minimal early input rejections are
separately closed and cannot claim unchecked derived summaries. The public
`assurance-program-verification` schema now exposes these exact nested structures; cross-field
arithmetic remains enforced by the runtime verifier. Relationship schema conditions require
configured deadlines, observations, and linked evidence for supported/violated timing and
resilience states. Runtime checks additionally require supported timing/recovery to remain within
their declared deadlines, measured timing violations to exceed the deadline, repository-binding
checks to match bound totals, and credited completed evidence not to exceed passed/failed records.
Publication additionally requires the staged receipt's program and normalized verdict digests to
match the exact in-memory result supplied to the renderer.
Runtime reconciliation derives each full-verdict check from the corresponding error-code
namespace rather than trusting the declared boolean. Endpoint, deadline-overrun, and
circuit-breaker-violation projections must also match the exact relationship-scoped finding code
and location. This semantic linkage is intentionally stronger than JSON Schema and prevents
balanced count/validity edits from moving a failure between assurance domains.
Finding codes are restricted to producer-owned namespaces. Runtime reconciliation also prevents
observed deadline or recovery overruns from being relabeled as unverified, derives validation
metric availability from the credited/count-backed populations, and derives the LLM aggregation
mode from credited and count-backed evaluations. Count-backed unsupported-claim rates must equal
their projected claim totals. The public schema mirrors deterministic availability and
aggregation-state constraints where JSON Schema can express them.
Governance summaries distinguish declared, fully validated, and credited program-level approvals.
Approval credit requires a closed record, supported subject kind, known exact subject, bounded
identities, a supported decision, and an offset-bearing timestamp. Malformed declarations remain
visible in the declared total and findings but cannot satisfy roles or named-program approval.
Required roles use bounded, whitespace-free identifiers and must also be unique after
case-normalization, preventing visually distinct declarations from collapsing into one authority.
Exactly one valid program-level decision may occupy each normalized role. Multiple approvals,
rejections, or mixed decisions for the same role are reported as an explicit conflicting-role
set, receive no program credit, and reconcile to role-scoped conflict findings in embedded reports.
Approval timestamps are also compared deterministically with the sealed program's creation time.
A record that predates the program remains declared and actionable but is excluded from validated
and credited totals; verification intentionally does not depend on the host's current clock.
Completed external evidence reports verified, credited, and exact-duplicate claim counts. Credit
identity hashes the content-addressed artifact, technique, status, normalized subjects,
producer/reviewer identities, and metrics. Repeating one semantic claim under another ID is an
evidence-domain error and cannot inflate relationship support or evidence totals. Malformed
evidence reference arrays also disqualify that record directly in the evidence domain.
Direct program-verdict JSON, Markdown, and HTML render/export APIs apply this contract before
destination inspection. JSON stages are strictly parsed and semantically matched to the requested
verdict, Markdown stages are exact-byte matched, and HTML stages retain full report verification.
The derived verdict uses a projection-scaled 1,500,000-node read budget under its existing byte
ceilings; the assurance-program input remains limited to 500,000 nodes.

## Offline review-package use

Current `sfmea package` directory and ZIP outputs embed `schema-catalog.json` and the complete
public schema set under their stable catalog filenames. The package manifest checksums every file and
binds the catalog format, path, canonical digest, and schema count. `sfmea verify-package`
additionally cross-checks catalog completeness, schema identities, and each canonical digest.
This lets a recipient validate public structures while disconnected and retain the exact
contracts beside the governed evidence. Verification accepts a regular directory or ZIP root only;
final symbolic links and linked directory entries are rejected rather than resolved.

The review-package verification contract optionally defines package-publication state for
`package --json` receipts. Status is `published` or `not_published`; phase is one of
`analysis_load`, `generation`, `complete`, or `post_publication_verification`. Standalone
`verify-package --json` verdicts omit this receipt-only field.
Every verdict requires `verifier.name` and `verifier.version`, so stored receipts retain the exact
implementation provenance even when package creation fails before an artifact exists. Failure
findings use stable rule IDs and path-safe messages. Not-published receipts also require
`publication.failure_code`, the canonical `publication.failure_rule_id`, and
`publication.catalog_format`. `publication.catalog_sha256` is the exact catalog content address;
consumers should branch on those bounded identities and
`publication.phase` rather than parsing human text or traversing findings. The schema limits
failure codes by phase, requires the exact rule identity and a matching error-level finding, and
prohibits failure identity metadata on published receipts.
Every not-published receipt also requires a catalog-defined `publication.next_action`. Runtime
classification and schema generation share the same immutable, self-validating catalog, and the
schema binds the exact action to its failure code while prohibiting actions on published receipts.
The companion `publication.retry_policy` is `after_remediation` or `manual_diagnostics`; it
prevents clients from interpreting a structured failure as permission for an immediate blind
retry. Policy is bound to the failure code and prohibited on published receipts.
The catalog format, catalog digest, rule identity, code, phase, action, and retry policy are
constrained as one catalog-defined tuple, preventing a producer from composing individually valid
but contradictory remediation metadata. The catalog's `content_sha256` is computed over the
canonical JSON object with that field removed, using sorted keys, compact separators, retained
Unicode text, and UTF-8 bytes. It must equal every receipt's `publication.catalog_sha256`.
The catalog declares `algorithm: sha256` and
`canonicalization: json-sort-keys-compact-utf8`; receipts bind the same declarations through
`catalog_algorithm` and `catalog_canonicalization`. These fields are part of the hashed catalog
content and are prohibited on published receipts with the rest of the failure-only tuple.
Cross-field constraints require successful receipts to be `published/complete`, not-published
receipts to be invalid with zero checked files and an input/generation phase, and
post-publication rejection to be invalid and explicitly published. Contradictory producer claims
therefore fail schema validation.
Universal verdict invariants additionally require valid results to have at least one checked file
and zero errors, and invalid results to have at least one error. These checks apply equally to
standalone verification and package-publication receipts.
Successful verdicts also require a lowercase SHA-256 content address for the exact manifest bytes
used during verification. Successful ZIP verdicts require both `manifest_sha256` and
`archive_sha256`, allowing detached receipts to bind the logical package file set and its exact
transport container. Count/finding presence constraints reject error or warning counts without a
matching finding level, and reject findings whose level is reported with a zero count.

New packages also include `assurance-work.json`. Package verification applies the embedded
work-queue contract, checks its canonical digest, and reconciles the complete deterministic
projection with packaged `analysis.json`. The JSON verdict exposes this nested verification as
`assurance_work_queue`. Packages produced before 0.47 may omit the focused artifact; current
exporter or analysis-generator provenance requires it.

Standalone work-queue verification first applies a strict 100 MiB, 100-level, 1,000,000-node
ingestion boundary. The source must remain the same regular non-symbolic-link file from inspection
through consumption; duplicate keys, non-finite values, numeric overflow, malformed UTF-8, and
structure exhaustion are rejected before schema, digest, binding, or projection evaluation.

Current manifests declare the closed capabilities `analysis_diagnostics_projection_v1`,
`assurance_register_projection`, `assurance_work_queue_projection`,
`evidence_catalog_projection_v1`, `guidance_traceability_projection_v1`,
`interchange_artifacts_projection_v1`, `package_provenance_projection_v1`,
`review_views_projection_v1`, and `sfta_projection_v1`. Current provenance requires all nine,
while legacy manifests may omit
capabilities introduced after their producer version.
The manifest schema describes the identifiers and `verify-package` enforces
version/capability/artifact consistency. Diagnostic verification regenerates summary,
validation, context, repository-inventory, and adapter-ledger views from packaged analysis.
Every readable packaged analysis also receives an `analysis_structure` verdict before hashing or
projection work. The verdict reports the observed iterative node/depth traversal against the
5,000,000-node and 100-level availability limits plus a `core_contract` check for the object,
array, and object-collection types consumed by semantic projectors. Failed content is withheld
from projection and produces bounded path-specific errors. This is verifier policy rather than a
package capability, so historical packages receive the same protection without changing their
declarations; passing it is not represented as complete analysis-schema validation.
Known malformed fields receive path-specific contract errors. An unforeseen exception beyond
that contract is converted to the same stable verdict envelope with the sanitized
`package.semantic_verification_aborted` rule; integrations never need to parse a traceback.
Guidance verification regenerates the complete trace and standalone citation catalog and checks
that the two artifacts agree.
SFTA verification regenerates the complete top-down model and flat gap register and reconciles
their gap counts.
Evidence verification reconciles the catalog baseline and its execution and evidence-artifact
inventories with packaged analysis.
Interchange verification regenerates SARIF and CycloneDX content and checks their shared
analysis-baseline identity. Embedded tool metadata is regenerated with the manifest's declared
producer version so a newer verifier does not reject an otherwise compatible older package.
Review-view verification regenerates ten human-facing worksheet, system, audit, guidance, and
assurance exports and compares canonical UTF-8 text in an isolated temporary workspace. Exact
transferred bytes remain independently checked by the outer manifest.
Package-provenance verification regenerates the package-time audit manifest and reviewer README,
then reconciles audit/package timestamps and audit/package/analysis baselines.
Register verification regenerates deterministic content, checks the embedded queue, and
reconciles it with the standalone queue. The package-verdict schema defines all nine nested
projection-verifier envelopes. For ZIP inputs, nested queue paths use the stable
`PACKAGE.zip!/assurance-work.json` notation.

Older `pysfmea-review-package-1` artifacts without schemas remain supported. Schema contracts
are an additive extension: when declared or present, the complete set is required and partial
bundles are invalid.

The verifier also recognizes the complete four-contract 0.37, six-contract 0.38,
eight-contract 0.39, nine-contract 0.40–0.42, ten-contract 0.43–0.44, and eleven-contract
0.45 catalog profiles.
Their catalog identities and declared content digests are verified using the same rules as the
former twelve-, thirteen-, fourteen-, and fifteen-contract profiles plus the current
sixteen-contract and current eighteen-contract profiles.
Mixing profile generations,
dropping one contract, duplicating a catalog name, or introducing an unknown contract remains
invalid.

Every package-verifier result includes the independent
`pysfmea-review-package-verification-1` discriminator. Its `format` field continues to report
the format discovered in the package itself and can therefore be empty on early rejection.
This separation lets automation identify the verdict contract without mistaking an invalid or
missing artifact for a different response type.

The distribution chain is self-describing: `pysfmea-schema-catalog.schema.json` validates the
schema catalog structure, `pysfmea-schema-bundle-verification.schema.json` validates accepted and
rejected schema-set verdicts, and
`pysfmea-publication-failure-catalog-verification.schema.json` validates accepted and rejected
publication-taxonomy verdicts. Digest reconciliation, complete-file-set enforcement, and unique
catalog names remain semantic checks performed by PySFMEA.

`pysfmea-detached-signature.schema.json` checks the closed signature envelope, Ed25519
algorithm declaration, signed package-subject fields, SHA-256 fingerprint syntax, and exact
64-byte signature encoding. Only `sfmea verify-package --signature ... --public-key ...`
performs cryptographic verification and reconciles that subject with the supplied package.
Key and signature files are regular, non-symbolic-link inputs consumed under one-megabyte
limits with inspected/opened/final identity reconciliation. Envelopes require strict
duplicate-free finite UTF-8 JSON under 20-level/10,000-node limits. Verification freshly
validates the package, rereads and strictly decodes its manifest under a
10 MB/100-level/250,000-node limit, and rejects stale verdicts or changed manifest bytes before
cryptographic verification. Exact ZIP bytes are additionally rehashed
under a 550 MB identity-checked streaming boundary and reconciled to the fresh verdict.

`pysfmea-workflow-status.schema.json` checks the complete top-level status envelope, known
lifecycle stages, required gate/action fields, status vocabulary, counts, bounds, configured
paths, and the disclosed analysis-selection method. The selection contract distinguishes explicit,
standard-location, latest-timestamped-artifact, bounded-timestamped-artifact, and default-missing
discovery, plus explicit unsafe-link outcomes that preserve final path identity; timestamped candidate counts are bounded to 1,000. Generate the payload with `sfmea status REPOSITORY --json`. JSON
Schema also validates optional `paths.artifact_selection`, which records whether each HTML report,
PDF report, and review package was conventionally discovered or selected with the status command's
explicit artifact path. JSON Schema validates structure; PySFMEA's workflow implementation supplies the semantic relationships between summary counts,
`ready_for_handoff`, gate states, and remediation action IDs.

`pysfmea-assurance-work-queue.schema.json` checks the focused
`sfmea assurance ANALYSIS --format work-json` artifact. It closes the work-state and
next-action vocabularies, requires provenance, analysis binding, and canonical content-integrity
metadata, and bounds blockers and identifiers. The companion verifier schema covers stable
success, mismatch, and rejection envelopes from `sfmea assurance-work-verify --json`.
PySFMEA remains responsible for semantic count reconciliation, lifecycle ordering, and deciding when implementation or
controlled execution is eligible.

## Structural and semantic validation

JSON Schema checks structure: required fields, types, identifier syntax, array and text bounds,
enumerations, format constants, and the closed canonical diagram vocabulary. It cannot by
itself establish all governed semantics.

Use the corresponding PySFMEA verifier to check:

- canonical content and whole-document digests;
- unique diagram and node identities;
- edge references to existing nodes;
- downgrade protection;
- baseline, analysis-schema, and exact analysis-state binding.

```powershell
sfmea diagram-verify diagrams.json --analysis sfmea-analysis.json --json
sfmea report sfmea-analysis.json -o sfmea-report.html --json
sfmea report-verify sfmea-report.html --analysis sfmea-analysis.json --json
```

`report --json` emits the same `html-report-verification` contract with exact analysis binding
required, but publication is transactional: generation and verification use a private sibling and
the destination is atomically replaced only after a valid verdict. Its optional `publication`
object distinguishes `published/complete` from `not_published` input-validation, analysis-load,
generation, verification, and publication phases. It also records whether the destination existed
at command start and whether that prior artifact was preserved. Schema conditionals reject a
published invalid receipt, a not-published valid receipt, incompatible phases, and false
preservation claims for published output. All structured-mode failures remain schema-valid and
sanitized on stdout with a nonzero status. Standalone `report-verify` retains optional binding
semantics and omits generation-only publication state.
The report destination itself must be absent or an existing regular file. Direct symbolic links,
directories, other non-regular objects, and the analysis input are rejected in the
`input_validation` phase without following or altering them.
Optional engineering notes must be regular, non-symbolic-link UTF-8 input and are read with a
two-megabyte consumption-time bound. Newlines are canonicalized after decoding. Notes failures
occur during `generation`, never publish the staged artifact, and preserve a prior destination.

Schema validity does not authenticate an author, approve an analysis, demonstrate control
effectiveness, or accept residual risk.

Every current `html-report-verification`, `assurance-program-report-verification`,
`diagram-bundle-verification`, and `assurance-work-queue-verification` result carries
`verifier.name: PySFMEA` and the exact package
version that issued the verdict. Their shared public envelope defines the verifier object as a
closed name/version record. It is intentionally optional in the v1 schemas to preserve validation
of genuine historical verdicts, but current producers populate it on both successful and rejected
paths. Diagram-file verification and custom-diagram import both enforce the same byte limit on the
bytes consumed from a regular, non-symbolic-link stream rather than trusting a separate pre-read
file-size observation.

## Compatibility policy

Schema catalog names and URN major versions identify compatibility boundaries. Additive
diagnostic properties may appear in verifier verdicts because their schemas intentionally allow
format-specific extensions. The required verdict envelope and named checks remain stable within
major version 1. A breaking required-field, meaning, type, or closed-vocabulary change requires
a new schema name/URN major version. Catalog SHA-256 values expose every byte-level contract
change, including compatible clarifications.

Versioned programmatic outputs that are not present in the public schema catalog, including the
repository inventory described above, do not inherit this schema-compatibility guarantee. Their
format identifier is still a required consumption boundary; integrations should reject an unknown
major format and tolerate additive fields within a recognized format.

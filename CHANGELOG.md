# Changelog

Notable user-visible changes are recorded here. PySFMEA follows semantic versioning for the
package; public artifact and schema identifiers carry their own explicit compatibility versions.

## 0.59.0 - 2026-08-05

### Executable fault injection and quality ratchets

- Add three governed built-in fault-injection plugins for dependency exceptions/timeouts,
  malformed or degraded return values, and controlled failure/recovery sequences.
- Generate content-bound, non-executable starter plans from assurance obligations; require
  explicit callable/patch/fault/outcome bindings and reject false-pass paths where the injected
  dependency was never exercised.
- Add CLI discovery, plan export, and exact obligation-binding verification while retaining the
  existing approved-sandbox and independent evidence-review boundary.
- Add validated plan completion and deterministic pytest-bridge commands; ready plans now use a
  closed contract, mandatory exact provenance binding, content integrity, denied networking,
  disabled scanner execution, and an approved-sandbox execution marker.
- Support dotted synchronous and asynchronous subjects, controlled failure/recovery sequences,
  per-invocation elapsed-time evidence, and optional minimum/maximum timing oracles.
- Add branch-coverage, strict incremental typing, Hypothesis property tests, focused mutation,
  critical-module coverage ratchets, Bandit source scanning, dependency-vulnerability gates,
  CycloneDX dependency SBOM evidence, and automated dependency update checks to CI.
- Replace untrusted JUnit parsing with `defusedxml` and eliminate temporarily world-writable
  evidence staging by running the container with the invoking unprivileged host identity where
  bind-mount ownership is meaningful.
- Extract stable typed interfaces, deterministic assurance-planning policy, and pure sandbox
  command policy from the largest orchestration modules.
- Preserve structured static call sites with lexical control context and await state; label
  ambiguous internal resolution and unresolved external-interface candidates by confidence in
  sequence and canonical interface projections.
- Add conservative annotation-, import-, and constructor-assignment-aware receiver resolution,
  retain its provenance, preserve nested Python call evaluation order, and exercise a real
  internal cascade in the golden corpus.
- Record valid, unavailable, and invalid runtime timing explicitly on imported spans and edges,
  with a 90% runtime-module coverage ratchet and focused mutation targets.
- Reconcile bounded static and observed sequence relations in JSON, Mermaid, canonical diagrams,
  and HTML while explicitly distinguishing corroboration from reachability or causal proof.
- Separate direct guidance coverage from supporting/contextual citation coverage in traceability
  JSON and HTML, including each finding's strongest relationship and rules lacking direct support.
- Add the current FAA AC 450.141-1A Appendix B.1.2/Table B-1 taxonomy locator and direct
  commercial-space mappings for functional, calculation, data, interface, logic, and timing
  SFMEA screening; retain AC 20-115D lifecycle mappings as contextual.
- Add per-mapping governance records and digests, locator-summary digests, integrity metrics, and
  an explicit distinction between maintainer curation and independent regulatory approval.
- Expand the checked-in golden repository to 75 source-aware cases across framework-style routes,
  tasks, async behavior, data models, control flow, typed receivers, nested-call order, and an
  internal cascade while retaining the independent-validation
  limitation.
- Add eight exhaustive call-resolution labels with overall and per-provenance precision/recall;
  exact line/order, await-state, and control-context identity prevents repeated call sites from
  collapsing, and missing or unexpected labeled calls now fail `sfmea evaluate`.
- Add closed runtime instrumentation manifests and expected-versus-observed coverage for scenario,
  producer, clock, sampling, dropped-span, expected-component, and expected parent-child
  relationship declarations.
- Add source-revision-bound organizational mapping reviews with content digests, distinct named
  producer/reviewer identities, approval/rejection decisions, authority, expiry, rationale, and a
  deterministic effective-approval audit against the persisted analysis timestamp.
- Add bounded utilities for scanner performance evidence, clean-result validation-cohort records,
  separately gated failure-mode/call-resolution cohort metrics, and content-addressed independently
  labeled LLM quality metrics.
- Verify scan-manifest and resolved-input digests during normal validation, cross-bind every
  reproducibility claim to the governed analysis, retain explicit portable-root handling, and
  expose the verdict in HTML. Rehashed false input, baseline, timestamp, guidance, adapter, or
  static-execution claims now remain invalid outside package verification too. The shared
  integrity module is enforced by strict typing and a 95% branch-coverage ratchet.
- Grant organizational mapping-review approval credit only when the persisted scan timestamp is
  protected by valid manifest content and timestamp bindings.
- Preserve expected-side and actual-side match counts, verifier version, and the canonical
  evaluation-result digest in converted validation cohorts; admit imperfect but structurally
  reconciled measurements, support explicit
  count-backed-cohort policy, and gate/report micro-averaged failure-mode and call-resolution
  recall/precision alongside legacy-compatible macro metrics.
- Bind converted cohorts to the retained evaluation JSON by exact byte digest and program-relative
  artifact reference. Program verification consumes that artifact through bounded,
  identity-stable strict JSON ingestion and cross-checks its canonical digest, corpus, verifier,
  counts, rates, missing/unexpected cases, and call-resolution projection before granting credit.
- Preserve LLM decision and claim counts, bind the retained labeled corpus by exact bytes, and
  replay its closed sample contract during program verification. Unsupported-claim aggregation now
  uses total claims rather than sample-count weighting, with explicit legacy aggregation status.
- Add `pysfmea-llm-quality-corpus-2` with an exact provider/model/prompt subject. Converter and
  program verification reject subject substitution; version-1 corpora remain replayable but cannot
  satisfy the new default subject-binding gate.
- Reject duplicate validation and LLM corpus declarations even when they use different record IDs.
  Program metrics, repository coverage, cases, samples, and claims now credit each validation
  corpus digest once and each replayed LLM semantic fingerprint once. LLM fingerprints ignore
  descriptive metadata, byte formatting, and sample order while retaining subject and decisions;
  verdicts report declared, credited, duplicate, and fingerprinted evidence counts.
- Add a compact visual guide with end-to-end, discovery, cascade, finding-lifecycle,
  evidence-credit, and multi-repository diagrams plus review and output matrices.

## 0.58.0 - 2026-08-05

### Governed system assurance programs

- Add `program-init`, `program-seal`, and `program-verify` for content-addressed,
  multi-repository assurance programs bound to exact governed analyses and baselines.
- Validate cross-repository component relationships, deadlines, timeouts, retries, ordering,
  clock semantics, and observed timing evidence without presenting static topology as causality.
- Add provider-neutral external requirements and evidence records with source/content digests,
  artifact hashes, bounded consumption, subject validation, and producer/reviewer independence.
- Aggregate independently reviewed validation cohorts and configurable recall/precision gates;
  separately aggregate model/prompt-specific grounding, citation, unsupported-claim, and sample
  metrics for optional LLM use.
- Enforce named program approval, required roles, known approval subjects, and independent
  evidence review while leaving authentication, authorization, and legal signature to enterprise
  controls.
- Add self-contained searchable HTML, Markdown, and JSON program-verification reports plus public
  JSON Schema contracts. Current review packages now contain 16 schemas and 44 checked artifacts;
  genuine older schema sets remain verifiable.
- Credit timing and resilience only from completed, digest-verified evidence; failed evidence now
  blocks readiness, while unrun and inconclusive records remain visible without claim credit.
- Add explicit circuit-breaker opening, half-open, and bounded-recovery contracts with
  fault-evidence verification and independent timing/resilience states.
- Require repository-qualified finding/hazard references, timezone-qualified program/source/
  approval timestamps, closed nested records, independent validation/LLM producer-reviewer
  identities, distinct program-level approval authorities for every required role, and unresolved
  required-role rejection blocking.
- Add an accessible bounded repository-topology visual, trusted-evidence accounting,
  timing/resilience tables, report navigation, severity filtering, Markdown escaping, and a
  bounded finding envelope.

## 0.57.65 - 2026-08-05

### Consistent safe inventory accounting across outputs

- Use one repository-inventory summary projection for HTML, coverage JSON/Markdown, system
  inventory Markdown, and human/JSON CLI summaries.
- Add repository files, regions, semantic-analysis depth, opaque/unresolved totals, snapshot
  provenance, and `reconciled`/`recomputed`/`unavailable` state to coverage and inventory views.
- Override stale artifact totals in `sfmea summary` with record-derived values while retaining the
  governed analysis unchanged and keeping validation/handoff errors explicit.
- Version-gate regenerated inventory and coverage review views so current packages require the
  richer accounting while genuine pre-0.57.65 packages remain exactly verifiable.
- Add a concise operator workflow covering timestamped artifacts, scan-to-handoff commands,
  repository-accounting states, executable assurance tests, evidence boundaries, and exact
  artifact verification; document GitHub Actions publishing authorization for contributors.

## 0.57.64 - 2026-08-05

### Reconciled inventory reporting and handoff enforcement

- Centralize safe repository-inventory summary derivation and compared-field policy for validation
  and report projection so the two consumption paths cannot drift, including non-empty semantic
  coverage while preserving historical zero-file `null` compatibility.
- Render only record-derived inventory metrics in self-contained HTML reports; inconsistent stored
  summaries are visibly labeled `recomputed`, while structurally unusable records withhold counts
  as `unavailable` instead of displaying untrusted values.
- Preserve exact governed analysis and validation findings while distinguishing a clean
  `reconciled` summary from repaired presentation data inside report integrity.
- Prove workflow handoff remains blocked by inventory-summary validation errors and provide the
  existing validation remediation command.

## 0.57.63 - 2026-08-05

### Repository provenance validation and reporting polish

- Derive repository inventory summaries through one shared implementation and reconcile file,
  region, status, kind, snapshot-source, and opaque/unresolved counts during quality validation.
- Reject missing or unknown snapshot provenance with bounded, actionable validation findings while
  keeping historical analyses loadable for explicit rescan and repair.
- Explain reused, independently captured, and unavailable snapshots directly in the self-contained
  HTML coverage view and document the programmatic inventory compatibility boundary.
- Refresh documentation navigation, release adapter-version checks, guidance/requirements audit
  identity, and the tool's own SFMEA verification record.

## 0.57.62 - 2026-08-05

### Coverage snapshot and repository-provenance unification

- Load optional coverage JSON before repository baseline construction and reuse the exact accepted
  bytes for coverage attribution, settings provenance, immutable run-manifest binding, and
  in-repository inventory hashing.
- Prevent a coverage path replacement after normalization from making component line/branch
  evidence describe different bytes than repository coverage or the baseline identity.
- Preserve semantically partial coverage snapshots as content-addressed repository evidence while
  retaining explicit unsafe-path, malformed-record, and duplicate-path warnings.
- Keep external coverage inputs outside repository artifact accounting while retaining their exact
  byte count and SHA-256 in scan settings and the run manifest.
- Expose `coverage_evidence_snapshot` through inventory entries, summary counts, and the HTML
  provenance visual; upgrade repository discoverer provenance to v6 and coverage.py JSON evidence
  provenance to v2 with replacement, external-boundary, zero-reread, wheel, and compatibility tests.

## 0.57.61 - 2026-08-05

### Unified supporting-evidence snapshots

- Publish accepted dependency-manifest and interface-contract byte snapshots into the scan-local
  repository evidence registry and reuse them for repository inventory size/digest evidence.
- Prevent a dependency or contract path replacement after parsing from making repository coverage
  describe different bytes than the manifest claims, extracted operations/data types, baseline,
  or immutable run manifest.
- Expose `dependency_manifest_snapshot` and `interface_contract_snapshot` provenance through each
  inventory entry, summary counts, and the self-contained HTML snapshot-provenance visualization.
- Preserve all existing dependency/contract per-file, discovery, aggregate, structure, semantic,
  link, containment, and identity limits without adding repository reads.
- Upgrade repository discoverer provenance to v5, dependency inventory to v4, and local contract
  analysis to v3; add replacement-race, zero-reread, provenance, installed-wheel, and historical
  package compatibility regressions.

## 0.57.60 - 2026-08-05

### Run-bound single-snapshot test evidence

- Capture each eligible textual test-evidence file once before baseline construction and reuse the
  same immutable bytes for PEP 263 decoding, component test-reference attribution, and repository
  inventory hashing.
- Record accepted/rejected test-evidence counts, accepted bytes, and a canonical snapshot-set
  SHA-256 in the repository baseline; bind that digest into the immutable run manifest and overall
  source baseline identity.
- Apply configured and hidden/default directory exclusions consistently to test-reference indexing,
  and expose outside-repository, link/non-file, identity-race, file-limit, and aggregate-limit
  rejection as bounded evidence rather than silent omission.
- Add inventory snapshot-source summary counts and a dedicated provenance visualization to the
  self-contained HTML coverage view.
- Upgrade repository-discoverer capability provenance to v4 and add replacement-race, zero-reread,
  exclusion-scope, manifest-binding, visual-report, installed-wheel, and historical-package tests.

## 0.57.59 - 2026-08-05

### Identity-stable repository inventory

- Reuse each accepted Python analysis snapshot for repository-inventory size and digest evidence,
  preventing a later path replacement from making the inventory describe different source bytes
  than the AST findings and source-snapshot baseline.
- Route every other hashed artifact through the shared regular-file, non-link,
  inspected/opened/final identity-stable boundary while preserving the 20 MB per-artifact and
  500 MB aggregate consumption budgets.
- Expose `snapshot_source` on every inventory entry so consumers can distinguish reused analysis
  evidence, independent identity-stable inventory evidence, and unavailable snapshots.
- Retain bounded bytes-consumed accounting on rejected snapshots, make identity races explicit
  unresolved evidence, and add source-replacement, zero-reread, artifact-race, installed-wheel,
  and historical-package compatibility regressions.
- Upgrade repository-discoverer capability provenance to v3.

## 0.57.58 - 2026-08-05

### Single-snapshot Python source analysis

- Route Python source and textual test evidence through the shared exact-byte, regular-file,
  non-link, inspected/opened/final identity-stable ingestion boundary.
- Capture each selected source once and reuse those immutable bytes for PEP 263 decoding, AST
  parsing, included-test indexing, and repository baseline hashing, preventing a concurrent edit
  from binding findings to a different source baseline.
- Record accepted/rejected source counts, total accepted bytes, and a canonical source-snapshot-set
  SHA-256 in the baseline and bind that digest into the immutable run manifest.
- Preserve explicit warnings and digest-bound rejected records when a source cannot be safely read;
  syntax or encoding failures remain distinct from file-identity failures.
- Upgrade AST parser capability provenance to v2 and add exact-read-count, identity-race,
  provenance, encoding, limit, installed-wheel, and historical-package regressions.

## 0.57.57 - 2026-08-05

### Exact-snapshot dependency manifest provenance

- Route pyproject, requirements/constraints include chains, and supported lockfiles through the
  shared exact-byte, regular-file, non-link, inspected/opened/final identity-stable boundary.
- Preserve the existing conservative contract: supported declarations are parsed only where their
  format is explicitly understood, while opaque lockfile formats remain content-addressed evidence
  rather than sources of speculative dependency claims.
- Add explicit `evidence_type`, accepted byte count, and SHA-256 fields to every manifest inventory
  record while retaining the compatible `sha256:` specification representation.
- Bind the richer inventory into the repository baseline, dependency component fingerprint,
  immutable run manifest, and v3 dependency-adapter provenance ledger.
- Add exact-provenance, recursive-include, per-file/aggregate limit, identity-replacement,
  revalidation, and installed-wheel regressions.

## 0.57.56 - 2026-08-05

### Strict custom-diagram provenance and import budgets

- Route custom report diagrams and standalone diagram-bundle verification through the shared
  exact-byte, regular-file, non-link, inspected/opened/final identity-stable JSON boundary.
- Reject duplicate keys, `NaN`/`Infinity`, numeric overflow, malformed UTF-8, and excessive JSON
  structure under explicit 5 MB/100-level/250,000-node per-file limits.
- Bound each report invocation to 50 custom diagram files and 25 MB of accepted source bytes in
  addition to the existing 50-diagram, 2,000-node, and 5,000-edge model limits.
- Attach the exact accepted source byte count and SHA-256 to every imported diagram so the report's
  integrity-protected visual narrative remains attributable to one file snapshot.
- Add ambiguity, numeric-overflow, structure, identity-replacement, file-count, aggregate-byte,
  provenance, and installed-wheel regression coverage.

## 0.57.55 - 2026-08-05

### Identity-stable interface-contract evidence

- Extract a reusable exact-byte bounded file snapshot boundary that rejects links/non-files and
  reconciles inspected, opened, and final file identity before returning accepted bytes.
- Route OpenAPI, JSON Schema, YAML, and protobuf contract evidence through that shared boundary
  before it can create contract components or compatibility failure modes.
- Strictly decode JSON contracts with duplicate-key and non-finite-number rejection plus explicit
  100-level/1,000,000-node limits while retaining malformed contracts as visible, unparsed
  inventory records with deterministic warnings.
- Record the accepted byte count beside each contract SHA-256; the complete contract inventory,
  including this provenance, remains bound into the immutable run manifest.
- Add exact-snapshot, byte-limit, ambiguity, numeric-overflow, structure-exhaustion,
  identity-replacement, and provenance regressions.

## 0.57.54 - 2026-08-05

### Exact-byte coverage evidence provenance

- Route coverage.py JSON through the shared exact-byte, regular-file, non-link,
  inspected/opened/final identity-stable ingestion boundary before line or branch evidence can
  influence a component.
- Reject duplicate object keys, non-finite or overflowed numbers, malformed UTF-8, and excessive
  JSON depth or node count under explicit 100 MB/100-level/2,000,000-node limits.
- Bound file-record traversal to 100,000 entries and path processing to 4,096 characters while
  preserving aggregate warnings for unsafe paths, malformed coordinates, and normalized aliases.
- Record the exact accepted coverage byte count, SHA-256 digest, supplied file count, and accepted
  file count in scan settings, and bind that digest into the immutable run manifest.
- Add adversarial coverage ambiguity, overflow, structure, identity-race, file/path-limit, and
  end-to-end provenance regressions while retaining compatible historical package verification.

## 0.57.53 - 2026-08-05

### Strict guidance and runtime-evidence provenance

- Add an exact-byte governed JSON document result so callers can decode, validate, hash, and retain
  provenance from one inspected/opened/final identity-stable file snapshot without a second read.
- Route organizational guidance packs through a 5 MB/100-level/250,000-node strict boundary before
  source, locator, applicability, or rule-mapping data can influence finding citations.
- Route simple and OTLP runtime traces through a 100 MB/100-level/2,000,000-node strict boundary
  before observed spans, cascade edges, timing fields, history, or summary state are derived.
- Reject duplicate keys, `NaN`/`Infinity`, finite-syntax numeric overflow, links/non-files,
  concurrent replacement, and decoded-structure exhaustion while preserving exact accepted-byte
  provenance hashes and transactional runtime rollback.
- Add adversarial guidance/runtime regressions and a maintained tool-SFMEA runtime-evidence failure
  mode covering incomplete, ambiguous, stale, or hostile observations.

## 0.57.52 - 2026-08-05

### Identity-stable strict signature verification

- Add a reusable strict decoder for already-captured JSON bytes, giving ZIP members and other
  bounded streams the same duplicate-key, finite-number, UTF-8, depth, and node rules as files.
- Strictly decode detached signature envelopes under a 1 MB/20-level/10,000-node boundary before
  envelope validation, canonicalization, key comparison, or Ed25519 verification.
- Strictly decode the independently reread signed package manifest under its existing 10 MB limit
  plus a 100-level/250,000-node structure boundary before constructing the signed subject.
- Reconcile inspected, opened, and final identities for private keys, public keys, detached
  signatures, and directory manifests, preventing path replacement during bounded consumption.
- Isolate signing file-identity comparisons from unrelated verifier fault injection and add
  duplicate/non-finite/overflow, structure-limit, signature-race, and public-key-race regressions.

## 0.57.51 - 2026-08-05

### Strict assurance and execution evidence ingestion

- Route assurance work queues, scaffold manifests, retirement records, imported execution-evidence
  manifests, and recorded execution manifests through the shared bounded, identity-stable JSON
  boundary before lifecycle, integrity, baseline, or artifact decisions are made.
- Reject duplicate object keys, `NaN`/`Infinity`, and finite-syntax numeric overflow such as
  `1e9999`, preventing ambiguous or platform-dependent evidence from changing assurance status.
- Apply explicit 100-level and caller-scaled node ceilings before canonical hashing or deterministic
  projection, while retaining existing byte limits and transactional evidence-import rollback.
- Harden each generated standalone pytest scaffold with its own strict JSON decoder and iterative
  structure guard, so exported tests fail collection safely without importing PySFMEA.
- Add adversarial queue, scaffold, and execution-evidence tests for ambiguity, numeric overflow,
  structure exhaustion, inspected/opened/final identity changes, and link refusal.

## 0.57.50 - 2026-08-05

### Strict identity-stable governed JSON verification

- Add one reusable governed-JSON ingestion boundary with regular non-link enforcement, bounded
  binary consumption, inspected/opened/final identity reconciliation, and strict UTF-8 decoding.
- Reject duplicate object keys and non-finite `NaN`/`Infinity` values before semantic validation
  or canonical hashing so ambiguous JSON cannot be normalized into an apparently valid artifact.
- Apply iterative decoded-structure limits with caller-selected depth/node ceilings, preventing
  deeply nested or high-cardinality inputs from reaching recursive digest and projection logic.
- Route public failure-catalog file verification through a 1 MB, 50-level, 100,000-node boundary
  while retaining schema-valid structured rejection verdicts and stable source identity.
- Route every allowed offline schema-bundle file through a 2 MB, 100-level, 250,000-node boundary
  before root-object, identity, catalog, and canonical-digest reconciliation.
- Add exact UTF-8 round-trip, byte/depth/node, duplicate/non-finite, non-file/link, safe-open/final
  identity, catalog CLI, and schema-bundle regression coverage.

## 0.57.49 - 2026-08-05

### Race-safe assurance and contract publication

- Route executable assurance-register JSON/CSV/Markdown and focused work-queue JSON through the
  shared bounded, final-link-safe, prior-preserving single-file publisher.
- Preserve the exact UTF-8-BOM assurance CSV contract while refusing non-file destinations,
  synchronizing staging bytes, and cleaning residue after a rejected atomic replacement.
- Move individual offline JSON Schema exports onto the same publication boundary without changing
  schema identity, canonical content, CLI behavior, or schema-bundle directory semantics.
- Add an opaque retained-destination state so a caller can validate an existing or absent output
  and require that exact state at staging and atomic replacement boundaries.
- Apply retained-state publication to the public failure catalog, preserving its refusal to
  replace unknown files and preventing a newly appeared or concurrently edited destination from
  being overwritten after catalog-envelope validation.
- Add assurance, schema, prior-preservation, exact BOM, non-file, replacement-failure, cleanup,
  and absent-to-present destination-race regressions.

## 0.57.48 - 2026-08-05

### Uniform bounded artifact publication

- Add one reusable 256 MiB single-file publication boundary that preserves final-path identity,
  rejects symbolic-link and non-file destinations, stages beside the destination, flushes and
  synchronizes bytes, and refuses a concurrently changed destination before atomic replacement.
- Route CSV/Markdown worksheets, inventory/audit/guidance views, architecture/sequence/
  traceability/coverage exports, SFTA, SARIF/CycloneDX JSON, canonical diagram bundles, and the
  self-contained HTML report through the shared prior-preserving publisher.
- Preserve exact format behavior, including UTF-8-BOM spreadsheet exports and portable CSV
  newlines, while bounding the complete encoded artifact before destination preparation.
- Isolate the signing replacement seam so a simulated signature-publication failure cannot
  disable independent package-projection regeneration through a process-wide mock.
- Add adversarial size, link, concurrent-change, failed-replacement, staging-cleanup, and exact
  encoding coverage plus cross-export/package/signing regression tests.

## 0.57.47 - 2026-08-05

### Bounded content-addressed golden-corpus evaluation

- Replace unbounded, link-following CLI evaluation-file reads with a 20 MB consumption boundary
  that requires a regular non-link file and reconciles inspected, opened, consumed, and final
  identity.
- Strictly decode UTF-8 corpus JSON with duplicate-key and non-finite-number rejection plus
  iterative 20-level/500,000-node limits before semantic evaluation.
- Define the `pysfmea-golden-corpus-1` closed contract with bounded metadata, 100,000 cases, 100
  unique scope patterns, exact string fields, supported schema identity, and duplicate-case
  rejection for file and programmatic callers.
- Bound active evaluation candidates at 500,000 and replace repeated corpus/candidate scans with
  source/component/rule indexes while preserving ambiguity refusal and exact-key semantics.
- Emit deterministic `pysfmea-evaluation-result-1` verifier provenance and a canonical corpus
  SHA-256 digest with explicit case/scope counts.
- Register the bounded golden-corpus verifier in the adapter catalog and extend PySFMEA's own tool
  SFMEA with malformed, stale, or adversarial evaluation-baseline failure handling.
- Add malformed UTF-8/JSON, duplicate/non-finite, link/non-file, forced-small byte/depth/node/
  case/candidate, identity-change, closed-contract, CLI, installed-wheel, and historical-package
  compatibility coverage.

## 0.57.46 - 2026-08-05

### Bounded transactional model-assisted discovery

- Bound OpenAI-compatible requests at 3 MB and responses at 10 MB, validate endpoint/model/key
  metadata, and strictly decode outer and nested UTF-8 JSON with duplicate-key and non-finite
  number rejection.
- Apply iterative 50-level/100,000-node response limits to network and custom providers before
  hashing, validation, or governed-state mutation.
- Replace permissive suggestion parsing with an exact output field set, bounded text/list/identity
  values, evidence/citation allowlists, and an explicit 25-suggestion per-component ceiling.
- Bound grounded summary packets and responses through the same provider contract, require exact
  summary fields, and retain the canonical response hash alongside provider and prompt provenance.
- Stage suggestions across every requested component and commit only after all provider responses
  validate, so a later rejection leaves suggestions, history, and summary state unchanged.
- Roll back the complete governed analysis when accepted-suggestion materialization fails after a
  partial mutation, preserving both the proposal and the pre-review worksheet state.
- Publish version-2 LLM adapter capabilities and prompt/evidence/suggestion contract version 3;
  no provider-generated content gains engineering authority or automatic acceptance.
- Add duplicate, request/response size, depth, unknown-field, suggestion-count, multi-packet
  rollback, materialization-rollback, summary-bound, installed-wheel, and historical-package
  compatibility coverage.

## 0.57.45 - 2026-08-05

### Transactional bounded PDF report publication

- Preserve the caller's final PDF path identity and reject symbolic-link, directory, and other
  non-regular destinations without following them to an unintended target.
- Verify browser output through a regular non-link file descriptor, cap both verification and
  publication at 250 MB, and reconcile inspected, opened, consumed, and final source identity.
- Stream the verified renderer snapshot into a random private sibling, flush it to stable storage,
  and independently verify its PDF header, trailer, size, and identity before publication.
- Revalidate an existing or absent destination immediately before atomic replacement so a
  concurrent writer is preserved and reported rather than silently overwritten.
- Preserve the previous PDF and remove private staging residue on invalid/oversized renderer
  output, identity drift, destination races, and atomic replacement failures.
- Reconcile Windows path/descriptor creation-time precision when comparing governed-analysis file
  snapshots, while retaining file identity, exact size, and modification-time checks and the
  stricter metadata-change-time comparison on POSIX.
- Add forced-small size, malformed output, linked/non-file destination, opened-identity,
  destination-race, replacement-failure, installed-wheel, and historical-package compatibility
  coverage without changing the PDF command or report contract.

## 0.57.44 - 2026-08-04

### Bounded transactional governed-analysis persistence

- Replace unbounded `json.load` analysis ingestion with a 100 MB consumption-time binary boundary
  that rejects symbolic links/non-files and reconciles inspected, opened, and final file identity.
- Decode strict UTF-8 JSON with duplicate-key and non-finite-number rejection, then apply a shared
  iterative 100-level/2,000,000-node limit before migrations or derived-state materialization.
- Reuse the same structure primitive in review-package verification so persisted and packaged
  analyses cannot drift onto different JSON-complexity contracts.
- Replace unbounded no-op-save reconciliation and reviewer ETag `read_bytes` hashing with the same
  bounded identity-stable analysis reader/streaming hasher.
- Keep the final analysis path unresolved, reject linked/non-file destinations, serialize UTF-8
  output through the 100 MB limit, and revalidate destination identity and metadata immediately
  before atomic replacement.
- Preserve prior content and remove staging residue on size, destination-race, revision-conflict,
  and replacement failures without changing analysis schema or package formats.
- Add forced-small byte/depth/node/hash/output, invalid-UTF-8/JSON, duplicate/non-finite, link,
  directory, opened-identity, destination-race, replacement-failure, installed-wheel, and
  historical-package compatibility coverage.

## 0.57.43 - 2026-08-04

### Bounded snapshot-safe package authentication

- Replace precheck-only, unbounded private/public key and detached-signature reads with regular-file,
  symbolic-link-safe, consumption-time bounded reads that revalidate inspected/opened identity.
- Parse signature envelopes as strict bounded UTF-8 JSON, bound signer labels and passphrases, and
  return stable key/input failures without exposing cryptography or filesystem exception details.
- Read directory and ZIP manifests through a 10 MB boundary and reconcile their exact byte digest
  with the freshly verified package before constructing or accepting a signed subject.
- Treat caller-supplied package-verification results as advisory and always perform fresh integrity
  verification, preventing stale or fabricated verdicts from authenticating changed package bytes.
- Derive signed manifest digests from the successful verification snapshot and reconcile exact ZIP
  bytes through a 550 MB identity-checked streaming rehash instead of unbounded artifact hashing.
- Revalidate signature-destination identity at the publication boundary, atomically replace only
  the inspected destination, preserve prior content on failure/race, and remove staging residue.
- Add forced-small key/signature/manifest/passphrase, invalid-UTF-8, identity-change, stale-verdict,
  replacement-failure, installed-wheel, and historical-package compatibility coverage.

## 0.57.42 - 2026-08-04

### Bounded identity-preserving project configuration

- Replace unbounded `tomllib.load` configuration parsing with a regular-file,
  symbolic-link-safe binary read capped at 5 MB, revalidate inspected/opened file identity before
  consumption, and apply explicit bounded UTF-8 TOML validation.
- Preserve the final path identity of configured coverage JSON and organizational guidance packs
  while normalizing relative paths, so downstream link-safety checks cannot be bypassed by early
  path resolution.
- Return stable configuration read/encoding/size failures without leaking raw filesystem details;
  semantic schema validation remains specific and fail-closed after bounded parsing succeeds.
- Make configuration-template publication final-link-safe and atomic, revalidate destination type
  at the mutation boundary, preserve an existing file on replacement failure, and remove staging
  residue on every rejected publication.
- Add forced-small byte, invalid-UTF-8/TOML, directory/link, downstream-identity, injected atomic
  replacement failure, workflow-status, and installed-package regression coverage.

## 0.57.41 - 2026-08-04

### Consumption-bounded repository inventory hashing

- Replace repository artifact size prechecks plus unbounded `read_bytes` hashing with regular-file
  stream reads capped at 20 MB per artifact and 500 MB actually consumed across the inventory.
- Refuse symbolic links and non-regular filesystem artifacts before opening them, and replace raw
  filesystem exception details with stable unresolved accounting.
- Continue safe metadata and semantic accounting after aggregate hash exhaustion, but add a
  digest-protected unresolved region and set the inventory truncation signal so reports and
  validation cannot present the inventory as complete.
- Bound excluded/opaque directory-region accounting at 100,000 records in addition to the existing
  100,000-file ceiling, while preserving deterministic inventory hashes and status summaries.
- Publish version-2 repository, dependency, and contract adapter descriptors whose capabilities now
  declare the implemented bounded-ingestion and fail-soft semantics.
- Add forced-small per-file/aggregate/region limits, exact-hash, link/non-regular refusal, inventory
  integrity, and installed-package regression coverage without changing inventory schema versions.

## 0.57.40 - 2026-08-04

### Bounded type-safe interface-contract analysis

- Replace interface-contract size prechecks plus unbounded byte reads with regular-file,
  symbolic-link-safe consumption-time reads capped at 20 MB per file, 1,000 discovered files, and
  100 MB in aggregate across OpenAPI/Swagger, JSON Schema, YAML, and protobuf inputs.
- Reject final links, non-files, and resolved repository escapes with stable warnings while
  retaining continued analysis of safe contracts and the rest of the repository.
- Decode contract text as strict UTF-8, handle malformed JSON and unexpected scalar/container
  shapes without tracebacks, and retain the exact accepted-byte digest even when semantic
  extraction is unavailable.
- Bound extracted operations and data types to 500 distinct values per category during traversal,
  emitting explicit truncation evidence instead of building an unbounded intermediate list.
- Add forced-small per-file/discovery/aggregate/entity limits, invalid-UTF-8, scalar-root, link,
  exact-digest, and installed-package regression coverage without changing analysis formats.

## 0.57.39 - 2026-08-04

### Bounded dependency-manifest evidence ingestion

- Replace unbounded and repeated dependency-manifest reads with cached regular-file,
  symbolic-link-safe binary reads capped at 20 MB per file, 1,000 attempted files, and 100 MB in
  aggregate across pyproject, requirements/constraints include chains, and supported lockfiles.
- Hash and parse the exact same accepted bytes so dependency evidence cannot change between a
  manifest digest pass and its semantic extraction pass; resolved aliases reuse one snapshot.
- Normalize included-manifest paths before containment checks, reject final links and repository
  escapes, and stop further ingestion after aggregate exhaustion with stable warnings.
- Decode requirements as strict UTF-8 and validate supported pyproject dependency container shapes,
  retaining the accepted manifest hash while refusing malformed dependency claims.
- Add forced-small byte/file/aggregate limits, link, traversal, invalid-UTF-8, malformed-TOML-shape,
  exact-hash, and continued-analysis regression coverage without changing analysis formats.

## 0.57.38 - 2026-08-04

### Bounded Python source and test-evidence ingestion

- Replace unbounded Python source and test-file text reads with a shared regular-file,
  symbolic-link-safe, consumption-time 20 MB reader that honors PEP 263 encoding declarations.
- Reject in-repository source links consistently with the repository inventory and surface stable
  boundary, size, and encoding warnings without aborting analysis of the remaining repository.
- Cap selected Python source discovery at 100,000 files and the test-reference index at 10,000
  files and 100 MB, reporting the exact limit when deterministic indexing stops.
- Reuse the source byte boundary during repository baseline calculation so a rejected source file
  cannot be consumed unbounded by a later scan phase.
- Add forced-small file/aggregate limits, non-UTF-8 declared encoding, unsupported encoding,
  internal-link, inventory-accounting, and continued-analysis regression coverage.

## 0.57.37 - 2026-08-04

### Bounded path-safe coverage evidence ingestion

- Replace resolved-path plus unbounded coverage JSON loading with a final-link-safe,
  consumption-time 100 MB bounded binary read and explicit UTF-8 JSON object validation.
- Reject repository escapes, parent traversal, empty paths, and duplicate normalized file keys;
  absolute coverage paths are retained only when they resolve beneath the analyzed repository.
- Normalize line and branch evidence to typed coordinates before analysis, retaining coverage.py's
  signed branch destinations while requiring positive source lines, so malformed records cannot
  crash a scan or be mistaken for observed execution.
- Preserve the first valid normalized record and expose aggregate unsafe, malformed, and duplicate
  counts through stable `CoverageError` warnings while the remainder of the scan continues.
- Add forced-small limit, invalid-UTF-8/root/link, path-traversal, duplicate-key, malformed-record,
  and end-to-end scan regression coverage without changing the analysis schema.

## 0.57.36 - 2026-08-04

### Transactional bounded runtime-trace ingestion

- Replace runtime trace resolution plus unbounded byte buffering with a final-link-safe,
  consumption-time 100 MB bounded binary read and explicit UTF-8 JSON root validation.
- Replace permissive recursive span traversal with a type-safe iterative simple/OTLP walker and
  enforce the existing 50,000-span limit before governed state changes.
- Bound nested runtime attribute normalization to 32 levels and validate human labels, malformed
  runtime/history containers, empty traces, and unsupported scalar roots with stable errors.
- Defer all runtime-evidence, history, and summary mutation until normalization and edge derivation
  succeed; restore the complete analysis snapshot if final summary refresh fails.
- Add forced-small byte/span/depth limits, invalid-UTF-8/root/link/label/empty-trace inputs, and
  injected summary-failure rollback coverage without changing runtime evidence record formats.

## 0.57.35 - 2026-08-04

### Transactional bounded external evidence ingestion

- Replace external execution-manifest size prechecks plus unbounded text reads with a regular-file,
  symbolic-link-safe, consumption-time bounded UTF-8 JSON object reader.
- Hash external artifacts under per-file and aggregate consumed-byte limits, then copy and hash each
  stream through an independent bound; reject changed content/size and clean private staging.
- Apply the same bounded, link-safe manifest and artifact verification when managed evidence is
  later adjudicated, preventing review from consuming mutated oversized records.
- Defer imported test registration until evidence validation and publication succeed; roll back the
  complete analysis snapshot and published evidence directory if governed recording fails.
- Add forced-small-limit, invalid-UTF-8, manifest/artifact link, bounded-copy failure, managed-review
  bound, staging cleanup, and analysis/filesystem rollback regression coverage.

## 0.57.34 - 2026-08-04

### Safe standalone scaffold collection

- Replace the generated pytest module's unbounded collection-time manifest text read with a
  self-contained 64 MiB consumption-time bounded binary read.
- Require a regular non-symbolic-link manifest, decode exact consumed bytes as UTF-8 JSON, and
  reject malformed encoding, excessive nesting, non-object roots, and unsupported scaffold formats
  with stable operator-facing collection failures.
- Preserve canonical manifest integrity verification and additionally require a non-empty,
  object-shaped obligation list before pytest parameterization.
- Add execution-level forced-small-limit, invalid-UTF-8, root-shape, symbolic-link, integrity, and
  obligation-shape regression coverage for the emitted test module.

## 0.57.33 - 2026-08-04

### Race-resistant scaffold lifecycle operations

- Refactor scaffold verification internally to return the exact bounded manifest object whose
  integrity, binding, selection, queue identity, and generated-file state were checked, while
  keeping the public verification response unchanged.
- Carry that verified snapshot into guarded refresh and archive instead of independently consuming
  lifecycle parameters from a later manifest read.
- Revalidate the queue at the publication/mutation boundary and compare its manifest identity with
  the initial snapshot, refusing concurrent replacement even when both manifests are independently
  valid.
- Preserve the original queue and remove staged output on refresh races; leave archive sources and
  retirement state untouched on archive races; add deterministic race-injection regression tests.

## 0.57.32 - 2026-08-04

### Bounded assurance-scaffold verification

- Replace assurance-manifest and retirement-record size prechecks plus unbounded text reads with
  exact consumption-time bounded UTF-8 JSON ingestion across verification, guarded refresh, and
  archival.
- Stream generated pytest/README SHA-256 verification under an independent byte limit instead of
  buffering entire files, while retaining informational treatment of expected implementation edits.
- Require every consumed scaffold artifact to be a regular non-symbolic-link file and detect a
  broken retirement link as an invalid present record rather than silently treating it as absent;
  refresh/archive retain final-path identity and refuse broken-link destinations or records.
- Add forced-small-limit, invalid-UTF-8, oversized generated-file/retirement-record, and
  broken-link-equivalent regression coverage without changing public scaffold formats.

## 0.57.31 - 2026-08-04

### Consumption-bounded offline schema verification

- Replace offline schema-bundle entry size prechecks plus unbounded text reads with one bounded
  binary read per catalog/schema file, closing concurrent-growth bypasses at the public-contract
  verification boundary.
- Explicitly decode bounded bytes as UTF-8 JSON and preserve the existing closed-object and exact
  catalog identity/digest reconciliation after safe ingestion.
- Keep missing, malformed, oversized, symbolic-link, and non-file entries as schema-valid
  `schema-bundle-verification` rejections with stable file-level error locations.
- Add default-limit, forced-small-limit, invalid-UTF-8, mocked/real symbolic-link, public-schema,
  and atomic export regression coverage without changing bundle contents or profile counts.

## 0.57.30 - 2026-08-04

### Hardened organizational guidance ingestion

- Replace organizational-guidance size prechecks plus unbounded byte reads with one
  consumption-time bounded read, preventing concurrent growth from bypassing the five-megabyte
  trust boundary used by citation discovery.
- Require every configured pack to be a regular non-symbolic-link file and explicitly decode it as
  UTF-8 JSON before schema, locator, applicability, and mapping validation.
- Continue hashing the exact bytes that passed bounded ingestion so pack provenance remains bound
  to the content actually used to generate finding citations and package projections.
- Add directory, invalid-UTF-8, oversized, mocked/real symbolic-link, exact-byte-count, and digest
  regression coverage without changing the organizational pack schema.

## 0.57.29 - 2026-08-04

### Bounded, link-safe engineering notes

- Replace report-notes size prechecks plus unbounded text reads with one consumption-time bounded
  binary read, closing concurrent-growth bypasses for both HTML and PDF report generation.
- Require notes to be a regular non-symbolic-link file and valid UTF-8 before any report content is
  built; missing, directory, linked, malformed, and oversized inputs fail closed.
- Preserve universal newline semantics by canonicalizing CRLF and CR notes to LF after decoding,
  keeping report content stable and portable across producer platforms.
- Keep JSON report publication transactional for real notes-input failures: return a sanitized
  schema-valid generation rejection, remove staging residue, and preserve any prior report.
- Add regular, non-regular, invalid-encoding, oversized, symbolic-link, canonical-newline, and
  prior-destination regression coverage.

## 0.57.28 - 2026-08-04

### Safe report destinations and unified bounded diagram ingestion

- Refuse symbolic-link and non-regular HTML report destinations before loading or generation in
  both human and JSON modes, preserving the link, its target, directories, and governed analysis.
- Keep the final report path unresolved during atomic replacement so a link can never redirect the
  verified staged artifact to a different file; a link introduced after validation is replaced as
  a directory entry rather than followed.
- Make structured destination rejections use the existing schema-valid
  `report.invalid_destination` receipt with explicit input-validation and prior-preservation state.
- Unify diagram verification and custom report-diagram imports on one symbolic-link-safe,
  consumption-bounded binary JSON reader, closing the remaining precheck/unbounded-read path.
- Add directory, symbolic-link target-preservation, human/JSON behavior, oversized import, and
  diagram-link regression coverage.

## 0.57.27 - 2026-08-04

### Attributable verifier receipts and bounded diagram consumption

- Add exact `verifier.name` and `verifier.version` provenance to every current HTML-report,
  diagram-bundle, and assurance-work-queue verification verdict, including structured rejection
  envelopes, so stored CI evidence identifies the implementation that issued it.
- Publish the shared verifier-provenance shape in all three public JSON schemas while retaining
  compatibility with genuine older v1 verdicts that predate the additive field.
- Replace diagram verification's size precheck plus unbounded text read with one bounded binary
  read at consumption time, preventing concurrent file growth from bypassing the availability
  boundary.
- Add success, rejection, public-schema, and oversized-stream regression coverage.

## 0.57.26 - 2026-08-04

### Transactional verified HTML report publication

- Make `sfmea report ANALYSIS --json` generate into a private sibling, verify complete document
  integrity and exact analysis binding there, and atomically publish only after a valid verdict.
- Preserve an existing destination byte-for-byte and remove staging residue when analysis loading,
  generation, verification, or final publication fails.
- Emit schema-valid, sanitized JSON for every structured-mode failure phase, including invalid
  destinations, missing or malformed analysis, generator failures, verifier failures, and atomic
  replacement failures; JSON mode never exposes unexpected exception detail on stderr.
- Add explicit `published/complete` and `not_published` receipt state, phase, prior-destination
  observation, and preservation status with schema constraints that reject contradictory claims.
- Refuse to use the governed analysis JSON itself as the HTML destination.

## 0.57.25 - 2026-08-04

### Verified HTML report generation receipts

- Add `sfmea report ANALYSIS --json` to generate the self-contained HTML report, immediately verify
  its complete document/payload integrity and exact governed-analysis binding, and emit the public
  `html-report-verification` verdict without human progress noise.
- Return nonzero with a schema-valid, sanitized stdout verdict when post-generation verification
  cannot complete; unexpected verifier details are not copied into CI output.
- Replace report verifier size prechecks plus unbounded reads with a single consumption-time
  bounded binary read, closing file-growth races at the availability boundary.
- Preserve existing human report output and standalone `report-verify` behavior.
- Add matched generation-receipt, path binding, injected verifier failure, stderr isolation,
  schema validation, and bounded-read coverage.

## 0.57.24 - 2026-08-04

### Verified export receipts and stronger target recognition

- Make `publication-catalog --output FILE --json` emit the schema-backed catalog-verification
  verdict for the exact exported path, giving CI one atomic export-and-receipt operation.
- Require a forced-refresh target to pass format, integrity-metadata, and complete structural
  envelope checks; a file that merely spoofs the catalog format no longer qualifies.
- Strengthen failure-entry structural checks across closed fields, scalar types, phase arrays,
  uniqueness, and allowed phase vocabulary before exact taxonomy comparison.
- Preserve the ability to repair structurally recognized drifted catalogs whose digest or exact
  content is invalid, while continuing to refuse unrelated or malformed targets.
- Add JSON export-receipt, format-spoofing, malformed nested value, and path-binding coverage.

## 0.57.23 - 2026-08-04

### Atomic publication catalog export

- Add `sfmea publication-catalog --output FILE` for deterministic UTF-8 catalog export without
  shell redirection, including parent-directory creation and atomic sibling replacement.
- Protect existing files by default; `--force` replaces only a regular, recognized publication
  catalog and refuses symbolic links, directories, malformed JSON, and unrelated files.
- Verify staged catalog content before publication, remove temporary residue on failure, and leave
  the previous catalog byte-for-byte unchanged when atomic replacement fails.
- Reject conflicting `--verify`/`--output` modes and `--force` without an output destination.
- Add export, refresh, unrelated-file preservation, option-validation, and injected replacement
  failure coverage.

## 0.57.22 - 2026-08-04

### Bounded publication catalog verification

- Add `sfmea publication-catalog --verify FILE` with concise human output, nonzero rejection
  status, and schema-backed `--json` verdicts for CI and offline evidence capture.
- Verify bounded regular UTF-8 JSON input, format, integrity metadata, structure, canonical digest,
  and exact equality with the taxonomy shipped by the verifier using stable error codes.
- Publish `publication-failure-catalog-verification` as the fourteenth public schema and embed it
  in current review packages, expanding the governed package inventory to 42 files.
- Preserve the former thirteen-schema package profile as an explicit supported compatibility
  generation alongside earlier profiles.
- Add success, drift, and unavailable-input verifier coverage plus exact verdict/schema and
  current/legacy package checks.

## 0.57.21 - 2026-08-04

### Self-describing catalog integrity

- Declare `algorithm: sha256` and `canonicalization: json-sort-keys-compact-utf8` directly in the
  publication failure catalog so consumers can recompute its content address without prose-only
  knowledge.
- Bind failed receipts to the same semantics through `publication.catalog_algorithm` and
  `publication.catalog_canonicalization` alongside the catalog digest.
- Include the integrity semantics in the canonical catalog payload, so changing either declaration
  also changes the content address.
- Prohibit integrity declarations on published receipts and add negative coverage for missing,
  unsupported, and independently altered metadata.

## 0.57.20 - 2026-08-04

### Content-addressed publication taxonomy

- Add a deterministic `content_sha256` to `publication-catalog --json`, computed over the
  canonical catalog document without the digest field.
- Add the matching `publication.catalog_sha256` to every not-published receipt so archived
  results bind to the exact remediation taxonomy rather than only its format family.
- Constrain both digest fields to the catalog derived from the immutable runtime taxonomy and
  expose the digest in human catalog output for operational verification.
- Prohibit catalog digests on published receipts and add negative coverage for missing,
  mismatched, or independently altered digest claims.

## 0.57.19 - 2026-08-04

### Self-identifying publication failure receipts

- Add the canonical `publication.failure_rule_id` directly to every not-published receipt so
  automation can correlate the primary failure with findings without traversing diagnostic text.
- Add `publication.catalog_format` so stored receipts retain the exact taxonomy contract used to
  interpret their code, action, and retry policy.
- Bind catalog format and rule identity to failure code, phase, action, retry policy, and the
  matching error finding in the review-package verification schema.
- Prohibit catalog and failure-rule metadata on successful and post-publication-verification
  receipts, and add negative coverage for missing or mismatched identities.

## 0.57.18 - 2026-08-04

### Explicit publication retry safety

- Add a catalog-defined `publication.retry_policy` to every not-published receipt so orchestration
  can distinguish retry-after-remediation from failures requiring manual diagnostics.
- Classify input, destination, and generation failures as `after_remediation`; classify internal
  failures as `manual_diagnostics` to prevent blind retry loops.
- Bind retry policy exactly to failure code, phase, next action, and stable finding in both the
  receipt schema and publication-failure catalog schema.
- Prohibit retry policy on successful and post-publication-verification receipts.
- Show retry policy in human catalog output and add negative coverage for missing, mismatched, and
  published-state retry claims.

## 0.57.17 - 2026-08-04

### Discoverable publication failure catalog

- Add `sfmea publication-catalog` with concise human output and schema-validated `--json` output
  for failure codes, stable rule IDs, valid phases, safe messages, and remediation actions.
- Publish a new `publication-failure-catalog` JSON Schema and embed the exact catalog as an
  annotation in the review-package verification schema for offline integration discovery.
- Expand current review packages to 13 content-addressed public schemas and 41 verified artifacts.
- Preserve the former 12-schema profile as an explicit supported compatibility generation.
- Add exact catalog-schema coverage, CLI human/JSON coverage, annotation parity, package/archive
  inventory checks, and current/previous profile verification.

## 0.57.16 - 2026-08-04

### Single-source publication remediation contract

- Centralize publication failure code, rule ID, valid phases, path-safe message, and remediation
  action in one immutable catalog shared by runtime classification and JSON Schema generation.
- Add `publication.next_action` to every not-published receipt, giving automation an explicit
  remediation command category without interpreting human text.
- Enforce exact failure-code/phase/next-action/finding relationships and prohibit both failure
  metadata fields on published receipts.
- Validate taxonomy uniqueness, phase membership, rule naming, and remediation completeness at
  module load so future contract drift fails immediately.
- Add schema-catalog parity and negative coverage for mismatched remediation actions and
  published receipts that improperly claim an action.

## 0.57.15 - 2026-08-04

### Enforceable publication failure taxonomy

- Add a first-class `publication.failure_code` to every not-published package receipt so
  automation does not need to traverse findings or parse messages for the primary outcome.
- Constrain analysis-load failures to analysis input categories and generation failures to
  destination/generation categories, with internal failure valid in either phase.
- Require each failure code to have a matching error-level finding with the corresponding stable
  `package.publication.*` rule ID.
- Prohibit `failure_code` on successful and post-publication-verification receipts.
- Add negative schema coverage for published failure claims and failure-code/finding mismatches.

## 0.57.14 - 2026-08-04

### Provenanced, path-safe automation diagnostics

- Add required `verifier` name/version provenance to every package verification and publication
  verdict, including early failures that cannot read an analysis or create an artifact.
- Replace the generic pre-publication failure rule with stable categories for missing, unreadable,
  or invalid analysis input; unavailable destinations; rejected generation; and internal failure.
- Remove raw exception text from JSON publication findings so local paths, operating-system
  details, and sensitive internal messages are not copied into CI logs or orchestration records.
- Preserve remediation value through bounded category-specific messages, publication phase, output
  identity, and nonzero exit status.
- Add schema and CLI coverage for verifier provenance, malformed JSON, permission failures,
  destination conflict, and internal failure redaction.

## 0.57.13 - 2026-08-04

### Content-addressed package receipts

- Add `manifest_sha256` to successful directory and ZIP verification verdicts, binding a
  detached receipt to the exact manifest that commits the complete package file set.
- Define both `manifest_sha256` and `archive_sha256` in the public verification schema; require
  every valid verdict to carry a manifest digest and every valid ZIP verdict to carry its archive
  digest.
- Compute the manifest digest from the same bounded byte snapshot used for JSON parsing, avoiding
  an identity/parsing time-of-check gap.
- Require error and warning counts to agree qualitatively with their finding arrays, rejecting
  zero-count verdicts that contain that finding level and positive-count verdicts that omit it.
- Add digest recomputation and negative schema coverage for missing identities and contradictory
  finding/count claims.

## 0.57.12 - 2026-08-04

### Core verification verdict consistency

- Added universal JSON Schema invariants connecting `valid`, `checked_files`, and the error count
  for package verification and publication receipts.
- Require every valid verdict to report at least one checked file and zero errors.
- Require every invalid verdict to report at least one error, preventing schema-valid rejection
  envelopes that provide no machine-readable failure signal.
- Added isolated negative coverage for error-count and checked-file contradictions while keeping
  publication-state contradiction tests independently coherent.

## 0.57.11 - 2026-08-04

### Publication receipt consistency invariants

- Added JSON Schema cross-field constraints tying receipt validity, checked-file count,
  publication status, and publication phase into one coherent claim.
- Require valid receipts to be `published/complete`.
- Require not-published receipts to be invalid, report zero checked files, and use only the
  `analysis_load` or `generation` phase; require post-publication rejection to be
  invalid and `published/post_publication_verification`.
- Added negative schema coverage for four contradictory receipt combinations while retaining
  valid current receipts and publication-free standalone verifier compatibility.

## 0.57.10 - 2026-08-04

### Explicit package publication state

- Added an optional schema-defined `publication` object to package receipts so automation can
  distinguish `published` from `not_published` without interpreting messages or filesystem state.
- Classify receipt phases as `analysis_load`, `generation`, `complete`, or
  `post_publication_verification`.
- Mark post-publication verification rejection as published-but-invalid, while input and
  generation failures explicitly confirm that no new package was published.
- Added exact phase/state assertions for successful directory/ZIP output, missing input,
  destination conflict, sanitized runtime failure, and injected post-publication rejection.

## 0.57.9 - 2026-08-04

### Always-structured package automation failures

- Extended `sfmea package --json` to emit the public review-package verification envelope when
  publication fails before an artifact exists, instead of switching to plaintext stderr.
- Represent missing analyses, malformed JSON, destination conflicts, filesystem failures, and
  internal publication rejection with `package.publication_failed`, zero checked files, the
  requested container/path, and a remediation-oriented notice.
- Preserve actionable bounded messages for expected input/operational failures while sanitizing
  unexpected `RuntimeError` details.
- Added schema-validation coverage for missing input, existing-destination conflict, sanitized
  runtime failure, successful directory/ZIP receipts, and injected post-publication rejection.

## 0.57.8 - 2026-08-04

### Machine-readable package publication receipt

- Added `sfmea package --json` for directory and ZIP outputs, emitting the stable public
  `pysfmea-review-package-verification-1` verdict after publication.
- Keep JSON mode free of human progress text so CI and orchestration systems can parse exactly
  one schema-backed document without console scraping.
- Return a nonzero status if the post-publication verification receipt is invalid, retaining the
  same structured diagnostic envelope used by `sfmea verify-package --json`.
- Added directory/ZIP CLI coverage that validates each receipt against the published JSON Schema
  and checks container identity, artifact count, capabilities, and resolved package path.

## 0.57.7 - 2026-08-04

### Fail-closed package publication

- Run the independent package verifier against the complete staging directory before any new or
  replacement review package becomes visible at its destination.
- Withhold internally inconsistent generated packages with a concise, bounded list of verifier
  rule IDs instead of publishing artifacts that the same release rejects.
- Preserve an existing package byte-for-byte when a forced refresh fails its internal gate, and
  remove the rejected staging directory without modifying the caller's analysis.
- Added fault-injection coverage for rejection, cleanup, source immutability, and atomic prior-
  destination preservation.

## 0.57.6 - 2026-08-04

### Intuitive review-archive output

- Infer ZIP publication from a case-insensitive `.zip` output suffix, preventing the CLI from
  silently creating a directory whose name looks like an archive.
- Preserve `--zip` for the default archive destination while making it optional when `-o`
  already communicates the requested container type.
- Updated command help and workflow documentation to describe suffix-based dispatch.
- Added an end-to-end CLI regression that creates a `.ZIP` output and independently verifies
  it as a valid ZIP review package.

## 0.57.5 - 2026-08-04

### Frozen package-analysis snapshot

- Materialize deterministic assurance state on the package's deep-copied analysis before the
  first artifact is written, so every projection observes one settled snapshot.
- Repair absent or malformed derived assurance containers during packaging without modifying
  the caller's governed working analysis.
- Keep `analysis.json`, its manifest state digest, the full assurance register, and the focused
  work queue semantically aligned instead of allowing package generation order to create an
  internally invalid package.
- Added regression coverage proving both repaired cases produce verifier-valid packages whose
  declared analysis-state digest exactly matches the packaged analysis.

## 0.57.4 - 2026-08-04

### Total semantic-verifier fault containment

- Extended the early analysis contract to validate resolved project analysis/risk/quality
  configuration, fault-tree references, hazard-link string lists, finding/guidance citation
  identifiers, guidance profile mappings, and projection-critical provenance collections.
- Reuse the production configuration normalizer at the package boundary so malformed scalar
  policy values and fault-tree semantics are rejected before deterministic regeneration.
- Added a final public verifier exception boundary that converts an unforeseen semantic failure
  into a sanitized `package.semantic_verification_aborted` verdict without exposing internal
  exception text or returning a traceback.
- Added targeted leaf-value mutation tests for every previously uncaught path plus a forced
  internal-failure test proving the public JSON verdict remains schema-valid and sanitized.

## 0.57.3 - 2026-08-04

### Fail-closed package analysis contract

- Added a lightweight, backward-compatible core-container contract before package semantic
  projection, covering projection-critical objects, arrays, object collections, finding
  subrecords, runtime evidence, assurance records, fault-tree nodes, and provenance views.
- Invalid but checksum-consistent analysis content is withheld from every projector and returns
  `package.analysis_contract_invalid` plus bounded, path-specific machine-readable errors.
- Prevented uncaught type errors for malformed items, context, project, assurance, SFTA,
  guidance, runtime evidence, summaries, inventory, adapter runs, and system-context content.
- Extended the public `analysis_structure` verdict with an exact `core_contract` check while
  preserving the explicit distinction between availability protection and schema/engineering
  validity.
- Added direct contract-mutation coverage and an end-to-end adversarial package test whose
  checksum and governed-state digest are recomputed after inserting a malformed finding.

## 0.57.2 - 2026-08-04

### Exact SFTA selector semantics

- Corrected ID-only SFTA event selectors so an explicit `finding_ids` list links only those
  active findings instead of treating absent glob selectors as match-all wildcards.
- Defined mixed selector behavior as the union of exact finding IDs and pattern matches, with
  component and failure-mode globs applied conjunctively when both are configured.
- Resolve ID-only correlations through an index without scanning every finding, and reuse that
  index during hazard-link reconciliation to remove avoidable quadratic lookups.
- Replay the historical ID-wildcard behavior across SFTA, validation, and validation-bearing
  worksheet regeneration only when verifying packages that declare a pre-0.57.2 producer,
  preserving genuine older evidence without weakening new projections.
- Added regression coverage for unknown IDs, exact ID-only selection, mixed selector algebra,
  the ID-only fast path, cross-version SFTA/diagnostic verification, and worksheet parity.

## 0.57.1 - 2026-08-04

### Bounded analysis verification

- Added an iterative, machine-readable `analysis_structure` verdict that reports observed JSON
  node count and depth before governed-state hashing or artifact regeneration.
- Reject analysis snapshots above the 100-level or 2,000,000-node verification limits, including
  packages whose analysis checksum and governed-state digest were recomputed after tampering.
- Convert parser recursion failures into stable invalid-package findings instead of allowing an
  unhandled verification failure.
- Reuse one isolated analysis snapshot across all ten reviewer-view regenerations, eliminating
  repeated full-analysis copies while retaining side-effect isolation from the caller.
- Exposed structural metrics through human/JSON CLI output, the public verification schema, and
  workflow status, with adversarial depth/node and clean-package regression coverage.

## 0.57.0 - 2026-08-04

### Package provenance reconciliation

- Added `package_provenance_projection_v1` for the package-time audit manifest and reviewer
  README, with exact analysis-derived review/execution inventories plus explicit timestamp and
  baseline consistency checks.
- Unified outer-manifest, audit-manifest, CycloneDX, and README generation timestamps and made
  audit regeneration producer-version aware for future verifier upgrades.
- Added semantic rejection of forged audit decisions even when both the audit record's internal
  digest and the outer package checksum are recomputed.
- Made review-view and README reconciliation portable across LF/CRLF platforms by comparing
  canonical UTF-8 text while retaining exact transferred-byte verification in `manifest.json`.
- Preserved v0.56.1 and earlier capability contracts and exposed the nested provenance verdict
  through CLI, JSON Schema, workflow status, directory/ZIP verification, and release guidance.

## 0.56.1 - 2026-08-04

### Cross-version interchange verification

- Fixed exact SARIF and CycloneDX reconciliation so a newer verifier regenerates embedded tool
  metadata with the package's declared producer version rather than its own installed version.
- Strengthened compatibility coverage with a genuine v0.55 fixture whose embedded interchange
  versions and manifest hashes are rewritten consistently, preserving tamper detection without
  rejecting valid historical packages.
- Corrected new SARIF driver information URIs to the public `willtran87/project-py-sfmea`
  repository while retaining the historical URI during exact verification of older producers
  and preserving the explicit candidate-not-defect semantics.

## 0.56.0 - 2026-08-04

### Reviewer-view reconciliation

- Added the `review_views_projection_v1` package capability for ten human-review artifacts:
  worksheet CSV/Markdown, inventory, architecture, traceability, coverage, audit history,
  guidance CSV, and assurance CSV/Markdown.
- Package verification now regenerates those views in an isolated temporary workspace and
  compares exact bytes, rejecting rewritten reviewer-facing conclusions even when manifest
  hashes are recomputed.
- Exposed the five grouped projection checks plus artifact, finding, and component counts
  through human/JSON CLI output, workflow status, and the public verification schema.
- Preserved v0.55 and earlier capability contracts and added current, legacy, directory, ZIP,
  schema, workflow, and forged-checksum coverage.

## 0.55.0 - 2026-08-04

### SARIF and CycloneDX reconciliation

- Added the `interchange_artifacts_projection_v1` package capability for the SARIF finding
  exchange and CycloneDX declared-component inventory.
- Package verification now regenerates both artifacts from packaged analysis, checks exact
  projections and shared baseline identity, and rejects rewritten interchange content even
  when manifest hashes are recomputed.
- Unified the package manifest, README, and CycloneDX generation timestamp so current package
  exports are reproducible from a single auditable time declaration.
- Exposed SARIF-result and CycloneDX-component counts through human/JSON CLI output, workflow
  status, and the public package-verification schema while preserving v0.54 and older contracts.

## 0.54.0 - 2026-08-04

### Execution-evidence catalog reconciliation

- Added the `evidence_catalog_projection_v1` package capability for recorded assurance
  executions and evidence-artifact inventory.
- Package verification now checks the exact catalog projection, analysis-baseline binding,
  execution inventory, and evidence-artifact inventory. Forged evidence records remain invalid
  when manifest hashes are recomputed.
- Exposed execution/artifact counts and the four-check verdict through human/JSON CLI output,
  workflow status, and the public package-verification schema.
- Preserved v0.53 and earlier capability contracts and added current, legacy, forged-checksum,
  schema, directory, ZIP, and workflow coverage.

## 0.53.0 - 2026-08-04

### SFTA projection reconciliation

- Added the `sfta_projection_v1` package capability for the complete top-down Software Fault
  Tree model and its flat reconciliation-gap register.
- Package verification now regenerates both artifacts from packaged analysis, checks exact model
  and CSV-row projections, and reconciles model/gap counts. Rewritten SFTA content remains invalid
  when manifest hashes are recomputed.
- Review-package export now operates on a detached analysis snapshot and materializes SFTA once,
  preventing export-time mutation of a library caller's governed analysis.
- Exposed tree/gap counts and the three-check verdict through human/JSON CLI output, workflow
  status, and the public package-verification schema while preserving v0.52 and older packages.

## 0.52.0 - 2026-08-04

### Guidance-traceability reconciliation

- Added the `guidance_traceability_projection_v1` package capability for the complete guidance
  trace and standalone citation catalog.
- Package verification now regenerates both JSON artifacts from packaged analysis and checks
  their cross-artifact consistency. Rewriting citation evidence and recomputing its manifest
  checksum no longer produces a valid current package.
- Exposed citation and finding-link counts plus the three-check verdict through human/JSON CLI
  output, workflow status, and the public package-verification schema.
- Preserved v0.51 and earlier capability contracts and added current, legacy, forged-checksum,
  schema, directory, ZIP, and workflow coverage.

### Save determinism

- No-op saves now preserve `summary.last_saved_at` and byte identity across clock boundaries,
  while any substantive governed-analysis change still advances the saved timestamp.
- Added a forced-time regression so this behavior no longer depends on two operations occurring
  within the same second.

## 0.51.0 - 2026-08-04

### Bounded directory-package verification

- Applied the review-package entry, per-file, and cumulative-size limits to directory inputs as
  well as ZIP inputs.
- Replaced whole-file checksum buffering with bounded streaming SHA-256 calculation and enforced
  limits again during manifest, analysis, schema, diagnostic, queue, and register JSON parsing.
- Replaced recursive traversal of unexpected directory trees with bounded root enumeration and
  explicit flat-layout rejection.
- Added adversarial coverage for excessive manifest entries, oversized declarations, and nested
  directory content while preserving current and legacy package compatibility.

## 0.50.0 - 2026-08-04

### Analysis-diagnostic reconciliation

- Added the versioned `analysis_diagnostics_projection_v1` package capability for the summary,
  validation findings, resolved system context, repository inventory, and adapter-run ledger.
- Package verification now regenerates all five diagnostic views from packaged `analysis.json`.
  Validation timestamps remain provenance metadata; validation counts and findings reconcile
  exactly.
- Rewriting any diagnostic JSON artifact and updating its manifest checksum no longer produces
  a valid current package. The nested verdict is available in human/JSON verifier output,
  workflow status, and the public package-verdict schema.
- Preserved pre-0.50 package compatibility and added current directory, ZIP, forged-checksum,
  schema, workflow, and installed-wheel coverage.

## 0.49.0 - 2026-08-04

### Assurance-register reconciliation

- Added the `assurance_register_projection` package capability and exact regeneration of the
  full JSON assurance register from packaged analysis.
- Package verification now checks register structure, deterministic non-queue content, the
  embedded queue's integrity/binding, and byte-identical consistency between embedded and
  standalone work queues.
- Rewriting `assurance-register.json` and updating its manifest checksum no longer produces a
  valid current package. Register results are exposed in human/JSON output, workflow status,
  and the public package-verdict schema.

### Cross-version correctness

- Queue semantic reconciliation now excludes producer-version provenance and its dependent
  content digest while continuing to verify both independently. Compatible format-2 queues
  therefore remain valid after a PySFMEA upgrade instead of being reported as stale solely due
  to the installed verifier version.
- Preserved legacy packages that predate register-projection declarations and added
  cross-version, forged-register, embedded/standalone consistency, ZIP, schema, and workflow
  coverage.

## 0.48.0 - 2026-08-04

### Explicit package capabilities

- Added the manifest capability `assurance_work_queue_projection` to make the focused queue
  contract discoverable without inferring behavior solely from exporter versions or filenames.
- Current exporter or analysis-generator provenance requires a complete supported capability
  declaration; missing, duplicate, unknown, and incomplete declarations fail package verification.
- Added capabilities to human/JSON verifier output and workflow package diagnostics.

### Contract and ZIP polish

- Expanded the public manifest and package-verdict schemas with capability metadata and the
  complete nested assurance-work-queue verification envelope.
- Replaced temporary extraction paths in ZIP queue verdicts with stable logical references of
  the form `PACKAGE.zip!/assurance-work.json`.
- Preserved verification of older packages without capability declarations and added current,
  legacy, malformed-declaration, schema, directory, ZIP, and workflow regression coverage.

## 0.47.0 - 2026-08-04

### Review-package assurance handoff

- Promoted `assurance-work.json` to a first-class artifact in every new directory and ZIP
  review package, alongside the complete assurance register and its public schemas.
- Extended `sfmea verify-package` to verify the queue's internal digest and exact deterministic
  projection against packaged `analysis.json`. Rewriting the queue and recomputing both its
  digest and manifest checksum no longer produces a valid package.
- Exposed the queue verdict in human/JSON package verification and in `sfmea status` package
  integrity diagnostics. Current packages contain 40 governed files and twelve schemas.

### Compatibility and verification

- Preserved 0.46-and-earlier package profiles that predate the standalone queue. Current
  exporter or analysis-generator provenance requires the artifact, preventing silent omission
  from new packages.
- Added directory, ZIP, portable, forged-checksum, legacy-core, workflow, and installed-wheel
  coverage for the package-to-hardening-queue handoff.

## 0.46.0 - 2026-08-04

### Assurance work-queue integrity

- Upgraded focused automation backlogs to `pysfmea-assurance-work-queue-2`, with explicit
  generator provenance, baseline/schema/analysis-state binding, and a canonical SHA-256
  content digest.
- Added `sfmea assurance-work-verify QUEUE [--analysis ANALYSIS] [--json]`. Standalone
  verification detects accidental changes; analysis-bound verification also detects stale
  queues and rejects semantically altered queues even when their content digest is recomputed.
- Published the machine-readable `assurance-work-queue-verification` verdict contract and
  embedded all twelve public contracts in 39-file review packages.

### Compatibility and verification

- Preserved complete historical four-, six-, eight-, nine-, ten-, and eleven-schema package
  profiles, plus schema-less format-1 packages.
- Added bounded-file, malformed-input, tamper, forged-digest, stale-binding, CLI, schema, and
  installed-artifact coverage for the work-queue verification path.

## 0.45.0 - 2026-08-04

### Added

- Added `sfmea assurance ANALYSIS --format work-json` for a focused, independently consumable
  `pysfmea-assurance-work-queue-1` artifact without the full obligation register.
- Published a closed Draft 2020-12 `assurance-work-queue` contract covering work states,
  blockers, automation eligibility, latest execution status, summary counts, and next actions.
- Embedded the new contract as the eleventh content-addressed schema in standalone schema
  bundles and review packages.

### Compatibility and verification

- Preserved verification of complete historical four-, six-, eight-, nine-, and ten-schema
  profiles, plus schema-less format-1 packages.
- Added clean export equivalence, real generated-queue schema validation, package-profile, and
  installed-distribution coverage.

## 0.44.0 - 2026-08-04

### Added

- Added a deterministic assurance work queue that classifies every accepted finding as a
  contract gap, definition required, plan review required, ready for implementation, ready
  for execution, execution/evidence remediation, evidence review, verification review, or
  resolved.
- Each work item carries its finding and obligation IDs, priority, component, blockers,
  automation eligibility, latest execution state, and a stable next-action ID.

### Reporting and usability

- JSON assurance exports now include the complete versioned work queue; CSV and Markdown add
  work state, blockers, automation eligibility, and next-action columns.
- The self-contained HTML report and local reviewer annotate bounded obligations with the same
  derived work state without modifying the governed assurance contract.
- Lifecycle progress now reports implementation-ready, execution-ready, actionable, and
  state-distribution totals for CI and portfolio dashboards.

## 0.43.0 - 2026-08-04

### Added

- Published a self-contained Draft 2020-12 `workflow-status` contract for the complete
  `sfmea status --json` envelope, lifecycle stages, handoff gates, evidence, summaries, and
  remediation actions.
- Embedded the workflow contract as the tenth content-addressed schema in new review packages
  and standalone offline schema bundles.

### Compatibility and verification

- Preserved independent verification of historical complete four-, six-, eight-, and
  nine-schema package profiles as well as schema-less format-1 packages.
- Added contract validation against a real generated status result and semantic tests ensuring
  every blocked gate resolves to a supplied workflow action.

## 0.42.0 - 2026-08-04

### Added

- Added an explicit eight-gate handoff checklist to `sfmea status`, covering repository
  readiness, analysis availability, validation, finding review, revalidation, assurance
  planning, report currency, and review-package currency.
- Each gate now carries a stable ID, pass/block state, concise detail, concrete evidence,
  and a remediation action ID that resolves to the ordered workflow actions.

### Safety and usability

- Handoff readiness is derived from the complete gate set, preventing one lifecycle stage
  from hiding other simultaneous blockers.
- Human output presents a scannable pass/block checklist; JSON exposes the same evidence and
  summary for CI policy without changing the existing workflow-status format identifier.

## 0.41.0 - 2026-08-04

### Added

- Added `sfmea schema --bundle DIRECTORY` for atomic export of the complete offline contract
  catalog and all nine content-addressed schemas.
- Added `sfmea schema --verify-bundle DIRECTORY [--json]` for bounded, standalone verification
  of catalog completeness, schema identity, canonical digests, entry types, and file contents.

### Safety and usability

- Bundle refresh requires `--force`, accepts only a recognized generated file set, refuses
  symbolic links, directories, and reviewer-added files, and publishes through verified staging.
- Human verification output is concise while JSON output retains the stable public
  `pysfmea-schema-bundle-verification-1` contract and meaningful exit codes.

## 0.40.0 - 2026-08-04

### Added

- Published a closed Draft 2020-12 contract for detached Ed25519 signature envelopes,
  statements, package subjects, key fingerprints, and signature encoding.
- Embedded the signature contract as the ninth content-addressed schema in new review packages.
- Preserved complete 0.37, 0.38, and 0.39 schema profiles alongside schema-less format-1
  compatibility.

### Verification

- Signing tests validate real generated envelopes against the public contract before exercising
  trusted-key verification, wrong-key rejection, mutation detection, and replay protection.

## 0.39.0 - 2026-08-04

### Added

- Made the public contract chain self-describing with schemas for `schema-catalog.json` and
  `pysfmea-schema-bundle-verification-1` success/rejection verdicts.
- Expanded new review packages to carry eight content-addressed public schemas while retaining
  compatibility with older complete four- and six-schema, plus schema-less, format-1 packages.

### Verification

- Contract tests now validate the generated catalog plus successful and rejected schema-bundle
  verdicts against their own published Draft 2020-12 schemas.

## 0.38.0 - 2026-08-04

### Added

- Published self-contained JSON Schema contracts for the review-package manifest and the
  stable `verify-package --json` success/rejection verdict envelope.
- Added an explicit `pysfmea-review-package-verification-1` discriminator to every package
  verification result, including early archive and manifest failures.
- Embedded the expanded six-contract, content-addressed schema set in new review packages.

### Verification

- Package tests validate real exported manifests and verifier verdicts against the public
  Draft 2020-12 contracts and retain schema-less format-1 compatibility coverage.

## 0.37.0 - 2026-08-04

### Added

- Governed review directories and ZIP archives now carry the exact offline schema catalog and
  all four public diagram/verifier contracts.
- Package verification cross-checks schema file completeness, catalog identities, canonical
  content digests, and manifest catalog metadata; workflow status exposes the bounded verdict.

### Compatibility

- Existing `pysfmea-review-package-1` artifacts without embedded schemas remain verifiable.
  Schema files are treated as a complete declared extension, so partial bundles fail closed.

## 0.36.0 - 2026-08-04

### Added

- Standalone, bounded HTML report and canonical diagram-bundle verification commands.
- Independent payload and normalized whole-document integrity for current HTML reports.
- Analysis-state binding, downgrade protection, structured failure verdicts, and explicit
  requested/checked/failed/unchecked verification states.
- Content-addressed JSON Schema Draft 2020-12 catalog and atomic schema export command.
- Linux/Windows CI across Python 3.11–3.14, distribution builds, clean-wheel smoke tests,
  dependency updates, contributor guidance, security policy, and release checklist.

### Changed

- Workflow status now reuses the standalone HTML verifier instead of maintaining a separate
  payload-only implementation.
- Diagram and report verifier outputs now share stable automation semantics and safety notices.
- Unchanged assurance/SFTA derivations retain their provenance timestamps, making identical
  atomic saves byte-stable and preventing false external-change reloads in the review server.

## 0.31.0 - 2026-08-04

- Added bounded failure-propagation projection controls, trace navigation, assurance context,
  state-bound diagram bundles, atomic publication, and extensive workflow/report refinements.

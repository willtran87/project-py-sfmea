# Changelog

Notable user-visible changes are recorded here. PySFMEA follows semantic versioning for the
package; public artifact and schema identifiers carry their own explicit compatibility versions.

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

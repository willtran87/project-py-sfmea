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
| `assurance-program` | Multi-repository analysis bindings, external requirements/evidence, temporal and circuit-breaker relationships, independent validation/model metrics, and governance policy |
| `assurance-program-verification` | Program integrity, binding, trusted-evidence, timing/resilience, quality-gate, relationship, and governance verdicts |
| `assurance-work-queue` | Accepted-finding work states, blockers, automation eligibility, and next actions |
| `assurance-work-queue-verification` | Queue integrity, analysis binding, and deterministic-projection verdicts |
| `detached-signature` | Ed25519 signature envelope, signed statement, and package subject |
| `diagram` | Renderer-neutral `pysfmea-diagram-1` object |
| `diagram-bundle` | Generated, integrity-declaring `pysfmea-diagram-bundle-1` object |
| `diagram-bundle-verification` | Success, rejection, and incomplete diagram-verifier verdicts |
| `html-report-verification` | Success, rejection, and incomplete HTML-verifier verdicts |
| `publication-failure-catalog` | Package-publication failure codes, phases, stable findings, remediation actions, and retry policy |
| `publication-failure-catalog-verification` | Bounded catalog integrity and exact-taxonomy success/rejection verdicts |
| `review-package-manifest` | Package file inventory, checksums, provenance, and state binding |
| `review-package-verification` | Success and rejection verdicts from `verify-package --json`, plus success, pre-publication failure, and post-publication rejection receipts from `package --json` |
| `schema-bundle-verification` | Success and rejection verdicts for the offline schema set |
| `schema-catalog` | Content-addressed discovery metadata for the complete public contract set |
| `workflow-status` | Lifecycle stage, handoff gates, evidence, summaries, and remediation actions |

The schemas use stable `urn:pysfmea:schema:…:1` identifiers and have no external `$ref`
dependencies. A consumer can pin the catalog digest and retain the exported schema beside its
CI policy or evidence record.

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

### System assurance program contracts

`pysfmea-assurance-program-1` is a separate system-level artifact. It references one or more
governed analysis files by path, exact canonical state SHA-256, and baseline ID; it does not merge
or mutate those analyses. Closed, bounded collections represent cross-repository component
relationships and temporal/circuit-breaker policies, requirements-source snapshots, external
evidence artifacts, validation cohorts, LLM quality evaluations, governance approvals, and
configurable quality gates. Completed evidence requires an artifact path and digest. Cohort and LLM
records include corpus digests plus distinct producer/reviewer identities; finding and hazard
references are semantically resolved as `REPOSITORY_ID:RECORD_ID`.
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

## Offline review-package use

Current `sfmea package` directory and ZIP outputs embed `schema-catalog.json` and all sixteen
documents under their stable catalog filenames. The package manifest checksums every file and
binds the catalog format, path, canonical digest, and schema count. `sfmea verify-package`
additionally cross-checks catalog completeness, schema identities, and each canonical digest.
This lets a recipient validate public structures while disconnected and retain the exact
contracts beside the governed evidence.

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
2,000,000-node and 100-level availability limits plus a `core_contract` check for the object,
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
sixteen-contract profile.
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
lifecycle stages, required gate/action fields, status vocabulary, counts, and bounds. Generate
the payload with `sfmea status REPOSITORY --json`. JSON Schema validates structure; PySFMEA's
workflow implementation supplies the semantic relationships between summary counts,
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

Every current `html-report-verification`, `diagram-bundle-verification`, and
`assurance-work-queue-verification` result carries `verifier.name: PySFMEA` and the exact package
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

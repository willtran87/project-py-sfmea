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
```

`sfmea schema NAME` writes the selected schema to standard output. `-o` publishes deterministic
UTF-8 JSON through a temporary sibling and atomic replacement. The machine-readable catalog
contains the schema name, URN, JSON Schema draft, description, and canonical SHA-256 digest.

`--bundle DIRECTORY` atomically publishes the catalog and complete schema set after verifying
the staged output. A non-empty recognized bundle requires `--force`; unknown files, symbolic
links, and non-file entries prevent replacement so local material is not silently discarded.
`--verify-bundle DIRECTORY` performs bounded standalone verification and returns nonzero for a
missing, partial, mixed, malformed, or digest-mismatched bundle. `--json` emits the public
schema-bundle verification contract for CI policy and evidence capture.

Available names:

| Name | Contract |
|---|---|
| `assurance-work-queue` | Accepted-finding work states, blockers, automation eligibility, and next actions |
| `assurance-work-queue-verification` | Queue integrity, analysis binding, and deterministic-projection verdicts |
| `detached-signature` | Ed25519 signature envelope, signed statement, and package subject |
| `diagram` | Renderer-neutral `pysfmea-diagram-1` object |
| `diagram-bundle` | Generated, integrity-declaring `pysfmea-diagram-bundle-1` object |
| `diagram-bundle-verification` | Success, rejection, and incomplete diagram-verifier verdicts |
| `html-report-verification` | Success, rejection, and incomplete HTML-verifier verdicts |
| `review-package-manifest` | Package file inventory, checksums, provenance, and state binding |
| `review-package-verification` | Success and rejection verdicts from `verify-package --json` and publication receipts from `package --json` |
| `schema-bundle-verification` | Success and rejection verdicts for the offline schema set |
| `schema-catalog` | Content-addressed discovery metadata for the complete public contract set |
| `workflow-status` | Lifecycle stage, handoff gates, evidence, summaries, and remediation actions |

The schemas use stable `urn:pysfmea:schema:…:1` identifiers and have no external `$ref`
dependencies. A consumer can pin the catalog digest and retain the exported schema beside its
CI policy or evidence record.

## Offline review-package use

Current `sfmea package` directory and ZIP outputs embed `schema-catalog.json` and all twelve
documents under their stable catalog filenames. The package manifest checksums every file and
binds the catalog format, path, canonical digest, and schema count. `sfmea verify-package`
additionally cross-checks catalog completeness, schema identities, and each canonical digest.
This lets a recipient validate public structures while disconnected and retain the exact
contracts beside the governed evidence.

New packages also include `assurance-work.json`. Package verification applies the embedded
work-queue contract, checks its canonical digest, and reconciles the complete deterministic
projection with packaged `analysis.json`. The JSON verdict exposes this nested verification as
`assurance_work_queue`. Packages produced before 0.47 may omit the focused artifact; current
exporter or analysis-generator provenance requires it.

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
current twelve-contract profile. Mixing profile generations,
dropping one contract, duplicating a catalog name, or introducing an unknown contract remains
invalid.

Every package-verifier result includes the independent
`pysfmea-review-package-verification-1` discriminator. Its `format` field continues to report
the format discovered in the package itself and can therefore be empty on early rejection.
This separation lets automation identify the verdict contract without mistaking an invalid or
missing artifact for a different response type.

The distribution chain is self-describing: `pysfmea-schema-catalog.schema.json` validates the
catalog structure, and `pysfmea-schema-bundle-verification.schema.json` validates both accepted
and rejected catalog-integrity verdicts. Digest reconciliation, complete-file-set enforcement,
and unique catalog names remain semantic checks performed by PySFMEA.

`pysfmea-detached-signature.schema.json` checks the closed signature envelope, Ed25519
algorithm declaration, signed package-subject fields, SHA-256 fingerprint syntax, and exact
64-byte signature encoding. Only `sfmea verify-package --signature ... --public-key ...`
performs cryptographic verification and reconciles that subject with the supplied package.

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
sfmea report-verify sfmea-report.html --analysis sfmea-analysis.json --json
```

Schema validity does not authenticate an author, approve an analysis, demonstrate control
effectiveness, or accept residual risk.

## Compatibility policy

Schema catalog names and URN major versions identify compatibility boundaries. Additive
diagnostic properties may appear in verifier verdicts because their schemas intentionally allow
format-specific extensions. The required verdict envelope and named checks remain stable within
major version 1. A breaking required-field, meaning, type, or closed-vocabulary change requires
a new schema name/URN major version. Catalog SHA-256 values expose every byte-level contract
change, including compatible clarifications.

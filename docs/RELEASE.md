# Release checklist

This checklist produces a reviewable source distribution and wheel. Publishing, tagging, and
signing remain explicit maintainer actions.

## 1. Establish the release state

- Work from an approved release branch with intended changes reviewed.
- Confirm the version in `src/pysfmea/version.py` and the matching changelog entry.
- Confirm public format/schema compatibility and update major identifiers for breaking changes.
- Confirm current diagnostic/guidance/SFTA/evidence/interchange/provenance/review-view/register/work-queue review-package
  capabilities are explicitly declared and verifier-enforced.
- Confirm governed analysis load rejects links/non-files and opened/final identity changes,
  enforces 100 MB while consuming bytes, and rejects invalid UTF-8/JSON, duplicate keys,
  non-finite numbers, depth beyond 100 levels, and structures beyond 2,000,000 nodes.
- Confirm migrations and derived-state materialization occur only after those ingestion bounds,
  and review-package verification uses the same shared depth/node measurement primitive.
- Confirm analysis save rejects linked/non-file destinations, bounds serialized UTF-8 output to
  100 MB, retains final-path identity, and refuses destination identity/metadata changes before
  atomic replacement while preserving prior bytes and removing staging residue.
- Confirm no-op timestamp reconciliation and browser ETag hashing use bounded identity-stable
  ingestion; forced read/hash limits produce controlled failures without stale reviewer state.
- Confirm model-assisted requests and responses enforce 3 MB/10 MB byte boundaries, strict nested
  UTF-8 JSON, duplicate/non-finite rejection, 50-level/100,000-node limits, exact discovery and
  summary fields, bounded values, evidence/citation allowlists, and the 25-suggestion ceiling.
  Confirm a later invalid component response leaves all discovery state unchanged and failed
  suggestion materialization restores the complete pre-review analysis.
- Confirm PDF browser output is a regular non-link file, verification and streaming publication
  enforce the 250 MB consumption boundary, and inspected/opened/final identity remains stable.
  Confirm PDF destinations retain final-link identity, private sibling content is flushed and
  independently verified, destination races are refused immediately before atomic replacement,
  and invalid output or publication failures preserve prior bytes without staging residue.
- Confirm directory and ZIP package verification retains bounded entry, file, and total sizes,
  streaming hashes, flat layouts, bounded semantic JSON reads, and iterative analysis node/depth
  limits plus fail-closed core-container checks before governed-state hashing or projection
  regeneration.
- Confirm malformed scalar/configuration mutations and forced semantic-projector failures return
  schema-valid sanitized verdicts without tracebacks or internal exception messages.
- Confirm absent and malformed derived assurance state is materialized on a private package
  snapshot, the input analysis remains unchanged, and the resulting directory and ZIP packages
  pass exact analysis-state, register, and work-queue reconciliation.
- Confirm an explicit case-insensitive `.zip` package output selects archive publication without
  requiring `--zip`, while `--zip` without an output retains the default archive filename.
- Confirm package generation independently verifies the complete staging directory before
  publication and that a forced-refresh verification failure preserves the prior destination,
  removes staging residue, and returns bounded rule identifiers.
- Confirm `package --json` emits exactly one schema-valid post-publication verification verdict
  for directory and ZIP outputs and returns nonzero for an invalid receipt.
- Confirm missing input, malformed JSON, destination conflict, filesystem failure, and internal
  publication rejection remain schema-valid on stdout with empty JSON-mode stderr, bounded
  expected details, sanitized unexpected runtime details, and nonzero status.
- Confirm every package verdict records exact verifier name/version provenance, and that stable
  publication failure rule IDs distinguish input, destination, rejection, and internal failures.
- Confirm publication failure messages never echo raw exception text, source paths, destination
  paths, permission details, or injected sensitive runtime values.
- Confirm every not-published receipt has a phase-compatible `failure_code` and matching stable
  error finding, while published receipts reject any failure code.
- Confirm every failure has the catalog-defined `next_action`, mismatched actions fail schema
  validation, and the runtime/schema catalogs expose the same complete code/action sets.
- Confirm `publication-catalog` human and JSON modes expose the complete deterministic taxonomy,
  its JSON validates against the public catalog schema, and the verifier schema annotation matches.
- Confirm retry policy is present and catalog-correct on every not-published receipt, internal
  failures require manual diagnostics, and published receipts reject all retry metadata.
- Confirm every not-published receipt carries the exact catalog format and canonical failure rule
  ID, mismatched identity tuples fail schema validation, and published receipts reject both.
- Confirm the catalog's canonical `content_sha256` recomputes exactly, every not-published receipt
  carries it as `catalog_sha256`, and missing, altered, or published-state digests are rejected.
- Confirm catalog and receipt integrity metadata declares `sha256` with
  `json-sort-keys-compact-utf8`, is included in the canonical digest, and rejects missing,
  unsupported, or published-state declarations.
- Confirm `publication-catalog --verify` accepts the exact catalog, rejects drift and unavailable
  inputs with schema-valid bounded verdicts, requires inspected/opened/final identity agreement,
  rejects duplicate keys, non-finite numbers, malformed UTF-8, and depth/node overflow, and
  returns a nonzero rejection status.
- Confirm `publication-catalog --output` is deterministic and atomic, protects existing files,
  refreshes only recognized catalogs with `--force`, and preserves prior bytes on failure.
- Confirm JSON export emits a schema-valid path-bound verification receipt and forced refresh
  rejects format-only spoofing or malformed failure-entry structures without altering the target.
- Confirm current packages contain 14 public schemas and 42 checked artifacts while genuine
  twelve- and thirteen-schema packages remain compatible under the current verifier.
- Confirm offline schema-bundle verification rejects linked, non-file, malformed UTF-8, and
  oversized entries through schema-valid verdicts and enforces its two-megabyte limit on bytes
  consumed from each open stream rather than a pre-read size observation. Confirm every allowed
  file reconciles inspected/opened/final identity and rejects duplicate keys, non-finite numbers,
  and 100-level/250,000-node overflow before canonical hashing.
- Confirm organizational guidance packs reject missing, directory, symbolic-link, malformed
  UTF-8, duplicate-key, non-finite/overflowed numeric, oversized, deep, high-node-count, and
  inspected/opened/final identity-changing inputs; enforce the 5 MB/100-level/250,000-node limits;
  and hash the exact single-snapshot bytes used for citation selection.
- Confirm assurance-scaffold verification bounds manifest and retirement-record bytes while
  consuming each stream, streams generated-file hashes under their own byte limit, rejects
  non-regular/symbolic-link JSON artifacts, reconciles inspected/opened/final identity, rejects
  duplicate/non-finite/overflowed numeric JSON and depth/node exhaustion, and reports broken
  retirement links as invalid records. Confirm the generated standalone pytest loader applies the
  same strict decoding and iterative structure policy before collection.
  Confirm guarded refresh/archive reuse bounded ingestion, retain final-link identity, and refuse
  linked sources, retirement records, and destinations without following them.
- Confirm standalone assurance work queues use the strict 100 MiB/100-level/1,000,000-node input
  boundary before digest and deterministic projection checks. Confirm imported and recorded
  execution manifests use the strict 2 MB/100-level/100,000-node boundary before baseline,
  artifact, lifecycle, or evidence-review decisions, and identity-change failures remain
  transactional.
- Confirm guarded refresh/archive retain the exact initially verified manifest snapshot, revalidate
  the queue at the mutation boundary, reject a different independently valid manifest identity,
  preserve the source queue, and remove refresh staging residue without creating retirement state.
- Confirm the generated pytest module independently refuses linked/non-regular manifests, enforces
  its 64 MiB limit while consuming the binary stream, decodes UTF-8 JSON explicitly, validates its
  root/format/integrity/obligation envelope, and fails collection with bounded remediation text.
- Confirm external evidence import bounds manifest parsing plus artifact hash/copy streams on bytes
  consumed, rejects final links and resolved escapes, detects between-pass artifact changes, and
  removes staging on failure. Confirm governed test/evidence mutation occurs only after publication
  and restores both analysis and filesystem state if final recording fails; managed review reuses
  the bounded link-safe verifier.
- Confirm simple/OTLP runtime trace import rejects links/non-files, enforces its 100 MB byte limit
  while consuming an inspected/opened/final identity-stable stream, rejects duplicate keys,
  non-finite/overflowed numeric values, malformed UTF-8, and 100-level/2,000,000-node overflow,
  validates JSON roots, iteratively traverses typed containers, caps spans/attribute depth/labels,
  leaves rejected traces side-effect free, and restores the full analysis if
  runtime/history/summary finalization fails.
- Confirm coverage JSON import rejects links/non-files, enforces its 100 MB limit while consuming
  an inspected/opened/final identity-stable binary stream, rejects duplicate keys,
  non-finite/overflowed numbers, malformed UTF-8, and 100-level/2,000,000-node overflow, and
  validates JSON object roots. Confirm file traversal stops before exceeding 100,000 records,
  path processing is bounded to 4,096 characters, repository escapes and parent traversal are
  refused, and typed line/branch coordinates retain valid signed branch destinations. Confirm
  unsafe, malformed, and duplicate normalized records are omitted with stable aggregate warnings
  while the remaining repository analysis completes. Confirm the exact accepted-byte digest and
  record counts are retained in settings, the digest is bound into the immutable run manifest, and
  an in-repository coverage artifact reuses that captured snapshot for inventory hashing without a
  second read. Confirm external coverage is not added to repository artifact accounting.
- Confirm Python source and test-reference evidence reject links/non-files, enforce the 20 MB
  per-file limit while consuming an inspected/opened/final identity-stable stream, honor valid
  PEP 263 encodings, and report invalid or unsupported encodings without aborting the scan. Confirm
  each selected source is read once and its accepted bytes are reused for AST parsing, included-test
  indexing, and baseline hashing. Confirm each eligible test-evidence file is also read once before
  baseline construction, configured/default/hidden exclusions apply, and its bytes are reused for
  reference attribution and repository inventory hashing. Confirm discovery stops at 100,000
  selected files, test indexing stops at 10,000 files or 100 MB, rejected evidence remains visible,
  accepted/rejected file and byte counts are accurate, and both canonical snapshot-set digests are
  bound into the run manifest and baseline identity.
- Confirm pyproject, recursively included requirements/constraints, and supported lockfiles reject
  links/non-files, inspected/opened/final identity changes, and normalized repository escapes;
  enforce 20 MB per-file, 1,000 attempted-file, and 100 MB aggregate limits; and stop reading after
  aggregate exhaustion. Confirm hashing, accepted byte counts, recursive parsing, baseline
  fingerprinting, repository inventory evidence, and immutable manifest binding reuse one exact
  accepted snapshot without reopening the manifest path. Confirm
  requirement text requires UTF-8, malformed pyproject dependency container shapes cannot create
  dependency claims, and unsupported lockfile syntax remains hash evidence rather than speculative
  parsed claims.
- Confirm OpenAPI/Swagger, JSON Schema, YAML, and protobuf contract discovery rejects links,
  non-files, resolved escapes, and inspected/opened/final identity changes; enforces 20 MB
  per-file, 1,000 discovered-file, and 100 MB aggregate limits while consuming streams; and
  handles invalid UTF-8, malformed JSON, scalar roots, and unexpected containers without aborting
  the scan. Confirm JSON contracts reject duplicate keys, non-finite/overflowed numbers, and
  100-level/1,000,000-node structure overflow before semantic extraction. Confirm operations/data
  types stop at 500 distinct values per category, truncation is explicit, accepted byte counts and
  digests remain visible, repository inventory evidence reuses the captured contract bytes, and the
  complete inventory digest is bound into the run manifest.
- Confirm repository inventory hashing reuses accepted Python analysis, test-evidence,
  dependency-manifest, interface-contract, and in-repository coverage snapshots; rejects links and
  non-regular artifacts before opening, identity-reconciles every independent artifact snapshot,
  exposes a valid per-entry `snapshot_source`, and reconciles `summary.by_snapshot_source` to the
  complete file-entry count. Confirm external coverage never receives repository snapshot
  attribution. Enforce 20 MB per artifact and 500 MB across bytes actually consumed, and never
  expose raw filesystem failures. Confirm aggregate exhaustion
  continues safe metadata/semantic accounting but adds a digest-bound unresolved region, marks the
  inventory truncated, and omits later hashes; file and excluded/opaque-region traversal each stop
  at 100,000 records.
- Confirm HTML report inventory metrics are derived from entry/region records, declare
  `reconciled`, `recomputed`, or `unavailable`, never visualize a mismatched stored summary, and
  retain the validation error and blocked handoff gate until the governed analysis is rescanned.
- Confirm coverage JSON/Markdown, inventory Markdown, and human/JSON summary output reuse the same
  safe projection. Confirm review-view verification enables the richer Markdown sections only for
  0.57.65-and-newer producers and still accepts exact pre-0.57.65 package views.
- Confirm project configuration rejects links/non-files and inspected/opened identity changes,
  enforces its 5 MB limit while consuming the binary stream, and validates bounded UTF-8 TOML before semantic normalization. Confirm
  relative coverage/guidance paths retain final-link identity for their downstream loaders.
- Confirm configuration-template publication rejects linked/non-file destinations, stages and
  flushes complete content before atomic replacement, revalidates at the mutation boundary,
  preserves prior content when replacement fails, and removes temporary residue.
- Confirm detached signing and verification enforce consumption-time key/envelope limits,
  reject links/non-files and inspected/opened/final identity changes, and parse envelopes as
  strict duplicate-free finite UTF-8 JSON under 20-level/10,000-node limits. Confirm duplicate
  keys, non-finite literals, numeric overflow, and structure exhaustion fail before cryptography.
  Confirm signer/passphrase limits fail before package or key processing.
- Confirm signature verification ignores stale caller-supplied package verdicts, freshly verifies
  integrity, strictly decodes a 10 MB/100-level/250,000-node manifest reread, reconciles those exact
  bytes to the verified digest, and returns structured rejection when package bytes change between
  verification phases. Confirm exact ZIP bytes are identity-checked and streamed under the 550 MB
  reconciliation limit.
- Confirm signature publication revalidates destination identity at atomic replacement, refuses
  concurrent replacement, preserves prior content on failure, and removes staging residue.
- Confirm the repository discoverer reports version 6, the AST parser version 2, dependency
  inventory version 4, local-contract analysis version 3, and coverage.py JSON evidence version 2.
  Confirm discoverer provenance advertises source/test/dependency/contract/coverage snapshot reuse
  and snapshot attribution; AST provenance advertises exact-byte source snapshots, PEP 263
  decoding, identity reconciliation, and single-snapshot baseline binding; dependency, contract,
  and coverage provenance advertise their respective exact-byte reuse and manifest-binding
  capabilities.
- Confirm `report --json` stages privately, verifies exact binding before atomic replacement,
  emits only a schema-valid receipt, preserves prior output and removes residue on every failure,
  sanitizes unexpected load/generation/verification/publication details, and leaves stderr empty.
- Confirm report receipts distinguish `published/complete` from every `not_published` phase,
  accurately record pre-existing-destination preservation, reject contradictory state, and refuse
  the analysis JSON itself as an HTML destination.
- Confirm report publication rejects destination symbolic links, directories, and other
  non-regular objects before generation in human and JSON modes, preserves their bytes/targets,
  and never resolves the final atomic replacement through a link.
- Confirm every standalone CSV/Markdown/JSON/SARIF/CycloneDX/SFTA/visual/diagram/HTML,
  assurance-register/work-queue, individual-schema, and publication-catalog export uses the shared
  encoded-artifact boundary, retains BOM/newline compatibility, rejects link and non-file
  destinations, refuses concurrent destination changes, preserves prior bytes after forced
  replacement failure, and removes every sibling staging file.
- Confirm forced publication-catalog refresh carries the inspected destination state across
  recognized-envelope validation and refuses absent-to-present, replacement, and in-place edits
  before staging or atomic replacement without modifying the concurrent owner's bytes.
- Confirm HTML/PDF engineering notes reject missing, non-regular, symbolic-link, malformed UTF-8,
  and oversized inputs; enforce the byte limit while consuming the stream; canonicalize newlines;
  and preserve prior JSON-mode output through a sanitized generation receipt.
- Confirm HTML verification enforces its byte limit on the consumed stream rather than relying on
  a pre-read size check.
- Confirm diagram verification consumes one inspected/opened/final identity-stable regular
  non-link stream, enforces its 5 MB limit, rejects duplicate keys, non-finite/overflowed numbers,
  malformed UTF-8, and 100-level/250,000-node overflow, and returns bounded structured rejection.
- Confirm custom report-diagram imports reuse the standalone verifier boundary, stop at 50 files
  or 25 MB accepted in aggregate, retain the existing 50-diagram/node/edge limits, and embed each
  accepted source snapshot's exact byte count and SHA-256 in report-integrity-covered metadata.
- Confirm every current HTML, diagram-bundle, and assurance-work-queue success and rejection
  verdict records exact verifier name/version provenance while historical v1 receipts without the
  additive field remain schema-compatible.
- Confirm JSON publication receipts explicitly distinguish published and not-published states
  across analysis-load, generation, complete, and post-publication-verification phases.
- Confirm the public schema rejects contradictory receipt validity, checked-file count,
  publication status, and phase combinations while accepting standalone verification verdicts
  that omit receipt-only publication state.
- Confirm valid package verdicts require at least one checked file and zero errors, while invalid
  verdicts require one or more errors.
- Confirm every valid verdict content-addresses the exact parsed manifest, every valid ZIP verdict
  also content-addresses the archive, and the published schema rejects missing digests.
- Confirm error and warning counts agree with the presence or absence of corresponding finding
  levels in both successful and rejected verdicts.
- Confirm exact interchange verification uses package-producer metadata and retains genuine
  prior-version package compatibility under the current verifier.
- Confirm exact SFTA, validation, and worksheet verification use the package producer's selector
  semantics and that current ID-only selectors cannot widen to unrelated findings.
- Confirm package/audit/CycloneDX/README timestamps reconcile and text projections remain
  semantically portable across LF and CRLF while manifest byte checks remain exact.
- Confirm NASA/FAA/other guidance metadata and captured hashes were not changed unintentionally.
- Ensure the CI matrix is green and dependency-update alerts are reviewed.

## 2. Run release validation

```powershell
python -m pip install -e ".[dev,signing]"
python -m compileall -q src
python -m ruff check src tests
python -m pytest -q
python -m build
sfmea --version
sfmea schema --list --json
sfmea schema --bundle .release-contracts --force
sfmea schema --verify-bundle .release-contracts --json
```

Validate each public schema with a Draft 2020-12 validator and retain the catalog SHA-256 values
with the release evidence. Run the golden evaluation corpus and review unsupported-verification
claims, citation accuracy, trace integrity, and adapter provenance.

Confirm the golden corpus is a stable regular non-link file; ingestion enforces its 20 MB byte,
20-level/500,000-node JSON, 100,000-case, 100-scope, field-length, and 500,000-active-candidate
limits. Confirm duplicate/non-finite/unknown/malformed inputs fail closed, the result identifies
`pysfmea-evaluation-result-1`, and the recorded canonical corpus digest matches approved release
evidence.

```powershell
sfmea scan benchmarks\python_sfmea_corpus\repository `
  -o benchmark-analysis.json --fresh
sfmea evaluate benchmark-analysis.json `
  benchmarks\python_sfmea_corpus\expected.json --json
sfmea assurance benchmark-analysis.json --format work-json -o benchmark-assurance-work.json
sfmea assurance-work-verify benchmark-assurance-work.json --analysis benchmark-analysis.json --json
sfmea package benchmark-analysis.json -o benchmark-review-package --json
sfmea verify-package benchmark-review-package --json
```

## 3. Smoke-test the built wheel

Create a clean virtual environment, install only the wheel, and exercise dependency-free paths.

```powershell
py -3.11 -m venv .release-smoke
$wheel = Get-ChildItem dist\pysfmea-*.whl | Select-Object -First 1
.release-smoke\Scripts\python.exe -m pip install $wheel.FullName
.release-smoke\Scripts\sfmea.exe --version
.release-smoke\Scripts\sfmea.exe schema --list
```

Also test the `signing` extra separately when package signing is part of the release evidence.
Do not treat a successful build or smoke test as tool qualification or analytical validation.

## 4. Publish deliberately

- Review wheel and source-distribution contents before upload.
- Create a signed or otherwise organization-approved tag matching the package version.
- Publish through the project's approved PyPI/GitHub release process.
- Attach checksums, schema-catalog digests, test results, and known limitations.
- Verify installation from the published artifact in a new environment.
- Preserve the release evidence and record any accepted residual tool risks.

# PySFMEA methodology

## Purpose and boundary

PySFMEA automates repository decomposition, evidence gathering, candidate generation, persistence, and reporting. It does not automate acceptance of failure modes, consequence analysis, risk acceptance, or approval.

This boundary follows the central limitation in the public guidance: SFMEA depends on system knowledge, documentation, assumptions, and review by people with different perspectives. Source code can show that a function calls a remote service; it cannot determine whether the end effect of that service returning stale data is an inconvenience, financial loss, environmental release, or loss of life. The project configuration therefore records purpose, boundary, operating context, interfaces, assumptions, hazards, critical functions, and the project's risk policy alongside the scan.

## Analysis structure

The default implementation-level elements are public and private functions, methods, constructors, selected lifecycle methods, nested functions, closures, named lambdas, declarative data models, and executable module initialization. The inventory also contains the declared dependency environment, project-defined common causes, and local OpenAPI, Swagger, JSON Schema, and protobuf interface contracts. Dependency evidence includes parsed declarations, recursively included requirement files, and hashes of common lock/build manifests. Contract evidence includes extracted operations/data types and a content hash. Tests are evidence sources but are not analyzed as production components unless explicitly included.

Each component receives a stable ID derived from its relative path, qualified name, and kind. Each scanner candidate receives a stable ID derived from its component and rule. An unambiguous rename or move is matched through an identity-independent content fingerprint; predecessor IDs and review history are retained and revalidation is required. Ambiguous matches remain new/removed rather than guessing.

Every new analysis records the generator name, PySFMEA version, and analysis schema
version. Older migrated records whose original generator predates this provenance
retain `unknown` rather than being falsely attributed to the version that loaded them.

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

The rules intentionally state failure at the functional boundary. A coding defect such as an incorrect comparison is normally a cause; “returns an incorrect authorization decision” is the failure mode; unauthorized access or denial of legitimate access are effects.

## Evidence and confidence

Scanner evidence includes source location, AST signals, approximate internal callers and transitive upstream paths, complexity, decorators, textual test references, dependency declarations, and optional function-level line and branch evidence derived from coverage.py JSON. These are useful for triage and traceability. They are not proof that a failure exists or that a control is effective. Python's runtime dispatch means the caller evidence is deliberately conservative and incomplete.

Confidence describes how directly a rule was triggered by observable syntax. It is not likelihood or occurrence. The two baseline functional rules are generated systematically even when no specialized syntax is present.

Ordered call evidence and common framework decorators identify HTTP routes, background tasks, event handlers, and CLI commands. Framework recognition is metadata and a screening aid; it does not prove the runtime router, dependency injection graph, middleware order, or deployed configuration.

Imported simple or OpenTelemetry JSON spans add observed parent-child relations. Each import is hashed, baseline-linked, bounded, and audited. Static and observed relationships remain visibly distinct because one is approximate source evidence and the other is incomplete execution evidence.

Trace import is idempotent by source hash. Mapping prefers explicit `sfmea.component`
and code-function attributes, then unambiguous names, then code-file/function pairs.
Mapped and unmapped counts and mapping methods are retained so reviewers can assess
the strength of the runtime-to-source correlation.

## Machine-assisted discovery boundary

Machine discovery consumes bounded evidence packets rather than unrestricted repository content. Each packet assigns citation IDs to the component, existing candidates, requirements, hazards, interfaces, and runtime relations. Repository-derived strings are explicitly treated as untrusted data, not prompt instructions.

Generated suggestions are stored separately from SFMEA worksheet items. The response schema prohibits severity, occurrence, detection, disposition, workflow status, approval, and closure fields. Suggestions must cite supplied evidence IDs and record uncertainties and questions. Provider, model, prompt version, baseline, timestamp, response hash, and review history are retained. Duplicate failure-mode text for the same component is suppressed.

A reviewer may reject a suggestion or materialize it as a new unreviewed worksheet item. Materialization does not accept the failure mode into the governed analysis and never overwrites an existing item. Proposed suggestions and generated summaries are invalidated when the repository/configuration baseline changes.

## Effects and scoring

The initial local effect is a prompt. Next-higher and end effects remain blank because they require architecture and operational context. When exactly one project-defined hazard is linked to a critical function, its human-authored end effect and severity may be copied into the starter with an explicit confirmation rationale. Reviewers may edit all FMEA language.

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
provenance mismatches. A successful result proves internal package consistency only;
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

Portable-package mode operates on a copy and removes machine-local absolute path
prefixes from the package snapshot and manifest. Relative source locations, hashes,
baseline IDs, audit decisions, and analysis content remain unchanged.

## Review-quality gates

Completeness validation is intentionally separate from scanner candidate generation and risk assessment. Default gates require the system purpose, boundary, operating context, ground rules, analysis revision, and review team. Accepted items must identify a named reviewer, requirement, causes, local/next-higher/end effects, severity and rationale, and actual controls. Action-required items must describe the action and name its owner and date. Rejected prompts require rationale. Closed items must record implemented or explicit no-action resolution, residual assessment and rationale, verification evidence, and applicable named approval. Incomplete scans, malformed configuration or persisted records, unmatched critical patterns, corrupt references, and stale source/context/baseline validation are errors.

A passing validation report means the configured fields and workflow relationships are present. It does not prove that a failure mode is credible, a rating is correct, controls are effective, residual risk is acceptable, or required independence has been achieved. Teams should configure these gates to mirror—not replace—their approved lifecycle process.

The `sfmea doctor` preflight runs before scanning and checks only repository and
configuration readiness. Post-scan `sfmea validate` remains the authoritative
completeness gate for the generated analysis and reviewed worksheet.

## Public references

1. [NASA Software Engineering Handbook: SW Failure Modes and Effects Analysis](https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis)
2. [FAA Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety](https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf)
3. [IEC 60812:2018](https://webstore.iec.ch/en/publication/26359)

The IEC document is referenced but not reproduced. Users are responsible for obtaining and applying any required licensed standards.

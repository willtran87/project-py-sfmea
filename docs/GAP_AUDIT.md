# SFMEA guidance coverage audit

Last implementation audit: 2026-08-03

This matrix compares PySFMEA with the public NASA and FAA process guidance used by the project. “Implemented” means the repository contains a tested capability; it does not mean that scanner output has been accepted by a qualified engineering team.

| Guidance expectation | Current implementation | Evidence |
|---|---|---|
| Define the analyzed system, modules, boundary, phase, assumptions, and ground rules | Implemented through `sfmea.toml`; read-only preflight plus post-scan gates cover required context, ground rules, revision, catalog content, and malformed/unknown configuration | `sfmea doctor`, `config.py`, `validation.py`, inventory export |
| Construct a functional/block or data-flow view | Implemented as conservative architecture, static/observed sequence, and collision-safe requirement-to-hazard trace graphs in Mermaid or JSON, plus a validated canonical diagram model for generated/custom inline-SVG architecture, interface, propagation, control, traceability, state, flow, and sequence views | `architecture.py`, `visuals.py`, `diagrams.py`, `html_report.py`, diagram/report CLI commands |
| Categorize elements at an appropriate level | Functions, methods, private/nested callables, constructors, lifecycle methods, lambdas, executable module initialization, declarative data models, dependency environment, common causes, framework entrypoints, and local interface contracts are inventoried | `scanner.py`, inventory export |
| Identify functional and interface failure modes | Baseline functional guidewords plus internal/external interface, data, timing, calculation, logic, state, environment, hardware, resource, detection, and project-specific rules | `scanner.py` candidate rules |
| Consider bad data and event abnormalities | Input/model/serialization rules cover missing, wrong, stale, duplicate, range, precision, compatibility, omission, order, and timing prompts | scanner rules and methodology mapping |
| Identify specific potential causes | Each generated item contains rule-specific cause prompts; reviewers can replace or extend them; an accepted item cannot omit causes by default | analysis schema, validation, browser reviewer |
| Trace local, next-higher, and end effects | Three separate fields, transitive upstream paths, hazard linkage, and default completeness gates | `validation.py`, `architecture.py`, reviewer |
| Identify detection methods and compensating provisions | Separate existing prevention and detection controls, evidence, recommended actions, and implemented actions; action-required records cannot omit the action description/owner/date by default | model, validation, reviewer, exports |
| Identify safety requirements and hazards | Governed requirement/hazard catalogs and component mappings; unknown, unmatched, and orphaned references are reported | `config.py`, `validation.py` |
| Evaluate worst credible consequences | Ground rules and severity rationale are required by default; configured hazard severity may seed but never approve a record | configuration and quality gates |
| Support severity-focused SFMEA and defined organizational scales | Numeric severity, categorical severity, optional numeric S/O/D, and RPN arithmetic are supported | model, configuration, validation |
| Identify corrective actions and assess residual risk | Owner/date, actions taken, verification evidence, post-action ratings/category, and closure gates | model and validation |
| Assess impact of corrective/design changes | Callable, module/class, SFMEA-context, parsed dependency/lockfile, and repository baselines; move/rename continuity; transitive caller impact; explicit revalidation | scanner/store rescan tests |
| Consider dependent/common-mode failures | Project-defined common causes create cross-component items and graph edges; insufficient matches are reported | config, scanner, architecture |
| Maintain the analysis throughout the lifecycle | Stable IDs, generator/schema provenance, schema migrations, scan history, field-level review history, audit CSV, baseline IDs, malformed-record rejection, stale-write refusal, unsaved-edit protection, spreadsheet-safe CSV text, checksum-manifested portable directory/ZIP review packages, atomic publication, independent path- and archive-safe verification, and optional detached Ed25519 authenticity | store, server, report, signing, `sfmea verify-package` |
| Use cross-functional review | Named review team and required decision attribution; missing/unidentified reviewers and approvers are errors, limited role diversity is reported | config, reviewer, validation |
| Document the worksheet and unresolved issues | JSON source record, CSV/Markdown worksheet, self-contained interactive HTML report, inventory, architecture, sequence, traceability, coverage, audit export, deterministic/model summaries, and machine-readable findings | CLI and reports |
| Trace authoritative guidance to findings | Versioned and hashed NASA/FAA/NIST/IEC/CWE source catalog; exact section/page locators; typed rule mappings; per-finding citations; JSON/CSV exports; package artifacts; validation; HTML navigation; and a bounded source-to-finding diagram. FAA legacy and NASA-specific applicability are explicit | `guidance.py`, `scanner.py`, `validation.py`, `report.py`, `html_report.py`, `diagrams.py`, `sfmea citations` |
| Use automated discovery without transferring engineering authority | Grounded provider-neutral suggestions are evidence-cited, provenance-bound, schema constrained, separately reviewed, and materialized only as unreviewed records | `discovery.py`, browser and CLI suggestion workflow |
| Incorporate execution evidence | Idempotent simple and OTLP JSON imports produce baseline-linked observed relations, mapping diagnostics, and explicit incompleteness notices | `runtime.py`, sequence export, validation |
| Analyze machine-readable interface contracts | OpenAPI, Swagger, JSON Schema, and protobuf files become hashed, project-mappable contract components with extracted operations/data types, trace links, and compatibility failure prompts | `scanner.py`, inventory export, extension tests |
| Evaluate automation regression | Source-aware component/rule golden-corpus checks report missing/unexpected candidates, recall, and precision; ambiguous component names are rejected rather than merged | `sfmea evaluate`, extension tests |

## Boundaries that automation cannot close

- Static analysis cannot completely resolve reflection, monkey-patching, dependency injection, native extensions, runtime service wiring, generated code, or environment-dependent dispatch. Explicit component/interface mappings and runtime evidence remain necessary.
- Source code cannot determine a credible system consequence, hazard severity, independence claim, or risk acceptance without architecture, operational knowledge, and authorized reviewers.
- A bottom-up SFMEA does not prove top-down completeness. Projects whose process requires SFTA, FTA, STPA, or another hazard analysis must perform and reconcile that analysis separately.
- Textual test references and line/branch coverage do not prove control effectiveness. Off-nominal tests, fault injection, mutation testing, monitoring evidence, and independent verification must be supplied where required.
- PySFMEA cannot supply a licensed proprietary Action Priority table, domain certification, tool qualification, independence, an identity provider, or a legally controlled approval signature. Optional detached package signatures authenticate bytes to a trusted key; they do not provide authorization or approval workflow.
- Occurrence is not inferred from code metrics. If used, its project meaning and evidence must be defined by the responsible organization.

## Audit sources

1. [NASA Software Engineering Handbook — Software Failure Modes and Effects Analysis](https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis)
2. [FAA Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety, Appendix B](https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf)
3. [NASA-STD-8739.8B Software Assurance and Software Safety Standard](https://standards.nasa.gov/standard/nasa/nasa-std-87398)
4. [IEC 60812:2018 publication page](https://webstore.iec.ch/en/publication/26359) — referenced but not reproduced.

# Visual guide

This guide shows how PySFMEA turns static repository evidence into a reviewed, testable assurance
record. Use it for orientation; use the [operator workflow](WORKFLOW.md) for exact commands and the
[methodology](METHODOLOGY.md) for claim boundaries.

## End-to-end workflow

```mermaid
flowchart LR
    C["System context"] --> S["Static scan"]
    R["Python repository"] --> S
    E["Optional coverage, contracts, and traces"] --> S
    S --> A["Governed analysis"]
    A --> H["Human review"]
    H --> F["Accepted failure modes"]
    F --> O["Verification obligations"]
    O --> T["Hardening tests and fault injection"]
    T --> V["Reviewed execution evidence"]
    A --> P["Reports and diagrams"]
    V --> P
    P --> K["Verified handoff package"]
```

The governing rules are simple:

- `sfmea-analysis.json` is the source of truth.
- Reports, diagrams, work queues, and packages are derived views.
- Scanner results and LLM suggestions are candidates until a named reviewer decides.
- Passing tests are evidence, not automatic risk acceptance.
- Every integrity or completeness limitation remains visible.

## What the scanner discovers

```mermaid
flowchart TB
    SRC["Python source snapshots"] --> AST["Bounded AST analysis"]
    DEP["Dependencies and lockfiles"] --> INV["Repository inventory"]
    API["OpenAPI, JSON Schema, and protobuf"] --> IF["Interface inventory"]
    TST["Tests and coverage"] --> EV["Attribution evidence"]
    CFG["sfmea.toml"] --> CTX["System context"]
    RUN["Optional runtime spans"] --> OBS["Observed relationships and timing"]

    AST --> CMP["Components and call sites"]
    AST --> SIG["Failure-relevant signals"]
    CMP --> CAN["Candidate failure modes"]
    SIG --> CAN
    IF --> CAN
    CTX --> CAN

    CAN --> ANA["Governed SFMEA analysis"]
    INV --> ANA
    EV --> ANA
    OBS --> ANA
```

Static analysis identifies evidence and prompts. It cannot determine the credible end effect,
severity, control effectiveness, or acceptability of residual risk without engineering review.

## Failure cascade and containment

```mermaid
sequenceDiagram
    participant U as Upstream caller
    participant C as Analyzed component
    participant D as Dependency
    participant B as Circuit breaker
    participant S as Safe or degraded state

    U->>C: Request
    C->>D: Dependency call
    D--xC: Timeout or invalid response
    C->>B: Record failure
    alt Breaker threshold reached
        B-->>C: Open and reject bounded calls
        C->>S: Enter reviewed fallback
    else Threshold not reached
        C-->>U: Propagated delay or failure
    end
    Note over C,B: Static structure proposes the path
    Note over D,S: Runtime and fault evidence support observed behavior
```

The propagation view keeps four meanings separate:

| Visual evidence | Meaning | It does not prove |
|---|---|---|
| Static caller edge | A bounded syntactic exposure path exists. | Runtime reachability or causality. |
| Runtime-corroborated edge | The relationship was observed in an imported scenario. | That the failure effect propagated. |
| `not_observed` edge | The static relation was absent from the supplied trace. | Unreachability. |
| Containment boundary | A breaker or fallback candidate was detected. | Effective containment without reviewed fault evidence. |

## Finding-to-test lifecycle

```mermaid
stateDiagram-v2
    [*] --> Candidate
    Candidate --> Rejected: Reviewer rejects
    Candidate --> Accepted: Reviewer accepts
    Accepted --> Planned: Obligation has stimuli and oracles
    Planned --> Implemented: Test binding registered
    Implemented --> Executed: Approved sandbox run or imported evidence
    Executed --> Reviewed: Independent evidence review
    Reviewed --> Verified: Every criterion passes on current baseline
    Verified --> Revalidation: Source, context, or evidence changes
    Revalidation --> Planned
    Rejected --> [*]
    Verified --> [*]
```

An obligation should answer all of these questions:

- What failure is injected or stimulated?
- Under which mode, state, timing, and resource conditions?
- What local, system, safe-state, and recovery behavior is expected?
- Which oracle decides pass or fail?
- Which artifacts prove the exact test and execution?
- Who independently reviewed the evidence?

## Governed LLM-generated test path

```mermaid
flowchart TB
    subgraph PERTEST["Per-test evidence"]
        O["Accepted planning-ready obligation"] --> P["Bounded source-grounded packet"]
        P --> M["Model proposes one allowlisted test"]
        M --> X["Closed response + import-qualified target validation"]
        X --> H["Named human publication review"]
        H --> E["Exact registration + restricted execution"]
        E --> I["Observed stimulus + criteria + independent evidence review"]
        I --> R{"7 readiness gates"}
        I --> HTML["HTML: 5 analysis-resident evidence gates"]
        H --> EXT["External proposal + publication receipts"]
        EXT --> R
    end
    subgraph SUBJECT["Subject qualification"]
        C["Independent generated-test corpus"] --> Q{"14 declared / 15 artifact-backed gates"}
        Q --> S["Content-sealed result"]
        S --> V["Exact-corpus semantic replay"]
    end
    R --> D{"Human promotion decision"}
    V --> D
```

The lanes are deliberately independent. A qualified provider/model/prompt does not make one test
ready, and one ready test does not qualify the model generally. The HTML report projects only the
five gates available in the governed analysis—registration, passing restricted execution,
observed stimulus, complete criteria, and independent evidence review. The exact proposal and
publication receipt remain separately verified artifacts, so seven-gate readiness must be checked
with `sfmea assurance-test-readiness`. Model qualification uses
`sfmea assurance-test-quality-evaluate` and `sfmea assurance-test-quality-verify`.

## Evidence trust ladder

```mermaid
flowchart LR
    D["Declared claim"] --> B{"Exact bytes bound?"}
    B -- No --> U["Uncredited"]
    B -- Yes --> R{"Claims replay and reconcile?"}
    R -- No --> X["Blocking finding"]
    R -- Yes --> I{"Independent review required?"}
    I -- Missing --> X
    I -- Satisfied --> Q{"Unique evidence identity?"}
    Q -- Duplicate --> X
    Q -- Unique --> C["Credited evidence"]
    C --> G{"Quality and governance gates pass?"}
    G -- No --> X
    G -- Yes --> H["Eligible for handoff"]
```

For validation and LLM evidence, the program reports:

- declared records;
- uniquely credited records;
- duplicate corpus declarations;
- count-backed and artifact-verified records;
- macro and population-weighted micro metrics;
- subject-bound LLM evaluations and claim-weighted unsupported-claim rate.

A copied validation corpus or semantically repackaged LLM corpus cannot increase repository
coverage, cases, samples, claims, or quality metrics. LLM identity ignores descriptive metadata,
JSON formatting, and sample order while retaining corpus format, subject, IDs, and decisions.

## Multi-repository assurance

```mermaid
flowchart TB
    subgraph API["API repository"]
        A1["Governed analysis"]
        A2["Findings and hazards"]
        A1 --> A2
    end

    subgraph WORKER["Worker repository"]
        W1["Governed analysis"]
        W2["Findings and hazards"]
        W1 --> W2
    end

    A2 --> REL["Cross-service relationship contract"]
    W2 --> REL
    REQ["External requirements snapshot"] --> PRG["Assurance program"]
    REL --> PRG
    EVD["Timing, recovery, and fault evidence"] --> PRG
    VAL["Independent validation corpora"] --> PRG
    LLM["Subject-bound LLM quality corpora"] --> PRG
    GOV["Named program approvals"] --> PRG
    PRG --> VER["JSON, Markdown, and HTML verdict"]
```

The program binds analyses; it does not merge them. Repository-qualified IDs preserve ownership,
and explicit relationship contracts carry deadline, timeout, retry, ordering, clock, and
circuit-breaker expectations.

## Output map

| Need | Best output | Command | Primary reviewer |
|---|---|---|---|
| Navigate the complete analysis | Self-contained HTML | `sfmea report` | Cross-functional review team |
| Exchange diagram data | Canonical diagram JSON | `sfmea diagram` | Architecture and tooling teams |
| Triage incomplete work | Workflow status and queue | `sfmea status`, `sfmea queue` | Analysis owner |
| Plan hardening tests | Assurance register/work queue | `sfmea assurance` | Verification team |
| Inspect generated-test evidence | HTML LLM-generated test governance card plus external proposal/receipt | `sfmea report`, `sfmea assurance-test-readiness` | Verification and independent evidence reviewers |
| Qualify generated-test automation | Content-sealed generated-test quality result bound to its exact corpus | `sfmea assurance-test-quality-evaluate`, `sfmea assurance-test-quality-verify` | Independent model-evaluation authority |
| Review source coverage | Inventory and coverage views | `sfmea inventory`, `sfmea coverage` | Tool and software assurance |
| Audit NASA/FAA relationships | Citation trace | `sfmea citations` | Safety and compliance reviewers |
| Transfer a frozen review set | Verified ZIP package | `sfmea package`, `sfmea verify-package` | Independent recipient |
| Review system-level evidence | Program HTML/JSON/Markdown plus exact report receipt | `sfmea program-verify`, `sfmea program-report-verify` | System assurance authority |

## Diagram portfolio

| Diagram | Question answered | Important qualification |
|---|---|---|
| Architecture | Which components depend on which components? | Bounded static structure. |
| Interface flow | Where are internal, external, and unresolved calls? | Receiver resolution is confidence-labeled. |
| Data flow | Which bounded value/alias relationships cross components? | Static flow is not runtime information-flow proof. |
| Sequence | In what lexical/evaluation order do calls occur? | Not path-sensitive execution proof. |
| Failure propagation | Where could an effect be exposed upstream? | Exposure is not causal sufficiency. |
| Circuit breaker | Which state roles and transitions were detected? | Conceptual states and review gaps remain explicit. |
| Control coverage | Which findings have prevention, detection, and evidence? | Presence does not establish effectiveness. |
| Traceability | How do requirements, hazards, findings, and components connect? | A relationship is not verification evidence. |
| Guidance traceability | Which guidance locators and mappings support findings? | A citation is rationale, not compliance approval. |
| Assurance traceability | How do findings connect to obligations, tests, executions, and evidence? | Registration or execution alone is not readiness. |
| SFTA | How are reviewed top events, gates, and basic events structured? | Generated structure is not quantitative risk proof. |
| Evidence fabric | Which cross-domain records and discrepancies connect? | Correlation and lineage do not establish causality or authority. |

Generate and verify the complete portfolio:

```powershell
sfmea diagram sfmea-analysis.json -o diagrams.json
sfmea diagram-verify diagrams.json --analysis sfmea-analysis.json
sfmea report sfmea-analysis.json -o sfmea-report.html --json
sfmea report-verify sfmea-report.html --analysis sfmea-analysis.json
```

## Review order

1. Confirm system context and repository accounting.
2. Review critical components, interfaces, and unresolved calls.
3. Confirm failure modes, causes, and all three effect levels.
4. Inspect propagation, sequence, timing, and containment assumptions.
5. Validate guidance applicability and citation relationship strength.
6. Accept or reject candidates; assign owners and actions.
7. If generated-test automation is used, qualify the exact provider/model/prompt independently and
   retain the replayable result.
8. Implement obligations and collect controlled evidence; apply every per-test readiness gate.
9. Reconcile all blockers, verify outputs, and package the exact analysis state.

## Authority boundary

PySFMEA can verify structure, provenance, content binding, metric reconciliation, and configured
workflow gates. It cannot provide:

- system safety judgment or risk acceptance;
- reviewer identity authentication or authorization;
- proof of causal completeness or schedulability;
- proof that a corpus is representative;
- regulatory approval, certification, or tool qualification.

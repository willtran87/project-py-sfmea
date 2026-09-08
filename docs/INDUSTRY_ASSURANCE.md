# Industry assurance profiles

PySFMEA separates five questions that are often blurred together:

1. Did the scanner create a bounded and reproducible candidate analysis?
2. Did authorized engineers review the findings and verification evidence?
3. Were the objectives of the project-selected standards addressed?
4. Has the tool evidence been independently benchmarked and assembled for qualification review?
5. Does an authorized certification, regulatory, or risk authority accept the result?

The tool can organize evidence for the first four. It cannot answer the fifth.

```mermaid
flowchart LR
    R["Repository baseline"] --> A["Governed analysis"]
    A --> C["Standards conformance workspace"]
    S["Licensed or public standards"] --> SLG["Edition/status review ledger"]
    SLG --> C
    TAX["Exact official CWE/CAPEC XML"] --> TX["Content-addressed taxonomy"]
    TX --> C
    C --> O["Objective assessments"]
    O --> XW["Objective/finding/evidence crosswalk"]
    A --> E["Tests and reviewed evidence"]
    SARIF["External SARIF 2.1.0 producers"] --> SF["Exact-byte SARIF fusion"]
    SF --> A
    A --> OSCAL["OSCAL Assessment Results observations"]
    E --> AC["Structured assurance case"]
    O --> AC
    Q["Independent qualification campaign"] --> B["Pre-registered benchmark assessment"]
    REG["Governed external benchmark registry"] --> BA["Independently reviewed adapter"]
    BA --> BX["Pinned isolated execution receipt"]
    BX --> B
    FUZZ["Atheris / ClusterFuzzLite campaign"] --> FE["Corpus, coverage, crash-triage receipt"]
    FE --> E
    B --> RQ["Release non-inferiority and leakage gate"]
    B --> TQ["Tool qualification dossier"]
    TQ --> AC
    AC --> GSN["GSN semantic projection"]
    AC --> IX["SACM / SFPM / ReqIF exchange"]
    IX --> NV["Normative schema validation"]
    NV --> RT["Independent receiving-tool round trip"]
    A --> DEP["HAZOP / RBD / Markov engineering"]
    A --> STPA["STPA / CAST workbench"]
    A --> COV["Requirements / MC/DC evidence"]
    COVRUN["Exact coverage.py observation"] --> COV
    A --> QFTA["Exact quantitative FTA"]
    A --> QE["ISO 25040 evaluation campaign"]
    A --> SL["PHA / FHA / PSSA / SSA / Operations"]
    A --> CCFA["Common-cause candidates"]
    VULN["Vulnerability evidence"] --> SSVC["Controlled SSVC decision table"]
    SSVC --> SEC["CVSS v4 / ASVS / SSVC prioritization"]
    B --> LAB["Independent laboratory governance"]
    B --> VP["Industry validation portfolio"]
    RT --> VP
    COVRUN --> VP
    UX["Representative analyst usability study"] --> VP
    VP --> D
    SL --> D
    CCFA --> D
    RT --> D{"Authorized decision"}
    DEP --> D
    STPA --> D
    COV --> D
    QFTA --> D
    QE --> D
    SEC --> D
    LAB --> D
    RQ --> D
    GSN --> D
    SSVC --> D
    D -->|external authority| X["Approval, certification, or risk acceptance"]
```

The executable 0.73.0 closure loop keeps generated discovery distinct from reviewed evidence:

```mermaid
flowchart LR
    R["Exact Python repository"] --> S["Static SFMEA scan"]
    S --> B["Direct semantic benchmark"]
    S --> T["ISO 29119-aligned test dossier"]
    T --> I["Implemented and executed tests"]
    I --> E["Reviewed assurance evidence"]
    SB["CycloneDX SBOM"] --> VA["OSV version applicability"]
    VA --> VW["Reachability / exposure / SSVC / remediation"]
    CF["ClusterFuzzLite CI artifacts"] --> CI["Exact artifact intake"]
    CI --> FC["Operator-completed fuzz campaign"]
    B --> Q{"Independent evidence gate"}
    E --> Q
    VW --> Q
    FC --> Q
    Q -->|external authority| D["Release or qualification decision"]
```

The semantic corpus bundled with the package is a regression and calibration control. It is not
independent evidence. External corpus custody, labels, representativeness, execution authority,
and acceptance remain separate evidence inputs.

Qualification-strengthening evidence is now explicitly layered:

- `benchmark-source-health-*` blocks execution eligibility until every suite has reviewed,
  immutable source, revision, license, schema, maturity, and independent-review evidence.
- `benchmark-native-*` translates supported OWASP CSV, TestGenEval JSON, and TDD/SWE-bench
  JSONL results while keeping runner, corpus, oracle, and environment evidence unresolved.
- `benchmark-item-quality*` requires exact normalized-case accounting, all nine quality criteria,
  criterion-level evidence, two reviewers independent of the audit authority, bounded exclusions,
  no open remediation, and exact replay before a benchmark claim becomes eligible.
- `benchmark-case-inventory*` gives suites without a qualified native adapter the same exact,
  source-bound population and item-review path; the validation portfolio requires a passing audit
  for every declared suite and replays both the population and review sources.
- `inspect-ai-*` preserves exact Inspect JSON log identity, configuration hashes, samples, scores,
  transcript/tool/store identities, errors, and usage without reinterpreting scorer semantics.
- `inspect-ai-conformance*` separately validates the retained log against a supplied official
  Inspect schema and binds the exact schema, run configuration, evaluator version, and evidence.
- `deployed-tevv-*` and `genai-telemetry-*` govern repeated production evaluation, explicit
  thresholds, incidents, circuit breakers, rollback, change traceability, and version-pinned
  OpenTelemetry GenAI semantic conventions with exact raw-span replay.
- `confidence-calibrate*` reports Brier score, expected calibration error, Wilson intervals,
  per-stratum results, and selective risk versus coverage.
- `causal-validate*` compares static cascade/effect predictions with injected-fault traces,
  deadlines, circuit-breaker transitions, and recovery observations. Format 2 computes
  conventional precision and recall per scenario, preventing an observation in one scenario from
  satisfying a prediction in another, and reports exact ordered-path/effect and eligible-population
  rates.
- `sarif-conformance*` uses a locally supplied official schema and adds bounded consumer-semantic
  checks; `scorecard-*` maps Scorecard checks only to candidate OSPS/SSDF/SLSA evidence.
- `standards-watchlist*` tracks relevant drafts—including NIST AI 200-2 TEVV-Athlon—separately
  from adopted profiles; NIST AI 800-4 is a current guidance profile for repeated post-deployment
  TEVV, monitoring, incident response, rollback, and change reassessment.

No generated artifact substitutes for lawful corpus custody, external labels, independent
execution, controlled normative text, accreditation, qualification, or risk acceptance.

## Governed standards catalog

```powershell
sfmea standards-catalog
sfmea standards-catalog --json
sfmea standards-catalog -o standards-catalog.json
```

The content-addressed catalog provides 144 selectable profiles. Select only profiles made
applicable by the system, market, contract, and approved assurance plan.

| Profile | Intended use | Normative text |
|---|---|---|
| `iec-60812-2018` | General FMEA/FMECA planning, execution, treatment, and maintenance | Licensed |
| `sae-j1739-202605` | DFMEA, FMEA-MSR, and PFMEA process | Licensed; proprietary rating/AP material is not bundled |
| `faa-airborne-do178c-do330` | Airborne software lifecycle and tool qualification | FAA AC is public; RTCA/EUROCAE material is licensed |
| `faa-do-331-model-based` / `faa-do-332-object-oriented` | Airborne model-based and object-oriented technology considerations | FAA AC navigation is public; supplements are licensed |
| `iec-61508-3-2010` | Functional-safety software lifecycle | Licensed |
| `iso-26262-6-2018` | Automotive software safety lifecycle | Licensed |
| `nist-ssdf-1.1` | Secure software development | Public |
| `iso-25010-29119` | Product-quality model and governed testing | Licensed |
| `iso-29119-11-2020` | Risk-based testing guidance for AI-based systems | Licensed |
| `nist-ai-600-1-llm` | LLM-assisted analysis and generated-test governance | Public |
| `iso-15026-2-2022` | Structured assurance-case content and lifecycle governance | Licensed |
| `iso-5338-2023` | AI system lifecycle integration | Licensed |
| `iso-42005-2025` | AI impact-assessment process | Licensed |
| `iso-pas-8800-2024` | Road-vehicle safety and AI assurance | Licensed |
| `ul-4600-edition-3` | Safety-case evaluation for autonomous products | Licensed |
| `aiag-vda-fmea-2019` | Seven-step automotive FMEA method | Licensed; proprietary rating/AP material is not bundled |
| `sae-arp4754b-arp4761a` | Aircraft/system development and safety assessment | Licensed |
| `iso-12207-2026` | Current software lifecycle processes | Licensed |
| `iso-330xx-process-assessment` | Governed process assessment and capability evidence | Licensed |
| `openssf-osps-2026-02-19` | Superseded open-source project security baseline retained for historical evidence | Public |
| `openssf-osps-2026-08-28` | Current open-source project security baseline | Public |
| `iso-42001-23894-ai-governance` | AI management and risk governance | Licensed |
| `nist-ssdf-800-218a-genai` | Generative-AI secure-development profile | Public |
| `iso-21434-21448-automotive` | Automotive cybersecurity and SOTIF | Licensed |
| `medical-14971-62304-81001` | Medical risk, software lifecycle, and health-software security | Licensed |
| `en-50716-2023-rail` | Railway software lifecycle | Licensed |
| `iec-62443-4-1-2018` | Industrial secure product development | Licensed |
| `iec-62443-3-2-2020` | IACS system security risk assessment and security-level target governance | Licensed |
| `iec-61511-process-safety` | Process-industry functional safety | Licensed |
| `iso-29148-2018` | Requirements engineering and bidirectional traceability | Licensed |
| `iso-42010-2022` | Architecture descriptions, viewpoints, views, and correspondences | Licensed |
| `iso-15288-2023` / `iso-15289-2019` | System lifecycle processes and controlled information items | Licensed |
| `iso-16085-2021` / `iso-31000-2018` / `iec-31010-2019` | Lifecycle and organizational risk management and technique selection | Licensed |
| `iec-61025-2006` / `iec-62502-2010` / `iec-62740-2015` | Fault tree, event tree, and root-cause analysis | Licensed |
| `omg-sysml-2-2025` / `oasis-oslc-lifecycle-2022` | System-model and lifecycle interoperability | Public specifications |
| `iec-61882-2016` / `iec-61078-2016` / `iec-61165-2006` | HAZOP, reliability block diagrams, and Markov techniques | Licensed |
| `iso-5055-25023-quality-measurement` / `ieee-1012-2024` | Automated source-quality measures and independent V&V | Licensed |
| `oasis-csaf-2-0` | Machine-readable security advisories | Public specification |
| `slsa-1-2` | Build and Source track provenance and supply-chain hardening | Public specification |
| `iec-62443-4-2-2019` / `cisa-ssvc` | Component security and stakeholder-specific vulnerability decisions | Licensed / public guidance |
| `iso-5259-data-quality` / `iso-25059-ai-quality` / `iso-tr-5469-2024` | AI data quality, system quality, and functional-safety considerations | Licensed |
| `iso-25040-2024` / `ieee-1633-2016` | Quality evaluation and software reliability programs | Licensed |
| `owasp-asvs-5-0` / `first-cvss-4-0` | Application-security verification and vulnerability severity | Public |
| `iso-27034-1-2011` | Application-security governance and lifecycle controls | Licensed |
| `nist-ai-rmf-1-0` / `iso-24029-robustness` | AI risk management and neural-network robustness | Public / licensed |
| `automotive-spice-4-0` / `faa-do-326a-ed-202a` | Automotive process assessment and aircraft cybersecurity | Mixed |
| `iec-82304-1-2016` / `iso-17025-2017` | Health-software product safety and laboratory competence | Licensed |
| `mit-stpa-cast` | STPA hazard analysis and CAST incident learning | Public |
| `nist-csf-2-0` / `iso-27001-27002-27005` | Organizational cybersecurity governance, controls, and risk management | Public / licensed |
| `iso-27701-2025` / `iso-29147-30111` | Privacy management and coordinated vulnerability lifecycle | Licensed |
| `iso-15408-18045-2026` | Common Criteria product-security evaluation and evaluator methodology | Licensed |
| `iso-9241-210-171` / `iec-62366-1` | Human-centred design, software accessibility, and medical usability engineering | Licensed |
| `iso-22301-2019` | Business continuity, recovery objectives, and exercises | Licensed |
| `iso-42006-2025` | AI management-system certification-body competence and impartiality | Licensed |
| `faa-do-333-formal-methods` | FAA-recognized airborne formal-method verification | Public FAA guidance; licensed supplement |
| `iso-15026-1-2025` / `iso-15026-3-2023` / `iso-15026-4-2021` | Assurance lifecycle, integrity-level, and assurance-assessment governance | Licensed |
| `openchain-5230-18974` | Open-source security and license-compliance program governance | Public specification / ISO adoption |
| `sbom-iso-5962-ecma-424` | SBOM structure, quality, lifecycle, and exchange governance | Public ECMA specification / ISO adoption |
| `ieee-730-2026` | Software quality-assurance planning, activities, records, nonconformance, and improvement | Licensed |
| `owasp-wstg-v42` | Version-pinned web-application security test planning, execution, evidence, and retesting | Public |
| `nist-sp-800-115` | Technical security testing and assessment planning, execution, analysis, and remediation | Public |
| `nist-samate-scas-500-268-270` | Independent source-code security-analysis specification, test plan, metrics, and result review | Public |
| `iso-29119-3-2021` / `iso-29119-4-2021` | Governed test documentation and specification/structure/experience-based test techniques | Licensed |
| `iso-29119-1-2022` / `iso-29119-5-2024` / `iso-29119-6-2021` | Testing concepts, keyword-driven testing, and agile-project testing guidance | Licensed |
| `nasa-gsfc-hdbk-8004` | NASA Goddard guidance for living FMEA/FMECA development, use, and maintenance | Public NASA guidance |
| `iso-42119-2-2025` | Risk-based testing of AI systems and AI-generated test workflows | Licensed |
| `nist-ai-100-2e2025-adversarial-ml` | Adversarial-ML taxonomy, lifecycle threats, mitigations, and change review | Public NIST |
| `owasp-agentic-ai-2025` | Agent identity, memory, tools, delegation, autonomy, containment, and adversarial evaluation | Public non-normative guidance |
| `iso-12792-2025-ai-transparency` | Stakeholder-oriented AI transparency information and lifecycle traceability | Licensed |
| `iso-24027-12791-ai-bias` | AI bias context, measurement, treatment, monitoring, and tradeoff evidence | Licensed |
| `iso-27004-2016-security-measurement` | Information-security measurement and evaluation; replacement-edition watch required | Licensed |
| `iec-61508-7-2010-techniques` | Functional-safety verification, test, tool, and technique-selection evidence | Licensed |
| `iso-26262-8-9-2018-supporting-analysis` | Automotive supporting processes, tool confidence, ASIL decomposition, and safety analysis | Licensed |
| `owasp-api-security-2023` | API inventory, authorization, abuse, resource, SSRF, configuration, and dependency risks | Public non-normative guidance |
| `tmmi-2-0-test-maturity` | Managed, defined, measured, and optimizing test-process maturity | Public model; accredited assessment is external |
| `osv-kev-epss-vulnerability-intelligence` | Exact affected-package, known-exploitation, and exploit-probability decision inputs | Public specifications/data |
| `iso-15939-2017` / `iso-25020-2019` / `iso-25041-2012` | Measurement validity, quality-measure construction, and developer/acquirer/independent-evaluator guidance | Licensed |
| `iso-25012-25024-data-quality` | Quality model and quantitative measures for findings, labels, corpora, and traces | Licensed |
| `faa-do-356a-do-355a` | Airworthiness security assessment and continuing-airworthiness security | FAA navigation is public; RTCA/EUROCAE material is licensed |
| `nist-sp-800-190` / `nist-sp-800-207a` | Container security and cloud-native zero-trust enforcement | Public |
| `openssf-security-insights-2-2` | Machine-readable project security posture and disclosure | Public |
| `eu-cra-2024-2847` | Phased EU product-security, vulnerability-handling, reporting, and technical-file evidence readiness | Public regulation/guidance; legal review required |
| `nasa-7150-8739-software-assurance` | NASA software engineering, assurance, safety, and measurement governance | Public NASA directives and standards |
| `iso-9001-2026-90003-2018` | Quality-management system controls specialized for software | Licensed |
| `iso-17020-17029-19011-assessment-governance` | Impartial inspection, validation/verification, and audit-program governance | Licensed |
| `iso-17043-13528-benchmark-proficiency` | Proficiency scheme design, stable items, assigned values, statistical evaluation, and impartial governance | Licensed |
| `iso-27036-software-supply-chain` | Supplier and multi-tier software/cloud relationship security from selection through exit | Licensed |
| `iso-20000-ieee-2675-service-devops` | Service-management and reliable secure DevOps lifecycle governance | Licensed |
| `nist-800-61-iso-27035-incident-response` | Risk-integrated incident preparation, response, recovery, evidence, and learning | Public NIST / licensed ISO |
| `nist-800-204c-d-cloud-devsecops` | Cloud-native microservice and CI/CD software-supply-chain assurance | Public NIST |
| `iso-27017-2026-cloud-security` | Cloud-provider/customer shared controls, isolation, operations, and exit | Licensed |
| `iso-17065-17067-product-certification` | Product-certification scheme and certification-body governance | Licensed |
| `ieee-828-2012-configuration-management` | Software configuration-management planning and control | Licensed |
| `machinery-iec-62061-iso-13849` | Safety-related machinery control systems and software | Licensed |
| `faa-do-278a-do-200b-ground-data-assurance` | Ground CNS/ATM software and aeronautical-data assurance | FAA navigation is public; RTCA material is licensed |
| `nuclear-iec-61513-60880-62138-62645` | Nuclear I&C software safety and cybersecurity lifecycle controls | Licensed |
| `mil-std-882e-system-safety` | Defense system-safety program and hazard-risk governance | Public US DoD standard |
| `medical-iso-13485-fda-csa` | Medical-device QMS and risk-based computer software assurance | Mixed licensed standard / public FDA guidance |

Catalog objectives are original summaries and navigation aids. A project using a licensed
standard must consult its controlled normative copy and record the adopted edition, tailoring,
customer-specific requirements, and interpretation authority.

Make standards currency and external security taxonomy releases reviewable evidence rather than
implicit tool assumptions:

```powershell
sfmea standards-lifecycle-init --authority "Standards owner" -o standards-lifecycle.json
# For every catalog profile, record observed edition/status, official source evidence, review and
# next-review dates, disposition, reviewer, and any required reapproval reference.
sfmea standards-lifecycle-seal standards-lifecycle.json -o standards-lifecycle.json
sfmea standards-lifecycle-verify standards-lifecycle.json --json

sfmea security-taxonomy-import C:\controlled\cwec_latest.xml --kind cwe `
  --authority "Product security" -o cwe-taxonomy.json
sfmea security-taxonomy-verify cwe-taxonomy.json `
  --source C:\controlled\cwec_latest.xml --json
```

The lifecycle verifier binds all 118 records to the exact shipped catalog and rejects missing,
overdue, changed, or unreviewed records. The taxonomy importer accepts bounded official MITRE CWE
or CAPEC XML, preserves identifiers, status, relationships, release metadata, and source digest,
and can regenerate the artifact from the exact XML bytes. Neither workflow decides applicability
or substitutes for the controlled normative publication.

## External analysis, OSCAL, benchmark, and fuzz evidence

PySFMEA can now consume external scanner evidence without flattening provenance or treating tool
agreement as truth:

```powershell
sfmea sarif-fuse analysis.json bandit.sarif semgrep.sarif `
  --authority "Security review board" --evidence-ref "evidence://scanner/run-42" `
  -o sarif-fusion.json
sfmea sarif-fuse-verify sarif-fusion.json --analysis analysis.json `
  --sarif bandit.sarif --sarif semgrep.sarif --json
sfmea oscal-assessment-results analysis.json --authority "Assurance board" `
  -o assessment-results.oscal.json
sfmea oscal-assessment-results-verify assessment-results.oscal.json `
  --analysis analysis.json --json
sfmea oscal-assessment-plan analysis.json --authority "Assessment lead" `
  --ssp-href ./system-security-plan.json -o assessment-plan.oscal.json
sfmea oscal-assessment-plan-verify assessment-plan.oscal.json `
  --analysis analysis.json --json
sfmea oscal-poam analysis.json --authority "Risk owner" `
  --ssp-href ./system-security-plan.json -o poam.oscal.json
sfmea oscal-poam-verify poam.oscal.json --analysis analysis.json --json
```

SARIF intake is bounded, version-gated to 2.1.0, exact-byte hashed, and lossless at the result
level. Mapping requires one unambiguous component source range. Clusters require the same source
coordinate and taxonomy/rule basis; they are an accounting view, never automatic deduplication.
The OSCAL projections use deterministic UUIDs and exact analysis bindings. The Assessment Plan
defines review activities and subjects; Assessment Results represents active SFMEA records as
observations; POA&M represents unresolved work as actions. None asserts unsupported control
effectiveness. The generated Assessment Plan and POA&M pass the official NIST OSCAL 1.2.3 JSON
schemas. Retain an `industry-schema-validate` receipt and an independent receiving-tool round trip
for interoperability credit.

External benchmark and fuzz execution use editable governed contracts:

```powershell
sfmea benchmark-suite-catalog
sfmea benchmark-execution-init --suite testgeneval --authority "Protocol owner" `
  -o benchmark-execution.json
# Create an adapter and record its exact suite revision, tree/source digest, license, digest-pinned
# image, argv, fixed output, normalization mappings/policies, owner, and independent reviewer.
sfmea benchmark-adapter-init --suite testgeneval --authority "Adapter owner" `
  -o benchmark-adapter.json
sfmea benchmark-adapter-seal benchmark-adapter.json -o benchmark-adapter.json
sfmea benchmark-adapter-verify benchmark-adapter.json --json
# Record the matching pinned dataset revision/tree digest, digest-pinned local image, argv,
# resource budget, independent roles, and evidence destinations. The container must emit
# /evidence/benchmark-observations.json using the public benchmark-observations schema.
sfmea benchmark-execution-seal benchmark-execution.json -o benchmark-execution.json
sfmea campaign-snapshot C:\path\to\suite
sfmea benchmark-execution-run benchmark-execution.json C:\path\to\suite `
  --adapter benchmark-adapter.json `
  --evidence-directory .artifacts\benchmark -o benchmark-execution.completed.json
sfmea benchmark-execution-verify benchmark-execution.completed.json --json
sfmea benchmark-observations-verify .artifacts\benchmark\benchmark-observations.json --json

sfmea fuzz-campaign-init --authority "Campaign owner" -o fuzz-campaign.json
# Record target/config/corpus digests, pinned image/argv, and resource limits. The container must
# emit /evidence/fuzz-result.json with runtime coverage and complete crash triage.
sfmea fuzz-campaign-seal fuzz-campaign.json -o fuzz-campaign.json
sfmea fuzz-campaign-run fuzz-campaign.json C:\path\to\repository `
  --evidence-directory .artifacts\fuzz -o fuzz-campaign.completed.json
sfmea fuzz-campaign-verify fuzz-campaign.completed.json --json
```

Eligibility requires an independently reviewed, exact-revision-matched adapter, a digest-pinned
image, exact non-placeholder source/corpus/configuration
digests, `network=none`, a read-only source mount, explicit resource limits, complete execution,
distinct governing identities, and evidence references. Fuzzing additionally requires coverage
evidence and complete disposition of each reproducible crash. Each benchmark case binds the exact
input and ground-truth bytes; each attempt binds output, generated test, environment, execution,
coverage, and mutation evidence. Each fuzz campaign binds the exact coverage observation plus
input, stack, and reproducer bytes for every crash. PySFMEA records and verifies these
facts; it does not download third-party corpora, authenticate people, validate labels, accredit a
laboratory, or turn a crash-free campaign into a defect-absence claim.

Case-level benchmark observations preserve the model, prompt-template revision, temperature,
seed, suite revision/snapshot, container image, and argv. Their verifier independently recomputes
pass@1/pass@k, resolved rate, coverage and mutation changes, flakiness, unsafe-oracle rate,
latency, input/output tokens, cost, errors, and TP/FP/FN/TN-derived precision, recall,
specificity, and F1. This supports LLM-generated-test evaluation without treating a generated
test, mutation kill, or benchmark pass as engineering acceptance.

### Case-paired differential comparison

Aggregate comparator scores can hide which cases disagree. The differential workflow retains each
independent label and each tool prediction, calculates per-tool confusion matrices, performs an
exact paired McNemar test, and creates a review queue for every discordant case. A comparison is
portfolio-eligible only after exact source replay, pinned suite and tool provenance, separated
label/adjudication authorities, complete evidence references, and disposition of all disagreements
when the policy requires it.

```powershell
sfmea benchmark-differential-init --authority "Comparison owner" -o differential.json
# Add the pinned suite, independent authorities, tools, labels, predictions, and adjudications.
sfmea benchmark-differential-seal differential.json -o differential.sealed.json
sfmea benchmark-differential-assess differential.sealed.json -o differential.assessment.json
sfmea benchmark-differential-verify differential.assessment.json `
  --source differential.sealed.json --json
```

Add both exact paths to the portfolio source and enable the policy gate when differential evidence
is mandatory:

```json
{
  "policy": {"case_paired_differential_required": true},
  "differential_evidence": [
    {
      "id": "semantic-comparison",
      "assessment_path": "differential.assessment.json",
      "source_path": "differential.sealed.json"
    }
  ]
}
```

The p-value characterizes paired correctness asymmetry under the declared population. It does not
establish practical significance, label correctness, population representativeness, or tool
qualification. Agreement between tools is never promoted to ground truth.

### Operational vulnerability intelligence

Use project-acquired snapshots so network state cannot change during analysis:

```powershell
sfmea vulnerability-intelligence-import `
  --osv C:\controlled\osv.json `
  --kev C:\controlled\known_exploited_vulnerabilities.json `
  --epss C:\controlled\epss_scores.csv.gz `
  --authority "Product security" --observed-at 2026-08-30T12:00:00Z `
  --max-age-days 2 -o vulnerability-intelligence.json
sfmea vulnerability-intelligence-verify vulnerability-intelligence.json `
  --osv C:\controlled\osv.json `
  --kev C:\controlled\known_exploited_vulnerabilities.json `
  --epss C:\controlled\epss_scores.csv.gz --as-of 2026-08-31T00:00:00Z --json
sfmea vulnerability-intelligence-match vulnerability-intelligence.json `
  --sbom bom.cdx.json -o vulnerability-leads.json
```

The importer retains exact bytes, aliases, PURLs, affected ranges, KEV fields, EPSS probability,
percentile, model metadata, and acquisition time. Identity matches remain `applicability=unresolved`:
ecosystem version semantics, reachability, exposure, safety impact, SSVC disposition, and risk
acceptance require separate evidence and authority.

### Continuous fuzzing and performance history

`.clusterfuzzlite/` supplies the official Python/Atheris build integration. The immutable-SHA-pinned
workflow runs ten-minute code-change fuzzing for pull requests and a longer weekly batch campaign,
minimizes crashes, and emits SARIF. This CI signal complements—but does not replace—the governed
`fuzz-campaign` receipt, which binds corpus, coverage, crash reproduction, triage, and approval.

Combine at least three exact, comparable `pysfmea-scan-performance-2` receipts:

```powershell
sfmea performance-history performance-0.69.json performance-0.70.json performance-0.71.json `
  --authority "Performance review board" --minimum-observations 3 `
  --max-runtime-regression-percent 10 --max-memory-regression-percent 10 `
  -o performance-history.json
sfmea performance-history-verify performance-history.json --json
```

The gate fails when environment, repository population, baseline, or cache mode differs. A passing
result is a non-regression statement for that controlled population—not a universal throughput
claim.

Authenticate exact release evidence with an offline Sigstore bundle:

```powershell
sfmea sigstore-verify sfmea-analysis.json sfmea-analysis.sigstore.json `
  --trusted-root trusted-root.json `
  --certificate-identity https://github.com/example/project/.github/workflows/assure.yml@refs/heads/main `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  --authority "Release assurance" -o sigstore-verification.json
sfmea sigstore-receipt-verify sigstore-verification.json `
  --artifact sfmea-analysis.json --bundle sfmea-analysis.sigstore.json `
  --trusted-root trusted-root.json --json
```

The command invokes the current `cosign verify-blob --bundle --trusted-root` interface without a
shell and records the exact artifact, bundle, local trusted root, expected certificate
identity/OIDC issuer, cosign version, exit code, and output digests.
Successful cryptographic verification authenticates the supplied identity claim; authorization,
identity ownership, policy suitability, qualification, and release approval remain external.

## Advanced method workbenches

All six workbenches use the same controlled lifecycle. `init` creates a conservative template,
`seal` validates edited evidence and updates its digest, `assess` derives results, and `verify`
checks integrity and can exactly regenerate the assessment from its source. Analysis-bound methods
require the same analysis file for seal and assessment.

```mermaid
sequenceDiagram
    participant S as Static analysis
    participant E as Authorized engineer
    participant W as Governed workspace
    participant A as Deterministic assessor
    participant V as Independent verifier
    S->>W: init with exact analysis digest
    E->>W: add intent, evidence, assumptions, and authority
    W->>W: seal closed content
    W->>A: assess relationships and criteria
    A-->>W: content-addressed result
    V->>W: reload bounded source and result
    V-->>E: integrity + exact-regeneration verdict
```

```powershell
sfmea stpa-cast-init analysis.json --authority "Safety lead" -o stpa.json
sfmea structural-coverage-init analysis.json --authority "Verification lead" -o coverage.json
sfmea quantitative-fta-init analysis.json --authority "Reliability lead" -o qfta.json
sfmea quality-evaluation-init analysis.json --authority "Quality lead" -o quality.json

sfmea structural-coverage-seal analysis.json coverage.json -o coverage.sealed.json
sfmea structural-coverage-assess analysis.json coverage.sealed.json -o coverage.assessment.json
sfmea structural-coverage-verify coverage.assessment.json --analysis analysis.json --source coverage.sealed.json

sfmea security-prioritization-init --authority "Security lead" -o security.json
sfmea laboratory-governance-init --authority "Laboratory manager" --subject-sha256 <digest> -o lab.json
```

- MC/DC credit is derived only when two supplied Boolean test vectors differ solely in the named
  condition and the decision outcome changes. Execution still requires coverage-tool evidence.
- Quantitative FTA uses exact Boolean enumeration for at most 20 basic events, preserving shared
  events. Larger or dynamic models require an independently qualified external solver.
- CVSS values are observations from a named calculator. The workbench validates canonical vectors,
  score ranges, severity labels, ASVS evidence links, and SSVC decisions; it does not substitute
  severity for treatment priority.
- Laboratory governance records competence and independence evidence but cannot grant ISO/IEC
  17025 accreditation. Likewise, method completeness is not certification or risk acceptance.

## Observed structural coverage

The MC/DC workbench validates requirement links, Boolean vectors, and unique-cause independence
pairs. Runtime observation is a separate evidence channel because `coverage.py` line and branch
data cannot establish decision or MC/DC coverage.

```mermaid
flowchart LR
    T["Controlled test run"] --> CJ["Exact coverage.py JSON"]
    CJ --> I["runtime-coverage-import"]
    A["Exact analysis state"] --> I
    CFG["Tool version + command + config digest"] --> I
    I --> R["Line/branch + component observation receipt"]
    R --> V["Exact-byte and semantic verification"]
    R -. "evidence only" .-> M["MC/DC engineering workspace"]
```

```powershell
sfmea runtime-coverage-import analysis.json coverage.json `
  --authority "Verification lead" `
  --command "coverage json -o coverage.json" `
  --configuration-sha256 <sha256> `
  --environment "Python 3.13, controlled CI image" `
  --test-run-ref "evidence://ci/run-42" `
  --evidence-ref "evidence://ci/run-42/log" `
  --minimum-statement-rate 0.95 `
  --minimum-branch-rate 0.90 `
  --require-all-components `
  -o runtime-coverage.json

sfmea runtime-coverage-verify runtime-coverage.json `
  --analysis analysis.json --coverage-json coverage.json --json
```

The importer never executes repository code. It consumes bounded strict JSON, binds the exact
artifact bytes, maps unique normalized paths and component line ranges, derives its own counts,
lists unmapped files and components, rejects contradictory line/branch observations, and rejects
rehashed false summaries. Object-code correlation remains an explicit project policy.

## Composite industry-validation portfolio

The portfolio is the final evidence-integration gate. It requires a benchmark-v2 assessment with
a `benchmark_suite` stratum and checks that each repository belongs to exactly one declared,
content-addressed external suite. The default policy requires both executable synthetic and
real-world defect suites, two distinct comparator tools, runtime coverage, and representative
analyst usability evidence. Selected interoperability formats must have passing independent
receiving-tool receipts. Formal-method and continuity gates become mandatory when their policy
flags are enabled; supplied optional evidence must still pass.

A defensible baseline can pair [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython)
for executable security cases with [BugsInPy](https://github.com/soarsmu/BugsInPy) for reproducible
real-world Python defects. Pin the exact source revision and digest in the portfolio; names and
URLs alone are not provenance. [NIST SARD](https://samate.nist.gov/SARD/) can add an independent
cross-language control corpus, but it does not replace representative Python evidence.

For the LLM test-generation layer, the governed targets include CyberSecEval 4 for insecure code,
prompt injection, interpreter misuse, autonomous action, defensive reasoning, and patching;
AgentDojo for dynamic indirect-injection, tool-use, and utility/security tradeoffs; CrossCodeEval
and CrossCodeLongEval for cross-file and long-range repository context; SWE-PolyBench Verified
Python for independently curated cross-project repository tasks; IDoFT Python for independently
maintained flaky-test candidates; and a local nondeterminism/concurrency corpus for schedule,
order, timing, race, and eventual-consistency mechanisms. AgentDojo, SWE-PolyBench, and IDoFT
have native upstream-shape normalization, but normalized output is not execution or correctness
evidence until joined to a pinned lawful source, reviewed adapter, environment, per-case evidence,
and independent authority. Model-judge output, lexical completion scores, dataset membership, and
a single passing repetition are never promoted to independent correctness labels.

The graph and generated-test qualification layer adds
[PyCG](https://github.com/vitsalis/PyCG), [JARVIS](https://pythonjarvis.github.io/), and
[DyPyBench](https://github.com/sola-st/DyPyBench) as distinct static-ground-truth and
runtime-observation populations. Dynamic traces are under-approximations, so they can establish
observed-edge recall but cannot label every unobserved edge false. [TestExplora](https://github.com/microsoft/TestExplora)
adds proactive latent-defect discovery: a generated test receives defect-exposure credit only when
it fails on the buggy revision, passes on the repaired revision, and does not regress the retained
suite. Every target remains `contract-only` until its exact version-specific adapter is reviewed;
PySFMEA deliberately does not guess evolving upstream formats.

Five additional contracts cover modern Python semantics, distributed timeout/retry/breaker
behavior, receiving-tool interoperability, longitudinal drift, and Pynguin/SBFT generated-test
research. The first four are maintained executable regression populations; Pynguin/SBFT remains
an external contract until a version-pinned, independently reviewed adapter is supplied.

For causal propagation, prepare an independently reviewed JSON scenario array and bind every
scenario to its exact injected fault and runtime trace:

```powershell
sfmea causal-validate causal-scenarios.json `
  --analysis-sha256 <analysis-content-sha256> `
  --producer "Fault-injection laboratory" `
  --reviewer "Independent validation reviewer" `
  --authority "Assurance board" `
  -o causal-validation.json
sfmea causal-validate-verify causal-validation.json --json
```

Format 2 computes edge and effect precision against predicted populations, recall against observed
populations, and accounts within each scenario before aggregation. It also reports exact ordered
path/effect rates and the populations eligible for deadline, breaker, and recovery conclusions.

```mermaid
flowchart TB
    OW["OWASP Benchmark Python\nexecutable synthetic"] --> BV2["Benchmark v2 assessment"]
    BP["BugsInPy / governed defect corpus\nreal-world defects"] --> BV2
    CT["Independent comparator tools"] --> P["Validation portfolio"]
    BV2 --> P
    RC["Runtime coverage receipts"] --> P
    IR["Independent round-trip receipts"] --> P
    UX["Representative usability study"] --> P
    FM["Formal proof records, if applicable"] --> P
    BC["Continuity exercises, if applicable"] --> P
    P --> A{"All policy gates pass?"}
    A -->|yes| D["Eligible for external authority decision"]
    A -->|no| G["Explicit evidence gaps"]
```

```powershell
sfmea validation-portfolio-init --authority "Qualification lead" -o portfolio.json
# Edit the closed workspace and add exact relative evidence paths.
sfmea validation-portfolio-seal portfolio.json -o portfolio.sealed.json
sfmea validation-portfolio-assess portfolio.sealed.json -o portfolio.assessment.json
sfmea validation-portfolio-verify portfolio.assessment.json `
  --source portfolio.sealed.json --json
sfmea validation-portfolio-report portfolio.assessment.json -o portfolio.html
sfmea validation-portfolio-report-verify portfolio.html `
  --assessment portfolio.assessment.json --json

# Join three independent evidence lanes through four exact artifacts and separate review authority.
sfmea industry-qualification-readiness `
  --standards-lifecycle standards-lifecycle.json `
  --benchmark-source-health benchmark-source-health.json `
  --benchmark-proficiency-source proficiency.sealed.json `
  --benchmark-proficiency proficiency.assessment.json `
  --validation-portfolio-source portfolio.sealed.json `
  --validation-portfolio portfolio.assessment.json `
  --authority "Qualification review board" `
  -o industry-readiness.json
sfmea industry-qualification-readiness-verify industry-readiness.json `
  --standards-lifecycle standards-lifecycle.json `
  --benchmark-source-health benchmark-source-health.json `
  --benchmark-proficiency-source proficiency.sealed.json `
  --benchmark-proficiency proficiency.assessment.json `
  --validation-portfolio-source portfolio.sealed.json `
  --validation-portfolio portfolio.assessment.json --json
```

Relative evidence paths cannot escape the portfolio directory. Assessment binds every referenced
machine artifact by byte count, SHA-256, and content digest; the standalone verifier recomputes all
decision gates so a rehashed false summary remains invalid. The responsive HTML report embeds the
exact assessment and independently protects both payload and normalized document bytes.

The qualification-readiness gate is intentionally stricter than any individual workflow. It binds
the current 144-profile and 41-suite catalogs. By default it requires every standard lifecycle record
to be reviewed and current, every benchmark source pinned, and every adapter operational. An approved
`qualification_scope` can select applicable standards and portfolio suites with exhaustive,
reasoned exclusions, separated roles, review expiry, and exact acceptance-policy binding. Selected
contract-only adapters still block eligibility. Regardless of scope, the gate requires the
cross-organization proficiency assessment to pass with exact source replay, the independent
validation portfolio to pass, and the decision authority to be separate from evidence
owners and reviewers. Its exact-source verifier regenerates the portfolio assessment from its
editable sources and then replays the aggregate from all six artifacts. A valid artifact with
unavailable source bytes is never review-eligible, and any partial
replay, catalog drift, summary tampering, contract-only adapter, or incomplete evidence becomes an
explicit blocker. Passing means only eligibility for a documented external authority decision; it
does not confer qualification, certification, accreditation, regulatory approval, or risk
acceptance.

```mermaid
flowchart LR
    S["144-profile standards lifecycle"] --> Q{"Exact qualification-readiness gate"}
    B["41-suite source, adapter, and item-quality ledger"] --> Q
    SC["Approved applicability + exclusions + policy"] --> Q
    CL["Audited case IDs + exact revision + scored labels"] --> V
    D["Case-paired differential source"] --> DA["Confusion metrics + exact McNemar + adjudication"]
    DA --> V
    PS["Proficiency scheme source"] --> PA["z-score + agreement assessment"]
    PA --> Q
    VS["Validation portfolio source"] --> V["Regenerated validation assessment"]
    V --> Q
    A["Separated decision authority"] --> Q
    Q -->|all evidence passes + exact replay| E["Eligible for external authority review"]
    Q -->|any gap, drift, or partial replay| X["Explicit blocker and remediation"]
```

## Objective-by-objective assessment

Create a workspace bound to the exact analysis state:

```powershell
sfmea conformance-init .artifacts\RUN\sfmea-analysis.json `
  --profile iec-60812-2018 `
  --profile nist-ai-600-1-llm `
  --system "Payments control service" `
  --phase verification `
  --basis "Approved software assurance plan SAP-17" `
  --authority "Software Assurance Board" `
  -o .artifacts\RUN\conformance.json
```

Every objective begins `undetermined` and `unassessed`. Record applicability and assessment
one objective at a time:

```powershell
sfmea conformance-assess .artifacts\RUN\conformance.json IEC60812-SCOPE `
  --applicability applicable `
  --status satisfied `
  --rationale "Scope and assumptions approved at review SRR-42." `
  --reviewer "assurance-board@example.org" `
  --evidence-ref "reqif://SAP-17/SFMEA-SCOPE"

sfmea conformance-verify .artifacts\RUN\conformance.json `
  --analysis .artifacts\RUN\sfmea-analysis.json --json
```

The assessment model is deliberately fail-visible:

- `satisfied` requires at least one evidence reference.
- Every assessed decision requires a rationale, reviewer, and timestamp.
- `not_applicable` is distinct from `unassessed` and requires an authorized rationale.
- Undetermined applicability and every applicable status other than `satisfied` remain blockers.
- Catalog, profile, objective, summary, and analysis-state changes invalidate verification.
- A fully satisfied workspace says only that the selected objective assessments support the
  declared position. It does not issue certification or regulatory approval.

## Objective-to-finding crosswalk

Create an authority-attributed mapping from applicable standards objectives to exact findings,
verification obligations, and controlled evidence. Unknown or inactive identifiers are rejected:

```powershell
Copy-Item examples\standards-crosswalk-mapping.json crosswalk-mapping.json
# Replace every template identifier and assertion with reviewed project data.
sfmea standards-crosswalk sfmea-analysis.json conformance.json `
  crosswalk-mapping.json -o standards-crosswalk.json
sfmea standards-crosswalk-verify standards-crosswalk.json `
  --analysis sfmea-analysis.json --conformance conformance.json `
  --mapping crosswalk-mapping.json --json
```

The artifact retains exact byte and canonical identities for all three sources, reports unlinked
applicable objectives and unmapped active findings, and can be exactly regenerated. A link is an
attributed engineering assertion; it is not proof that a finding is true or an objective is met.

## Structured assurance case

Generate a machine-readable claims–arguments–evidence artifact:

```powershell
sfmea assurance-case .artifacts\RUN\sfmea-analysis.json `
  --conformance .artifacts\RUN\conformance.json `
  --qualification qualification-result.json `
  -o .artifacts\RUN\assurance-case.json

sfmea assurance-case-verify .artifacts\RUN\assurance-case.json `
  --analysis .artifacts\RUN\sfmea-analysis.json --json
```

```mermaid
flowchart TB
    TOP["C-TOP: bounded evidence supports an authorized decision"]
    INV["C-INVENTORY"] --> TOP
    REV["C-REVIEW"] --> TOP
    VER["C-VERIFICATION"] --> TOP
    CON["C-CONFORMANCE"] --> TOP
    QUAL["C-QUALIFICATION"] --> TOP
    EA["Exact analysis bytes"] --> INV
    EA --> REV
    EA --> VER
    EC["Conformance workspace"] --> CON
    EQ["Qualification result"] --> QUAL
    DEF["Open defeaters"] -.challenge.-> TOP
```

The JSON structure aligns with ISO/IEC/IEEE 15026 assurance-case concepts and OMG SACM claim,
argument, artifact, and asserted-relationship semantics. Each unsupported or partial subclaim produces an explicit defeater and keeps
the top claim from becoming decision-ready.

Project the same exact case into closed GSN Version 3 semantic nodes for notation-oriented review:

```powershell
sfmea gsn-project assurance-case.json -o assurance-case-gsn.json
sfmea gsn-verify assurance-case-gsn.json --case assurance-case.json --json
```

Goals, strategies, solutions, assumptions, and open defeaters remain distinct. This PySFMEA JSON
is a semantic projection for review and visualization; it is not represented as a normative GSN
exchange serialization or proof of ISO/IEC/IEEE 15026 conformity.

Export bounded standards-oriented projections and independently reconcile them to their exact
source populations:

```powershell
sfmea industry-exchange sacm assurance-case.json -o assurance-case.sacm.xmi
sfmea industry-exchange sfpm sfmea-analysis.json -o findings.sfpm.xmi
sfmea industry-exchange reqif sfmea-analysis.json -o assurance.reqif
sfmea industry-exchange spdx sfmea-analysis.json -o inventory.spdx.json
sfmea industry-exchange-verify reqif assurance.reqif sfmea-analysis.json --json
```

The SACM 2.3 and SFPM 1.0 XMI files use official OMG namespace identities and declare the exact
PySFMEA subset represented. ReqIF 1.2 carries findings, obligations, and `verifies` relations.
SPDX 3.0.1 JSON-LD carries a Core+Software declared inventory. Verification covers structure,
source identity, and population reconciliation—not every feature of the receiving metamodel.

## Normative validation and independent round trips

Install the optional interoperability validators, then validate exact exchange bytes against the
controlled schema acquired for the adopted edition:

```powershell
pip install "pysfmea[interop]"
sfmea industry-schema-validate assurance.reqif reqif.xsd `
  --schema-kind xml-schema --standard "OMG ReqIF" --edition "1.2" `
  --schema-uri "controlled://standards/reqif/1.2/reqif.xsd" `
  --schema-sha256 EXPECTED_PUBLISHER_DIGEST -o reqif-schema-receipt.json
sfmea industry-schema-verify reqif-schema-receipt.json `
  --artifact assurance.reqif --schema reqif.xsd --json

# Validate the original Security Insights YAML bytes against a separately retained
# official OpenSSF release schema. YAML aliases/cycles and non-JSON scalars fail closed.
sfmea industry-schema-validate security-insights.yml security-insights.schema.json `
  --schema-kind yaml-json-schema --standard "OpenSSF Security Insights" `
  --edition "2.2.0" --schema-uri "https://security-insights.openssf.org/schema/2.2.0" `
  --schema-sha256 EXPECTED_PUBLISHER_DIGEST -o security-insights-validation.json
```

PySFMEA records the exact artifact and schema identities, validator implementation, publisher
digest comparison, and validation errors. It does not download or substitute normative schemas.
JSON Schema uses `jsonschema` with the bounded `regex` engine for standards such as OSCAL that
use Unicode property escapes; XML Schema uses `lxml`. YAML validation uses PyYAML's safe loader,
preserves plain timestamps as JSON strings, rejects aliases/cycles and non-JSON values, applies
the same depth/node limits, and binds the untouched YAML bytes in the receipt.

After a separate tool and operator import and re-export the artifact, capture their observation
record and seal it with the validation receipt:

```powershell
sfmea industry-roundtrip-seal reqif-schema-receipt.json receiver-observation.json `
  -o reqif-roundtrip.json
sfmea industry-roundtrip-verify reqif-roundtrip.json `
  --validation-receipt reqif-schema-receipt.json `
  --observation receiver-observation.json --reexport receiver-export.reqif --json
```

The evidence distinguishes PySFMEA self-reconciliation, normative schema validity, and an
independently attributable receiving-tool round trip. The receiving-tool identity, version,
operator, independence basis, differences, and exact re-export bytes remain reviewable.

## Requirements and system-model lifecycle bridge

Normalize controlled snapshots without fuzzy linkage:

```powershell
sfmea lifecycle-import reqif requirements.reqif --analysis sfmea-analysis.json `
  -o lifecycle-model.json
sfmea lifecycle-import sysml2-json system-model.json --analysis sfmea-analysis.json `
  -o lifecycle-model.json
sfmea lifecycle-import oslc-jsonld lifecycle-snapshot.json -o lifecycle-model.json
sfmea lifecycle-import-verify lifecycle-model.json `
  --source system-model.json --analysis sfmea-analysis.json --json
```

The bridge preserves source IDs, types, titles, explicit relationships, and exact input digests.
Code links are created only from explicit PySFMEA component identifiers; ambiguous name similarity
never earns traceability credit. Unsupported metamodel content remains outside the declared subset.

## PHA, FHA, PSSA, SSA, operations, and CCFA

The safety lifecycle workspace carries each declared hazard through objectives, allocation,
verification, and an authority-attributed residual-risk disposition. It also builds Common Cause
Failure Analysis scope from project-defined shared causes and qualitative cut sets from approved
software fault trees:

```powershell
sfmea safety-lifecycle-init sfmea-analysis.json --authority "System safety lead" `
  -o safety-lifecycle-authoring.json
# Complete the five stage records, hazard records, and CCFA reviews under configuration control.
sfmea safety-lifecycle-seal sfmea-analysis.json safety-lifecycle-authoring.json `
  -o safety-lifecycle-authoring.json
sfmea safety-lifecycle-assess sfmea-analysis.json safety-lifecycle-authoring.json `
  -o safety-lifecycle-assessment.json
sfmea safety-lifecycle-verify safety-lifecycle-assessment.json `
  --analysis sfmea-analysis.json --authoring safety-lifecycle-authoring.json --json
```

```mermaid
flowchart LR
    PHA["PHA: identify hazards"] --> FHA["FHA: classify effects and objectives"]
    FHA --> PSSA["PSSA: allocate requirements and independence"]
    PSSA --> SSA["SSA: reconcile implementation and verification"]
    SSA --> OPS["Operations: monitor changes, events, and assumptions"]
    C["Project common causes"] --> CCFA["CCFA review ledger"]
    FTA["Approved SFTA cut sets"] --> CCFA
    CCFA --> PSSA
    CCFA --> SSA
```

The operations record adds a FRACAS/CAPA-style periodic review and optional incident records with
affected hazards/findings/components, containment, root-cause evidence, corrective actions,
ownership, due date, effectiveness verification, and attributed closure. An approved lifecycle
status means the named reviewer supplied rationale and evidence; it does not mean PySFMEA approved
a design. Unapproved fault-tree logic receives no cut-set or CCFA credit.

## HAZOP, RBD, and Markov dependability analysis

Static discovery creates review scope; an authorized engineer supplies design intent, deviation
causes/effects, safeguards, success logic, reliability values, state-transition rates, assumptions,
uncertainty, and evidence:

```powershell
sfmea dependability-init sfmea-analysis.json --authority "Dependability lead" `
  -o dependability-authoring.json
# Edit the controlled authoring artifact.
sfmea dependability-seal sfmea-analysis.json dependability-authoring.json `
  -o dependability-authoring.json
sfmea dependability-assess sfmea-analysis.json dependability-authoring.json `
  -o dependability-assessment.json
sfmea dependability-verify dependability-assessment.json `
  --analysis sfmea-analysis.json --authoring dependability-authoring.json --json
```

HAZOP completeness is checked across every declared node/parameter/guideword pair. RBD results use
only explicit series, parallel, or k-out-of-n gates. Blocks may use direct reliability or an
evidence-backed constant failure rate, optional repair rate, and reliability interval. Multi-input
gates require explicit independence evidence and may apply a declared beta-factor common-cause
sensitivity adjustment; call graphs never imply statistical independence. Bounded homogeneous continuous-time Markov models are solved by uniformization and
must conserve probability. These calculations support engineering review; they do not choose
rates, prove independence, or accept risk.

## Independent benchmark assessment

PySFMEA's built-in corpus is a regression gate. Industry qualification should additionally use:

- Independently selected and labeled Python repositories
- Representative frameworks and application domains
- Positive and negative populations
- Precision, recall, false-positive rate, localization, semantic, and control metrics
- Confidence calibration and uncertainty intervals where statistically meaningful
- Conservative confidence bounds for every metric inside every represented stratum
- Unique retained repository source references to prevent duplicate holdout credit
- Cold/warm runtime, peak RSS, artifact size, and browser usability budgets
- Independent approval of labels, selection rationale, thresholds, anomalies, and deviations

Use `qualification-build`, `qualification-verify`, and `qualification-report` for the retained
campaign. Then assess it against a protocol frozen before scanner execution:

```powershell
Copy-Item examples\independent-benchmark-protocol.json benchmark-protocol.json
# Replace every placeholder and reviewer count with controlled project evidence.
sfmea benchmark-assess benchmark-protocol.json qualification-result.json `
  qualification-campaign.json `
  --execution-started-at 2026-08-26T12:00:00Z `
  --execution-evidence-ref "ci://qualification/run-42" `
  -o benchmark-assessment.json
sfmea benchmark-verify benchmark-assessment.json `
  --protocol benchmark-protocol.json `
  --qualification-result qualification-result.json `
  --qualification-manifest qualification-campaign.json --json
```

For the advanced format-2 campaign, publish an accessible self-contained report whose embedded
assessment and complete HTML document are independently integrity-bound:

```powershell
sfmea benchmark-report-v2 benchmark-v2-assessment.json -o benchmark-v2-report.html
sfmea benchmark-report-verify-v2 benchmark-v2-report.html `
  --assessment benchmark-v2-assessment.json --json
```

The assessment calculates two-sided Wilson intervals for finding, call, control, and semantic
recall/precision; calculates Cohen's kappa from the retained reviewer matrix; gates the lower
confidence bound rather than the point estimate; binds exact protocol, campaign, and result bytes;
and requires a closed requalification-trigger set. Missing metric populations fail visibly.
The verifier can exactly regenerate the artifact from all three retained sources.

Passing means only `eligible_for_authorized_tool_qualification_review`. PySFMEA cannot establish
that repositories are representative, labels are true, authorities are independent, or the
selected thresholds are sufficient.

For heterogeneous repositories and LLM-generated-test qualification, format 2 adds
repository-cluster bootstrap intervals, per-stratum minimum populations, prediction calibration,
Krippendorff nominal alpha, predeclared power evidence, and a broader change-trigger set:

```powershell
# Edit controlled protocol and observation templates, then reseal them.
Copy-Item examples\independent-benchmark-protocol-v2.json benchmark-protocol-v2.json
Copy-Item examples\independent-benchmark-observations-v2.json benchmark-observations-v2.json
sfmea benchmark-seal-v2 benchmark-protocol-v2.json -o benchmark-protocol-v2.json
sfmea benchmark-seal-v2 benchmark-observations-v2.json `
  --protocol benchmark-protocol-v2.json -o benchmark-observations-v2.json
sfmea benchmark-assess-v2 benchmark-protocol-v2.json benchmark-observations-v2.json `
  -o benchmark-assessment-v2.json
sfmea benchmark-verify-v2 benchmark-assessment-v2.json `
  --protocol benchmark-protocol-v2.json --observations benchmark-observations-v2.json --json
```

The tool-qualification dossier accepts either benchmark generation. Sealing establishes content
integrity only; external governance must prove pre-registration, independence, representative
sampling, label truth, power assumptions, and threshold sufficiency.

## Tool qualification dossier

Apply the release gate before a candidate enters tool-qualification or release approval:

```powershell
sfmea release-qualification-init --authority "Protocol owner" -o release-source.json
# Populate distinct authorities, temporal corpus records, content/history/lineage identities,
# every candidate/reference similarity pair, metric margins, resource observations, and evidence.
sfmea release-qualification-seal release-source.json -o release-source.json
sfmea release-qualification-assess release-source.json candidate-assessment.json `
  baseline-assessment.json -o release-assessment.json
sfmea release-qualification-verify release-assessment.json --source release-source.json `
  --candidate candidate-assessment.json --baseline baseline-assessment.json --json
```

Passing requires both format-2 benchmarks to pass, post-cutoff candidate and pre-cutoff reference
corpora, disjoint repository IDs/content/history roots/lineage, exhaustive below-threshold
similarity evidence, conservative recall/precision lower-bound non-inferiority, and duration,
peak-RSS, and artifact-size budgets. This proves policy accounting over supplied evidence; it
cannot authenticate the declared authorities or establish corpus independence.

The dossier is a controlled evidence index, not a qualification certificate:

```powershell
sfmea tool-qualification-bases
sfmea tool-qualification-bases -o qualification-bases.json
```

The three governed navigation packs cover DO-330/ED-215, ISO 26262-8, and IEC 61508-3. Each maps
all nine generic dossier objectives to lifecycle evidence categories and exposes classification
questions and tailoring boundaries without reproducing licensed normative requirements.

```powershell
sfmea tool-qualification-init sfmea-analysis.json `
  --benchmark benchmark-assessment.json --conformance conformance.json `
  --anomalies examples\known-anomalies.json `
  --intended-use "Screen Python repositories and retain review candidates" `
  --reliance "No lifecycle objective is eliminated solely by scanner output" `
  --basis "Project-approved DO-330-aligned process" `
  --classification "Classification pending authority decision" `
  --environment "Controlled CPython and dependency baseline" `
  --authority "Tool qualification authority" -o tool-qualification.json

sfmea tool-qualification-assess tool-qualification.json TQ-CLASSIFY `
  --applicability applicable --status satisfied `
  --rationale "Approved classification decision TQA-17" `
  --reviewer "independent-reviewer-id" --evidence-ref "record://TQA-17"

sfmea tool-qualification-verify tool-qualification.json `
  --analysis sfmea-analysis.json --benchmark benchmark-assessment.json `
  --conformance conformance.json --anomalies examples\known-anomalies.json --json
```

Nine immutable objectives cover classification, operational requirements, qualification and
verification plans, verification results, configuration, known anomalies, accomplishment, and
requalification. Exact-source verification reconciles the analysis, benchmark, conformance
workspace, anomaly register, and derived input gates. Every applicable objective needs attributed
evidence; open anomalies and undecided classification block readiness. Only an authorized authority
can choose DO-330 TQL, ISO 26262 tool-confidence, IEC 61508 tool-class, or another qualification
basis and approve its required lifecycle data.

```mermaid
flowchart LR
    P["Frozen protocol"] --> BA["Benchmark assessment"]
    QR["Exact qualification result"] --> BA
    QM["Exact campaign manifest"] --> BA
    A["Exact analysis"] --> TQ["Qualification dossier"]
    BA --> TQ
    C["Conformance workspace"] --> TQ
    K["Known-anomaly register"] --> TQ
    TQ --> V{"Exact-source verification"}
    V -->|eligible, never approved| H["Authorized qualification decision"]
```

## Supply-chain exchange

For governed vulnerability prioritization, use a project-approved complete SSVC-style decision
table. PySFMEA intentionally does not embed a mutable or guessed CISA decision tree:

```powershell
sfmea ssvc-policy-init --authority "Product security authority" -o ssvc-policy.json
# Populate the controlled model version and complete, non-overlapping decision table.
sfmea ssvc-seal ssvc-policy.json -o ssvc-policy.json
sfmea ssvc-observations-init --policy-digest POLICY_CONTENT_SHA256 `
  --authority "Vulnerability review board" -o ssvc-observations.json
# Populate attributable decision-point evidence and next-review dates.
sfmea ssvc-seal ssvc-observations.json --policy ssvc-policy.json `
  -o ssvc-observations.json
sfmea ssvc-assess ssvc-policy.json ssvc-observations.json -o ssvc-assessment.json
sfmea ssvc-verify ssvc-assessment.json --policy ssvc-policy.json `
  --observations ssvc-observations.json --json
```

Track, Track*, Attend, or Act is a deterministic application of the controlled local policy to
supplied evidence—not a CISA decision or an assertion that the evidence is true.

`sfmea sbom` emits CycloneDX 1.7. It declares the `discovery` lifecycle and explicitly marks the
project assembly and dependency graph `incomplete`, because static manifest inventory does not
resolve all installed or transitive components. SARIF findings remain labeled screening
candidates. Neither export implies vulnerability, dependency, or system-safety completeness.

Publish VEX only from an explicit product-security decision file; PySFMEA never infers an
exploitability state from static inventory:

```powershell
Copy-Item examples\vex-decisions.json vex-decisions.json
# Replace all template fields with authority-attributed decisions and evidence.
sfmea vex sfmea-analysis.json vex-decisions.json -o product.vex.cdx.json
sfmea vex-verify product.vex.cdx.json sfmea-analysis.json vex-decisions.json --json
sfmea csaf sfmea-analysis.json vex-decisions.json -o product.csaf.json
sfmea csaf-verify product.csaf.json sfmea-analysis.json vex-decisions.json --json
```

The CycloneDX 1.7 VEX exporter accepts the standard analysis states, justifications, and responses,
requires evidence for every entry, requires recognized justification for `not_affected`, rejects
unknown BOM references, and verifies exact regeneration from both controlled sources.
The CSAF 2.0 projection reuses those governed states and never derives product status from a scan.
Before operational publication, validate it with the official OASIS CSAF schema using
`industry-schema-validate` and retain the schema receipt beside the advisory.

Generate and verify SLSA Provenance v1 for the exact retained analysis:

```powershell
sfmea provenance .artifacts\RUN\sfmea-analysis.json `
  -o .artifacts\RUN\sfmea-analysis.intoto.json
sfmea provenance-verify .artifacts\RUN\sfmea-analysis.intoto.json `
  --analysis .artifacts\RUN\sfmea-analysis.json --json
```

The statement records the exact subject digest, analysis-state identity, safe scanner parameters,
builder/version, run identity and timestamps, source/configuration/guidance/adapter/dependency/
contract/inventory/context materials, and repository revision when available. Local structural
verification does not authenticate the builder. Sign and transparently publish the statement in
the release workflow when the organizational assurance plan requires authenticated provenance.

Apply a deny-by-default SLSA 1.2 policy after an external tool has verified the signature:

```powershell
sfmea slsa-policy-init --authority "Supply-chain authority" -o slsa-policy.json
sfmea slsa-observation-init --verifier "Independent verifier" -o slsa-observation.json
# Populate approved identities/constraints and the external verification receipt, then seal both.
sfmea slsa-policy-seal slsa-policy.json -o slsa-policy.json
sfmea slsa-observation-seal slsa-observation.json -o slsa-observation.json
sfmea slsa-policy-assess sfmea-analysis.intoto.json slsa-policy.json `
  slsa-observation.json -o slsa-assessment.json
sfmea slsa-policy-verify slsa-assessment.json --provenance sfmea-analysis.intoto.json `
  --policy slsa-policy.json --observation slsa-observation.json --json
```

Build and Source track levels are independent. The current format can establish Source L2 but
deliberately withholds Source L3 until its stronger administrator and technical enforcement
controls have a closed, independently verifiable evidence contract.

The repository also runs the official, immutable-SHA-pinned OpenSSF Scorecard action on `main`
and weekly. Results are retained as SARIF and sent to GitHub code scanning with read-only default
permissions and only the job-level `security-events` and OIDC permissions required for publishing.

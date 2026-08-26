# Generated-test qualification campaigns

Use this runbook when deciding whether a specific provider, model, and PySFMEA prompt version is
ready for a supervised test-generation pilot. It operationalizes the artifact-backed format-2
corpus; it does not authorize autonomous publication or replace the seven readiness gates applied
to every generated test. Those per-test gates still require the closed proposal's import-qualified
target binding, named publication review, exact registration, restricted execution, observed
stimulus, complete criteria, intact evidence, and independent evidence review.

## Campaign layout

Keep the corpus and all referenced bytes beneath one immutable evidence root:

```text
test-generation-evidence/
├── corpus.json
├── SAMPLE-001/
│   ├── analysis.json
│   ├── proposal.json
│   ├── application-receipt.json
│   └── fault.json
└── executions/
    ├── baseline-001/
    │   ├── execution.json
    │   └── raw test artifacts...
    └── seeded-001/
        ├── execution.json
        └── raw test artifacts...
```

The analysis assurance register names each execution directory and exact generated-test SHA-256.
Each `execution.json` manifest is content sealed and records the size and SHA-256 of every raw
artifact. `fault.json` binds one passing baseline and one failing seeded run to the same test.

```mermaid
sequenceDiagram
    autonumber
    actor Reviewer
    participant Builder as Fault-evidence builder
    participant Analysis as Governed analysis
    participant Baseline as Baseline evidence directory
    participant Seeded as Seeded evidence directory
    participant Evaluator as Format-2 evaluator

    Reviewer->>Builder: Build(sample, baseline ID, seeded ID, evidence root)
    Builder->>Analysis: Resolve both executions and exact test SHA-256
    Analysis-->>Builder: Baseline passed; seeded failed; distinct IDs
    Builder->>Baseline: Verify root confinement and execution.json seal
    Baseline-->>Builder: Verify every artifact size and SHA-256
    Builder->>Seeded: Verify root confinement and execution.json seal
    Seeded-->>Builder: Verify every artifact size and SHA-256
    Builder-->>Reviewer: Publish content-sealed fault.json
    Reviewer->>Evaluator: Evaluate exact corpus under the same evidence root
    Evaluator->>Analysis: Replay lifecycle and execution bindings
    Evaluator->>Baseline: Replay manifest and raw artifact verification
    Evaluator->>Seeded: Replay manifest and raw artifact verification
    Evaluator-->>Reviewer: 15 derived gates or fail-closed error
```

## Independent campaign workflow

1. Freeze the provider, model, prompt version, generation settings, repository revision, and
   environment. Select repositories and obligations before observing generation outcomes.
2. Record the selection method and representativeness rationale. Include proposed and refused
   cases, multiple repositories, domains, and frameworks appropriate to the intended use.
3. Have a labeler define the expected proposal/refusal decision and seeded fault independently of
   the model. Keep labeler, evidence producer, and final reviewer roles separate where required.
4. Retain the exact analysis, proposal, application receipt, execution manifests, and raw run
   artifacts. Do not substitute screenshots, narrative summaries, or digest-only claims.
5. Build each fault record from the retained execution evidence:

   ```powershell
   sfmea assurance-test-fault-evidence SAMPLE-001/analysis.json SAMPLE-001 `
     EXEC-BASELINE-001 EXEC-SEEDED-001 --fault-id MUTATION-001 `
     --environment "locked qualification container" `
     --evidence-root . -o SAMPLE-001/fault.json
   sfmea assurance-test-fault-evidence-verify SAMPLE-001/fault.json `
     --analysis SAMPLE-001/analysis.json --evidence-root . --json
   ```

6. Complete `corpus.json` with root-relative, content-addressed artifact references, then evaluate
   and replay the exact result:

   ```powershell
   sfmea assurance-test-quality-evaluate corpus.json --evidence-root . `
     --require-qualified -o result.json
   sfmea assurance-test-quality-verify result.json corpus.json --evidence-root .
   ```

7. Review all 15 gates, segment populations, refusals, unsafe attempts, and failed samples. Record
   the human promotion decision outside the evaluator. Preserve unsuccessful evidence; replacing
   it after seeing outcomes invalidates the campaign design.

## Acceptance checklist

- [ ] The subject exactly identifies provider, model, and prompt version.
- [ ] Sample selection predates observed outcomes and covers the declared intended use.
- [ ] Proposed and refused populations meet the declared minimums.
- [ ] Labeler and reviewer identities and dates are retained; required independence is satisfied.
- [ ] Every reference is relative to one evidence root and matches its exact bytes.
- [ ] Each proposed sample has one valid application receipt and two distinct execution records.
- [ ] Baseline passes, seeded execution fails, both bind the same generated test, and every raw
      artifact verifies at its recorded size and SHA-256.
- [ ] Duplicate artifact bundles do not increase sample credit.
- [ ] Evaluation and exact-corpus replay agree, and all 15 gates pass before promotion.
- [ ] Per-test planning, review, restricted execution, evidence review, and publication authority
      remain enforced after subject qualification.

## Interpretation boundaries

A passing campaign qualifies only the retained subject and sample under its declared policy. It
does not prove that the repositories are representative, authenticate human identities, establish
reviewer competence, demonstrate test semantic adequacy beyond the supplied stimuli/faults, or
grant certification or publication authority. Add new independent samples when the model, prompt,
tool version, target frameworks, domains, or intended use materially changes.

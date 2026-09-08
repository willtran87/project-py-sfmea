"""Governed adapter contract between external suites and PySFMEA observations."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .benchmark_observations import BENCHMARK_OBSERVATIONS_FORMAT
from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .industry_benchmarks import BENCHMARK_SUITES
from .model import utc_now

BENCHMARK_ADAPTER_FORMAT = "pysfmea-benchmark-adapter-1"
BENCHMARK_ADAPTER_VERIFICATION_FORMAT = "pysfmea-benchmark-adapter-verification-1"
SUITE_IDS = {item["id"] for item in BENCHMARK_SUITES}

# These policies are deliberately specific enough to prevent a nominal adapter from
# silently changing the unit of analysis or treating an upstream execution result as
# an independent label.  Implementations and suite snapshots remain externally pinned.
ADAPTER_BLUEPRINTS: dict[str, dict[str, Any]] = {
    "pysfmea-semantic-corpus": {
        "case_identity_policy": "repository snapshot, source path, component, rule or relationship kind, and exact labeled claim",
        "label_policy": "curator-supplied exhaustive finding, call, control, and semantic labels; preserve governance and qualification readiness",
        "exclusion_policy": "only pre-registered parser-incompatible repositories or cases outside declared exhaustive scopes",
        "metric_mappings": [
            "finding_precision",
            "finding_recall",
            "call_resolution_precision",
            "call_resolution_recall",
            "control_precision",
            "control_recall",
            "semantic_claim_precision",
            "semantic_claim_recall",
        ],
    },
    "pysfmea-causal-propagation": {
        "case_identity_policy": "repository snapshot, finding id, injection point, fault model, scenario id, and exact analysis revision",
        "label_policy": "independently reviewed ordered path, effect, deadline, breaker-transition, recovery, and trace-oracle labels",
        "exclusion_policy": "only pre-registered environment-incompatible scenarios; retain timeouts, instrumentation gaps, and injection failures as outcomes",
        "metric_mappings": [
            "path_edge_precision",
            "path_edge_recall",
            "exact_ordered_path_rate",
            "effect_precision",
            "effect_recall",
            "deadline_conformance",
            "breaker_transition_accuracy",
            "recovery_conformance",
        ],
    },
    "pysfmea-modern-python-dynamics": {
        "case_identity_policy": "corpus revision, interpreter version, feature stratum, source path, symbol, and canonical expected relationship",
        "label_policy": "two-reviewer source and runtime adjudication of calls, interfaces, and sequences with unsupported behavior retained separately",
        "exclusion_policy": "only pre-registered unavailable interpreter or dependency cases; retain parse failures, unresolved targets, crashes, and timeouts",
        "metric_mappings": [
            "call_edge_precision",
            "call_edge_recall",
            "interface_precision",
            "interface_recall",
            "sequence_precision",
            "sequence_recall",
            "unsupported_feature_rate",
        ],
    },
    "pysfmea-distributed-resilience": {
        "case_identity_policy": "corpus revision, topology id, scenario id, injection point, fault model, workload profile, and exact service revisions",
        "label_policy": "independently reviewed trace, state-transition, deadline, retry, queue, idempotency, failover, and recovery oracles",
        "exclusion_policy": "only pre-registered infrastructure-unavailable cases; retain injection, instrumentation, timeout, overload, and recovery failures",
        "metric_mappings": [
            "path_edge_precision",
            "path_edge_recall",
            "deadline_conformance",
            "retry_policy_accuracy",
            "breaker_transition_accuracy",
            "queue_effect_accuracy",
            "recovery_conformance",
            "trace_coverage",
        ],
    },
    "pysfmea-interoperability-conformance": {
        "case_identity_policy": "specification, edition, official schema digest, case id, validity class, producer, and receiving-tool version",
        "label_policy": "official-schema outcome plus independently reviewed semantic invariants and receiving-tool round-trip observations",
        "exclusion_policy": "only pre-registered unsupported specification editions; retain parser errors, schema errors, information loss, and consumer failures",
        "metric_mappings": [
            "valid_acceptance_rate",
            "invalid_rejection_rate",
            "roundtrip_preservation_rate",
            "semantic_preservation_rate",
            "schema_version_coverage",
            "consumer_compatibility_rate",
        ],
    },
    "pysfmea-longitudinal-drift": {
        "case_identity_policy": "series id, repository, base revision, target revision, scanner version, configuration digest, and expected change id",
        "label_policy": "independently reviewed expected and prohibited changes with findings, graph, confidence, performance, and incremental equivalence kept distinct",
        "exclusion_policy": "only pre-registered unavailable immutable revisions; retain scan, migration, performance, and incremental-analysis failures",
        "metric_mappings": [
            "expected_change_recall",
            "unexpected_change_rate",
            "finding_churn",
            "graph_churn",
            "confidence_drift",
            "runtime_regression",
            "memory_regression",
            "incremental_equivalence_rate",
        ],
    },
    "pynguin-sbft-python": {
        "case_identity_policy": "suite and subject revision, interpreter, module, stochastic seed, repetition, time budget, and generator version",
        "label_policy": "observed execution, coverage, mutation, real-fault, flakiness, and unsafe-oracle outcomes; coverage alone is never a correctness label",
        "exclusion_policy": "only pre-registered unsupported subjects or unavailable dependencies; retain generation, import, execution, oracle, timeout, and sandbox failures",
        "metric_mappings": [
            "test_generation_success_rate",
            "line_coverage",
            "branch_coverage",
            "mutation_score",
            "real_fault_detection",
            "flakiness",
            "unsafe_oracle",
            "runtime_seconds",
        ],
    },
    "pycg-callgraph": {
        "case_identity_policy": "suite revision, benchmark stratum, program or package id, entry point, and canonical caller-callee edge",
        "label_policy": "published ground-truth edge presence retained separately from each analyzer prediction",
        "exclusion_policy": "only pre-registered unsupported interpreter or irreproducible package cases; retain unresolved calls and analyzer failures",
        "metric_mappings": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "unresolved_calls",
            "runtime_seconds",
            "peak_memory_mb",
        ],
    },
    "jarvis-callgraph": {
        "case_identity_policy": "suite revision, micro or macro stratum, program or package id, entry point, and canonical caller-callee edge",
        "label_policy": "published reviewed call-edge ground truth; tool agreement remains a comparator observation rather than a label",
        "exclusion_policy": "only pre-registered unsupported interpreter or irreproducible package cases; retain tool crashes and timeouts",
        "metric_mappings": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "unresolved_calls",
            "runtime_seconds",
            "peak_memory_mb",
        ],
    },
    "dypybench": {
        "case_identity_policy": "benchmark revision, project id, immutable project revision, scenario or test id, and canonical observed or predicted edge",
        "label_policy": "instrumented runtime edges are observed evidence under the exact tests, never complete negative ground truth",
        "exclusion_policy": "only pre-registered unavailable projects or dependencies; retain build, test, instrumentation, and timeout failures",
        "metric_mappings": [
            "observed_edge_coverage",
            "static_edge_recall_against_trace",
            "unexpected_static_edges",
            "projects_executable",
            "tests_executed",
            "trace_coverage",
            "runtime_seconds",
        ],
    },
    "testexplora": {
        "case_identity_policy": "official task id, repository, buggy revision, repaired revision, test entry point, and task-document digest",
        "label_policy": "generated test must fail on the buggy revision and pass on the repaired revision while existing tests remain passing",
        "exclusion_policy": "only pre-registered environment or license failures; never exclude generation, compilation, execution, oracle, or regression failures",
        "metric_mappings": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "defects_exposed",
            "flakiness",
            "unsafe_oracle",
            "latency",
            "cost",
        ],
    },
    "owasp-benchmark-python": {
        "case_identity_policy": "upstream test-case identifier plus immutable relative path",
        "label_policy": "upstream expected vulnerability category and truth label; preserve CWE separately",
        "exclusion_policy": "only pre-registered unsupported categories or irreproducible cases with case ids",
        "metric_mappings": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "cwe",
        ],
    },
    "bugsinpy": {
        "case_identity_policy": "project, bug id, buggy revision, and fixed revision tuple",
        "label_policy": "upstream reproducible buggy/fixed pair and triggering tests; no inferred scanner label",
        "exclusion_policy": "only pre-registered build failures, unavailable dependencies, or non-Python tasks",
        "metric_mappings": [
            "defects_detected",
            "defects_missed",
            "tests_passing",
            "localization",
        ],
    },
    "testgeneval": {
        "case_identity_policy": "upstream repository and task identifier at the pinned dataset revision",
        "label_policy": "official hidden-test and execution outcome with separately observed coverage and mutation",
        "exclusion_policy": "only pre-registered unsupported environment or license cases; retain attempted failures",
        "metric_mappings": [
            "test_pass_rate",
            "coverage_delta",
            "mutation_score",
            "unsafe_oracle",
            "flakiness",
        ],
    },
    "tdd-bench-verified": {
        "case_identity_policy": "verified issue id, repository, base commit, and task instance id",
        "label_policy": "official fail-to-pass and pass-to-pass test outcomes; preserve per-test observations",
        "exclusion_policy": "only pre-registered unavailable images or irreproducible verified tasks",
        "metric_mappings": ["resolved", "fail_to_pass", "pass_to_pass", "regressions"],
    },
    "swe-bench-verified": {
        "case_identity_policy": "official instance id, repository, base commit, and problem statement digest",
        "label_policy": "official evaluation harness fail-to-pass and pass-to-pass outcomes",
        "exclusion_policy": "only pre-registered harness-incompatible cases; never exclude model failures",
        "metric_mappings": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "cost",
            "latency",
        ],
    },
    "swe-bench-live": {
        "case_identity_policy": "official instance id, dataset revision, repository, base commit, creation month, platform, image digest, and problem-statement digest",
        "label_policy": "official per-instance resolved, fail-to-pass, pass-to-pass, incomplete, and harness-error outcomes retained separately under the exact evaluator revision",
        "exclusion_policy": "only pre-registered license or platform-incompatible instances; retain patch, image, harness, timeout, incomplete, and model failures outside the resolved denominator",
        "metric_mappings": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "patch_application_rate",
            "harness_error_rate",
            "incomplete_rate",
            "contamination_window_days",
            "repository_and_month_stratum_coverage",
        ],
    },
    "terminal-bench-2": {
        "case_identity_policy": "pinned Terminal-Bench 2 task id and manifest digest, task and dataset revision, container image digest, Harbor revision, verifier revision, agent and model revision, system and tool policy digests, platform, attempt, seed, and trajectory digest",
        "label_policy": "preserve official verifier reward, task success, per-verifier outcomes, trajectory completion, unsafe actions, tool errors, timeouts, infrastructure failures, resource use, cost, and latency as distinct evidence",
        "exclusion_policy": "only pre-registered license or unavailable-image cases; retain verifier failures, zero rewards, unsafe actions, tool errors, timeouts, resource exhaustion, incomplete trajectories, and infrastructure errors outside the success denominator",
        "metric_mappings": [
            "task_success_rate",
            "verifier_reward",
            "trajectory_completion_rate",
            "tool_error_rate",
            "timeout_rate",
            "infrastructure_error_rate",
            "unsafe_action_rate",
            "cost",
            "latency",
        ],
    },
    "realvuln-python": {
        "case_identity_policy": "repository, immutable revision, ground-truth finding id, and source coordinate",
        "label_policy": "reviewed positive labels and explicit false-positive traps; preserve CWE and reviewer provenance",
        "exclusion_policy": "only pre-registered license, build, or unsupported-language cases",
        "metric_mappings": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "localization",
            "cwe",
        ],
    },
    "pysastbench": {
        "case_identity_policy": "repository, CVE, vulnerable revision, and reviewed vulnerable source coordinate",
        "label_policy": "upstream CVE/CWE ground truth with independently reviewed localization",
        "exclusion_policy": "only pre-registered non-reproducible revisions or unsupported project environments",
        "metric_mappings": [
            "cves_detected",
            "cves_missed",
            "cwe_recall",
            "localization_accuracy",
        ],
    },
    "patcheval-verified": {
        "case_identity_policy": "official task id, repository, vulnerable commit, and container manifest digest",
        "label_policy": "exploit oracle and functional oracle outcomes remain separate; resolved requires both",
        "exclusion_policy": "only pre-registered unavailable verified images or non-Python strata",
        "metric_mappings": [
            "resolved",
            "exploit_oracle",
            "functional_oracle",
            "regressions",
        ],
    },
    "nist-sard-control": {
        "case_identity_policy": "SARD suite id, suite version, test-case id, language, and weakness identifier",
        "label_policy": "NIST-published flaw presence, weakness, and location; retain synthetic and production strata",
        "exclusion_policy": "select exact pre-registered SARD suite ids; report unsupported languages as exclusions",
        "metric_mappings": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "cwe_mapping_accuracy",
            "sarif_interoperability",
        ],
    },
    "pysfmea-mutation-proficiency": {
        "case_identity_policy": "corpus revision, subject id, source digest, mutation engine and version, operator, mutant id, seed, repetition, and expected disposition",
        "label_policy": "independently reviewed kill, survival, equivalence, invalid, and real-fault correlation labels with per-mutant execution evidence",
        "exclusion_policy": "only pre-registered platform-incompatible subjects; retain timeouts, invalid mutants, tool disagreements, and unresolved equivalence",
        "metric_mappings": [
            "mutation_score",
            "seeded_fault_detection_rate",
            "equivalent_mutant_disposition_rate",
            "operator_stratum_coverage",
            "tool_agreement",
            "runtime_seconds",
        ],
    },
    "pysfmea-fuzz-ground-truth": {
        "case_identity_policy": "corpus revision, target id, target digest, seeded fault id, engine and version, seed corpus digest, random seed, repetition, and time budget",
        "label_policy": "exact triggering-input and fault-site evidence with independently reviewed crash classification and reproducible non-trigger controls",
        "exclusion_policy": "only pre-registered unavailable engines or platforms; retain build, instrumentation, timeout, crash-classification, and reproduction failures",
        "metric_mappings": [
            "fault_discovery_rate",
            "time_to_first_fault",
            "unique_fault_recall",
            "false_crash_rate",
            "coverage_growth",
            "reproducer_success_rate",
        ],
    },
    "pysfmea-framework-negative-controls": {
        "case_identity_policy": "corpus revision, framework and version, interpreter, case id, source digest, feature stratum, and expected positive, negative, or unsupported label",
        "label_policy": "two-reviewer source and runtime adjudication with benign controls, hazards, relationships, interfaces, and unsupported semantics retained separately",
        "exclusion_policy": "only pre-registered unavailable framework/interpreter combinations; retain parse, import, resolution, and analysis failures",
        "metric_mappings": [
            "finding_precision",
            "finding_recall",
            "false_positive_rate",
            "call_edge_precision",
            "interface_precision",
            "unsupported_feature_rate",
        ],
    },
    "pysfmea-python-platform-matrix": {
        "case_identity_policy": "matrix revision, case id, source digest, interpreter implementation and version, operating system, architecture, dependency lock, and package digest",
        "label_policy": "canonical reference artifact plus independently reviewed permitted and prohibited platform differences",
        "exclusion_policy": "only pre-registered unsupported matrix cells; retain install, scan, schema, semantic, runtime, memory, and artifact divergence",
        "metric_mappings": [
            "semantic_equivalence_rate",
            "artifact_equivalence_rate",
            "platform_failure_rate",
            "interpreter_failure_rate",
            "runtime_variance",
            "memory_variance",
        ],
    },
    "pysfmea-temporal-hidden-holdout": {
        "case_identity_policy": "scheme revision, opaque subject id, immutable post-cutoff revision, custody digest, execution id, and predeclared stratum",
        "label_policy": "independent hidden labels released only after frozen predictions, with provenance and adjudication retained by the holdout authority",
        "exclusion_policy": "only pre-registered legal or irreproducible subjects; retain scanner failures and prohibit post-outcome exclusions",
        "metric_mappings": [
            "finding_precision",
            "finding_recall",
            "propagation_precision",
            "propagation_recall",
            "calibration_error",
            "holdout_non_inferiority",
        ],
    },
    "pysfmea-cross-organization-proficiency": {
        "case_identity_policy": "scheme and round revision, item id and digest, participant pseudonym, method id, submission digest, and receipt timestamp",
        "label_policy": "competently assigned quantitative values or qualitative categories with uncertainty, stability, homogeneity, and independent review evidence",
        "exclusion_policy": "only predeclared participant withdrawal or invalid item rounds; retain late, incomplete, anomalous, warning, and action results",
        "metric_mappings": [
            "participant_completion_rate",
            "quantitative_z_score",
            "qualitative_agreement_rate",
            "between_participant_dispersion",
            "warning_rate",
            "action_rate",
        ],
    },
    "livecodebench-test-generation": {
        "case_identity_policy": "pinned LiveCodeBench release, scenario, task id, task publication date, model or generator revision, prompt policy digest, sample id, and execution receipt",
        "label_policy": "official hidden-test execution outcome retained separately from generated tests, public examples, coverage, contamination review, and SFMEA relevance",
        "exclusion_policy": "only pre-registered unsupported runtimes or dependencies; retain generation failures, sandbox failures, timeouts, suspected contamination, and post-cutoff violations",
        "metric_mappings": [
            "pass_at_1",
            "test_generation_pass_rate",
            "temporal_stratum_performance",
            "contamination_audit_rate",
            "execution_failure_rate",
        ],
    },
    "fuzzbench-statistical-trials": {
        "case_identity_policy": "FuzzBench revision, benchmark and fuzzer revision, experiment id, trial id, random seed, runner image digest, resource budget, and observation time",
        "label_policy": "observed per-trial coverage and event trajectories; statistical comparisons remain estimates and never become defect labels",
        "exclusion_policy": "only pre-registered infrastructure-invalid trials; retain crashes, timeouts, zero-coverage trials, censored events, and all post-outcome exclusions",
        "metric_mappings": [
            "coverage_distribution",
            "median_coverage",
            "time_to_event_distribution",
            "trial_failure_rate",
            "effect_size",
            "confidence_interval",
        ],
    },
    "quixbugs-python": {
        "case_identity_policy": "pinned QuixBugs revision, Python program id, buggy-source digest, corrected-source digest, task mapping revision, and test execution id",
        "label_policy": "reviewed buggy/corrected semantic difference and independently executed reveal tests retained separately from scanner prediction or generated test",
        "exclusion_policy": "only pre-registered unsupported interpreter cases; retain non-revealing tests, invalid tests, localization misses, timeouts, and regressions",
        "metric_mappings": [
            "defect_detection_rate",
            "fault_localization_accuracy",
            "generated_test_reveal_rate",
            "repair_validation_rate",
            "regression_rate",
        ],
    },
    "bigcodebench": {
        "case_identity_policy": "pinned BigCodeBench release and split, task id, task date, dependency lock digest, harness digest, model or generator revision, prompt policy digest, and sample id",
        "label_policy": "official harness and test outcome preserved separately from instructions, generated artifacts, sandbox behavior, library stratum, and SFMEA relevance review",
        "exclusion_policy": "only pre-registered unsupported dependencies; retain generation, dependency, sandbox, timeout, and harness failures plus contamination concerns",
        "metric_mappings": [
            "complete_pass_at_1",
            "instruct_pass_at_1",
            "library_stratum_performance",
            "test_generation_pass_rate",
            "sandbox_failure_rate",
        ],
    },
    "pysfmea-dual-mutation-engine-qualification": {
        "case_identity_policy": "corpus revision, subject digest, canonical mutant id, operator and location, engine id and version, mapped engine-mutant id, test-suite digest, and execution id",
        "label_policy": "per-engine killed, survived, invalid, timeout, or equivalent disposition with independent mapping and equivalence adjudication; agreement is not truth",
        "exclusion_policy": "only pre-registered unsupported operators; retain unmapped, invalid, timeout, engine-error, discordant, and unresolved-equivalence mutants",
        "metric_mappings": [
            "engine_mutant_mapping_rate",
            "kill_agreement_rate",
            "discordant_mutants",
            "equivalent_mutant_rate",
            "mutation_score_by_engine",
            "adjudication_completion_rate",
        ],
    },
    "pysfmea-scale-resource-exhaustion": {
        "case_identity_policy": "generator revision, deterministic seed, scale stratum, source-tree digest, graph-shape parameters, environment digest, resource budget, repetition, and execution id",
        "label_policy": "expected generated structure and independently observed completion, limit, runtime, memory, artifact, and semantic-equivalence outcomes",
        "exclusion_policy": "only pre-registered unsupported environments; retain generation, scan, timeout, memory, output-limit, crash, truncation, and semantic-divergence outcomes",
        "metric_mappings": [
            "completion_rate_by_scale",
            "runtime_scaling_exponent",
            "peak_memory_scaling",
            "timeout_rate",
            "resource_limit_conformance",
            "semantic_equivalence_rate",
        ],
    },
    "cyberseceval-4": {
        "case_identity_policy": "pinned CyberSecEval revision, benchmark family and version, dataset digest, case id, model and provider revision, system and tool policy digests, sampling seed, repetition, judge identity, and execution id",
        "label_policy": "preserve official deterministic labels, execution outcomes, model-judge decisions, false-refusal labels, and human adjudication as separate evidence channels; never convert model-judge output into unquestioned ground truth",
        "exclusion_policy": "only pre-registered unavailable controlled-access datasets or unsupported model modalities; retain refusals, blocked requests, judge failures, tool-policy violations, timeouts, unsafe actions, and infrastructure failures",
        "metric_mappings": [
            "insecure_code_rate",
            "prompt_injection_success_rate",
            "interpreter_abuse_rate",
            "autonomous_operation_success_rate",
            "defensive_reasoning_accuracy",
            "autopatch_success_rate",
            "false_refusal_rate",
        ],
    },
    "crosscodeeval-python": {
        "case_identity_policy": "pinned CrossCodeEval revision and Python split, repository and task id, left and right context digests, retrieval-corpus digest, retriever version, model revision, prompt policy, and sample id",
        "label_policy": "preserve official target and lexical metrics separately from retrieved context, generated artifact, optional syntax or execution outcome, and independent SFMEA-relevance review",
        "exclusion_policy": "only pre-registered license or unavailable-runtime cases; retain retrieval misses, generation failures, invalid syntax, execution failures, timeouts, and contamination concerns",
        "metric_mappings": [
            "exact_match",
            "edit_similarity",
            "identifier_match",
            "retrieval_recall",
            "dependency_context_precision",
            "execution_success_rate",
        ],
    },
    "crosscodelongeval-python": {
        "case_identity_policy": "pinned CrossCodeLongEval revision and Python split, repository and task id, long-range dependency labels, retrieval-corpus digest, retriever and model revisions, context budget, prompt policy, and sample id",
        "label_policy": "preserve official target and dependency labels separately from retrieval observations, completion metrics, token use, syntax or execution outcomes, and SFMEA-relevance review",
        "exclusion_policy": "only pre-registered license or unavailable-runtime cases; retain context truncation, retrieval misses, generation failures, invalid outputs, timeouts, and contamination concerns",
        "metric_mappings": [
            "exact_match",
            "edit_similarity",
            "identifier_match",
            "long_range_dependency_recall",
            "retrieval_precision",
            "context_efficiency",
        ],
    },
    "pysfmea-nondeterminism-concurrency": {
        "case_identity_policy": "corpus revision, scenario and stratum id, subject digest, interpreter and platform, dependency lock digest, seed, schedule or order trace, perturbation policy, repetition, and execution id",
        "label_policy": "independently reviewed nondeterminism mechanism and expected outcome distribution joined to isolated per-attempt observations; a passing repetition never proves stability",
        "exclusion_policy": "only pre-registered unavailable platform or dependency cases; retain hangs, deadlocks, crashes, timeouts, non-reproduction, instrumentation gaps, and divergent schedules",
        "metric_mappings": [
            "flaky_detection_precision",
            "flaky_detection_recall",
            "reproduction_rate",
            "schedule_stratum_coverage",
            "race_detection_rate",
            "order_dependency_detection_rate",
            "stabilization_validation_rate",
            "false_stability_rate",
        ],
    },
    "agentdojo": {
        "case_identity_policy": "pinned AgentDojo revision and benchmark version, suite, user task, injection task, attack, defense, pipeline, model revision, prompt and tool-output policies, seed, repetition, and trajectory digest",
        "label_policy": "preserve AgentDojo utility and security outcomes, injection-task utility, error, duration, and full trajectory as separate evidence; security success never substitutes for user-task utility",
        "exclusion_policy": "only pre-registered unavailable model or controlled service cases; retain refusals, context exhaustion, tool errors, injection success, utility failure, timeouts, and incomplete traces",
        "metric_mappings": [
            "benign_utility_rate",
            "utility_under_attack_rate",
            "security_under_attack_rate",
            "attack_success_rate",
            "defense_utility_delta",
            "tool_policy_violation_rate",
            "trajectory_completion_rate",
        ],
    },
    "swe-polybench-verified-python": {
        "case_identity_policy": "pinned SWE-PolyBench revision and Verified Python split, annotation digest, instance id, repository and base revision, frozen image digest, problem-statement digest, prediction digest, model revision, attempt, and execution id",
        "label_policy": "official per-instance resolved, fail-to-pass, pass-to-pass, patch-application, retrieval, and harness outcomes remain distinct; gold-patch validation and model results are separate strata",
        "exclusion_policy": "only pre-registered non-Python or unavailable lawful-image cases; retain empty patches, apply failures, build failures, test failures, timeouts, infrastructure errors, and incomplete results",
        "metric_mappings": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "file_retrieval_precision",
            "file_retrieval_recall",
            "node_retrieval_recall",
            "patch_application_rate",
            "harness_error_rate",
        ],
    },
    "idoft-python": {
        "case_identity_policy": "pinned IDoFT Python CSV digest, project URL, detected revision, fully qualified test name, order-dependence category, fixed revision when present, environment digest, schedule policy, repetition, and execution id",
        "label_policy": "upstream detected or fixed flakiness record is a candidate label joined to independent reproduction outcomes; absence from IDoFT is never a negative label",
        "exclusion_policy": "only pre-registered license or irretrievable revision cases; retain dependency failures, collection failures, non-reproduction, timeouts, infrastructure failures, and label ambiguity",
        "metric_mappings": [
            "flaky_detection_precision",
            "flaky_detection_recall",
            "order_dependency_accuracy",
            "reproduction_rate",
            "fixed_revision_validation_rate",
            "unavailable_revision_rate",
            "infrastructure_failure_rate",
        ],
    },
}


def benchmark_adapter_template(*, suite_id: str, authority: str) -> dict[str, Any]:
    if suite_id not in SUITE_IDS:
        raise ValueError("unknown governed benchmark suite")
    blueprint = ADAPTER_BLUEPRINTS[suite_id]
    return seal(
        {
            "format": BENCHMARK_ADAPTER_FORMAT,
            "generated_at": utc_now(),
            "suite": {
                "id": suite_id,
                "revision": "unassigned",
                "snapshot_sha256": "0" * 64,
                "license_evidence_ref": "unassigned",
            },
            "adapter": {
                "id": f"pysfmea-{suite_id}",
                "version": "unassigned",
                "source_sha256": "0" * 64,
                "source_evidence_ref": "unassigned",
                "image": "unassigned@sha256:" + "0" * 64,
                "command": [],
                "output_path": "/evidence/benchmark-observations.json",
            },
            "normalization": {
                "output_format": BENCHMARK_OBSERVATIONS_FORMAT,
                "case_identity_policy": blueprint["case_identity_policy"],
                "label_policy": blueprint["label_policy"],
                "exclusion_policy": blueprint["exclusion_policy"],
                "metric_mappings": list(blueprint["metric_mappings"]),
            },
            "authority": {
                "adapter_owner": bounded_text(authority, "benchmark adapter authority"),
                "independent_reviewer": "unassigned",
                "review_evidence_ref": "unassigned",
            },
            "limitations": [
                "The suite-aware normalization policy is supplied, but the adapter is not eligible until its exact suite, implementation, license, immutable runner, and independent review are bound."
            ],
            "claim_boundary": "This manifest governs deterministic translation into PySFMEA observations. It does not establish suite representativeness, label correctness, or certification.",
        }
    )


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value))
        and value != "0" * 64
    )


def _semantics(value: dict[str, Any]) -> tuple[bool, bool]:
    try:
        suite = value["suite"]
        adapter = value["adapter"]
        normalization = value["normalization"]
        authority = value["authority"]
        structure = bool(
            set(value)
            == {
                "format",
                "generated_at",
                "suite",
                "adapter",
                "normalization",
                "authority",
                "limitations",
                "claim_boundary",
                "content_sha256",
            }
            and set(suite)
            == {"id", "revision", "snapshot_sha256", "license_evidence_ref"}
            and suite["id"] in SUITE_IDS
            and set(adapter)
            == {
                "id",
                "version",
                "source_sha256",
                "source_evidence_ref",
                "image",
                "command",
                "output_path",
            }
            and isinstance(adapter["command"], list)
            and len(adapter["command"]) <= 100
            and all(
                isinstance(item, str) and 0 < len(item) <= 20_000
                for item in adapter["command"]
            )
            and adapter["output_path"] == "/evidence/benchmark-observations.json"
            and set(normalization)
            == {
                "output_format",
                "case_identity_policy",
                "label_policy",
                "exclusion_policy",
                "metric_mappings",
            }
            and normalization["output_format"] == BENCHMARK_OBSERVATIONS_FORMAT
            and isinstance(normalization["metric_mappings"], list)
            and len(normalization["metric_mappings"]) <= 1_000
            and len(normalization["metric_mappings"])
            == len(set(normalization["metric_mappings"]))
            and all(
                isinstance(item, str) and item
                for item in normalization["metric_mappings"]
            )
            and set(authority)
            == {"adapter_owner", "independent_reviewer", "review_evidence_ref"}
            and isinstance(value["limitations"], list)
            and bool(value["limitations"])
        )
        ready = bool(
            structure
            and suite["revision"] != "unassigned"
            and suite["license_evidence_ref"] != "unassigned"
            and _digest(suite["snapshot_sha256"])
            and adapter["version"] != "unassigned"
            and _digest(adapter["source_sha256"])
            and adapter["source_evidence_ref"] != "unassigned"
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", adapter["image"] or "")
            and not adapter["image"].endswith("0" * 64)
            and bool(adapter["command"])
            and all(
                normalization[name] != "unassigned"
                for name in ("case_identity_policy", "label_policy", "exclusion_policy")
            )
            and bool(normalization["metric_mappings"])
            and authority["independent_reviewer"] != "unassigned"
            and authority["independent_reviewer"] != authority["adapter_owner"]
            and authority["review_evidence_ref"] != "unassigned"
        )
        return structure, ready
    except (KeyError, TypeError):
        return False, False


def verify_benchmark_adapter(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="benchmark adapter", format_value=BENCHMARK_ADAPTER_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure, ready = _semantics(checked)
    if not structure:
        errors.append("benchmark adapter fields are invalid")
    if structure and not ready:
        errors.append(
            "benchmark adapter provenance, normalization, or independent review is incomplete"
        )
    return seal(
        {
            "format": BENCHMARK_ADAPTER_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "eligible_for_execution": integrity and structure and ready,
            "checks": {
                "content_integrity": integrity,
                "closed_adapter_contract": structure,
                "provenance_normalization_and_review_complete": ready,
            },
            "errors": errors,
            "notice": "Eligibility establishes a reviewed adapter contract, not benchmark validity or certification.",
        }
    )


def seal_benchmark_adapter(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="benchmark adapter")
    value.pop("content_sha256", None)
    result = seal(value)
    if not verify_benchmark_adapter(result)["valid"]:
        raise ValueError("benchmark adapter source is invalid")
    return publish_json(result, destination)


def verify_benchmark_adapter_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_benchmark_adapter(load_json(source, label="benchmark adapter"))
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_ADAPTER_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_execution": False,
                "checks": {
                    "content_integrity": False,
                    "closed_adapter_contract": False,
                    "provenance_normalization_and_review_complete": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark-adapter verification failed closed.",
            }
        )


def export_benchmark_adapter(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_benchmark_adapter(value)["valid"]:
        raise ValueError("benchmark adapter is internally invalid")
    return publish_json(value, destination)

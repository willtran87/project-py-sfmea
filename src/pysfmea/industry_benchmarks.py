"""Governed external benchmark registry and execution-evidence contract."""

from __future__ import annotations

import copy
import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .model import utc_now

BENCHMARK_CATALOG_FORMAT = "pysfmea-industry-benchmark-catalog-1"
BENCHMARK_EXECUTION_FORMAT = "pysfmea-benchmark-execution-2"
BENCHMARK_EXECUTION_VERIFICATION_FORMAT = "pysfmea-benchmark-execution-verification-1"

BENCHMARK_SUITES: tuple[dict[str, Any], ...] = (
    {
        "id": "pysfmea-semantic-corpus",
        "title": "Python SFMEA Semantic Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/python_sfmea_corpus",
        "population": "independently governable Python repositories labeled for components, call sequences, controls, failure modes, and exact semantic claims",
        "measures": [
            "finding_precision",
            "finding_recall",
            "call_resolution_precision",
            "call_resolution_recall",
            "control_precision",
            "control_recall",
            "semantic_claim_precision",
            "semantic_claim_recall",
        ],
        "use": "Directly evaluate the scanner's core SFMEA discovery, propagation-supporting graph, timing/control, and generated-failure-mode semantics.",
        "limitation": "The bundled corpus is a deterministic regression fixture, not independent representative evidence; qualification requires additional repositories, independent labels, blinded execution, and a reviewed population rationale.",
    },
    {
        "id": "pysfmea-causal-propagation",
        "title": "Python SFMEA Causal Propagation Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/causal_propagation_corpus",
        "population": "governed fault-injection scenarios labeled for ordered cascade paths, effects, deadlines, circuit-breaker transitions, and recovery",
        "measures": [
            "path_edge_precision",
            "path_edge_recall",
            "exact_ordered_path_rate",
            "effect_precision",
            "effect_recall",
            "deadline_conformance",
            "breaker_transition_accuracy",
            "recovery_conformance",
        ],
        "use": "Directly validate whether static cascade, timing, resilience-control, and recovery predictions agree with content-addressed runtime fault-injection evidence.",
        "limitation": "No external standard corpus establishes Python SFMEA causal truth. Qualification requires independently designed scenarios, reviewed injection and observation oracles, representative distributed-system strata, and controlled execution evidence.",
    },
    {
        "id": "pysfmea-modern-python-dynamics",
        "title": "Modern Python Dynamic Resolution Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/dynamic_python_corpus",
        "population": "independently labelable Python 3.12 through 3.14 cases for decorators, descriptors, protocols, singledispatch, dependency injection, framework routing, async tasks, plugins, reflection, and runtime registration",
        "measures": [
            "call_edge_precision",
            "call_edge_recall",
            "interface_precision",
            "interface_recall",
            "sequence_precision",
            "sequence_recall",
            "unsupported_feature_rate",
        ],
        "use": "Detect accuracy regression on dynamic language and framework constructs that older call-graph research corpora do not represent.",
        "limitation": "The bundled cases are regression fixtures until independently labeled, stratified, version-pinned, and supplemented by representative operational repositories.",
    },
    {
        "id": "pysfmea-distributed-resilience",
        "title": "Distributed Resilience and Temporal Failure Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/distributed_resilience_corpus",
        "population": "controlled multi-service Python scenarios with trace-grounded timeout, retry, backoff, circuit-breaker, queue, cancellation, idempotency, failover, overload, and recovery behavior",
        "measures": [
            "path_edge_precision",
            "path_edge_recall",
            "deadline_conformance",
            "retry_policy_accuracy",
            "breaker_transition_accuracy",
            "queue_effect_accuracy",
            "recovery_conformance",
            "trace_coverage",
        ],
        "use": "Evaluate whether static failure chains and generated tests reflect observed temporal and resilience-control behavior across service boundaries.",
        "limitation": "Controlled scenarios cannot establish production reliability; network, infrastructure, traffic, and dependency populations require project-specific campaigns and operational approval.",
    },
    {
        "id": "pysfmea-interoperability-conformance",
        "title": "Assurance Interoperability Conformance Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/interoperability_conformance_corpus",
        "population": "valid, invalid, boundary, round-trip, and semantic-preservation cases for supported SARIF, OSCAL, SPDX, CycloneDX, CSAF, ReqIF, Security Insights, and JSON Schema exchanges",
        "measures": [
            "valid_acceptance_rate",
            "invalid_rejection_rate",
            "roundtrip_preservation_rate",
            "semantic_preservation_rate",
            "schema_version_coverage",
            "consumer_compatibility_rate",
        ],
        "use": "Qualify supported interchange subsets against exact official schemas and independent receiving-tool evidence.",
        "limitation": "Passing bundled cases is not conformance to an entire external specification; official schema versions and independent consumers must be pinned for each campaign.",
    },
    {
        "id": "pysfmea-longitudinal-drift",
        "title": "Longitudinal Analysis Drift Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/longitudinal_drift_corpus",
        "population": "immutable repository revision series with reviewed expected finding, component, interface, graph, confidence, performance, and evidence changes",
        "measures": [
            "expected_change_recall",
            "unexpected_change_rate",
            "finding_churn",
            "graph_churn",
            "confidence_drift",
            "runtime_regression",
            "memory_regression",
            "incremental_equivalence_rate",
        ],
        "use": "Detect semantic, confidence, performance, and incremental-analysis regressions across product and repository revisions.",
        "limitation": "A frozen revision series supports non-regression and change sensitivity, not general accuracy outside its reviewed population.",
    },
    {
        "id": "pynguin-sbft-python",
        "title": "Pynguin and SBFT Python Test Generation Track",
        "source_url": "https://github.com/se2p/pynguin",
        "population": "version-pinned Python units and open-source subjects used to compare automated unit-test generation strategies under repeated bounded runs",
        "measures": [
            "test_generation_success_rate",
            "line_coverage",
            "branch_coverage",
            "mutation_score",
            "real_fault_detection",
            "flakiness",
            "unsafe_oracle",
            "runtime_seconds",
        ],
        "use": "Provide a search-based independent comparator for LLM-generated tests and coverage or mutation claims.",
        "limitation": "Pynguin is a research tool that executes target code. Campaigns require a network-denied disposable sandbox, repeated stochastic runs, exact subject versions, and independently reviewed assertions and fault results.",
    },
    {
        "id": "pycg-callgraph",
        "title": "PyCG Python Call-Graph Benchmark",
        "source_url": "https://github.com/vitsalis/PyCG",
        "population": "minimal Python call-resolution cases and real-package macro benchmarks with reviewed call-edge ground truth",
        "measures": [
            "call_edge_precision",
            "call_edge_recall",
            "unresolved_calls",
            "runtime_seconds",
            "peak_memory_mb",
        ],
        "use": "Evaluate static call resolution against a published ICSE replication package and provide a comparator baseline.",
        "limitation": "The archived research artifact targets older Python features and its micro/macro population cannot establish accuracy on current frameworks or dynamic runtime behavior.",
    },
    {
        "id": "jarvis-callgraph",
        "title": "JARVIS Python Call-Graph Benchmark",
        "source_url": "https://pythonjarvis.github.io/",
        "population": "flow-sensitive Python call-graph micro and macro benchmarks with published ground truth",
        "measures": [
            "call_edge_precision",
            "call_edge_recall",
            "unresolved_calls",
            "runtime_seconds",
            "peak_memory_mb",
        ],
        "use": "Cross-check call resolution against a distinct demand-driven analysis and its published benchmark labels.",
        "limitation": "The research artifact and ground truth require immutable archival pinning and independent label review; agreement between tools is not truth.",
    },
    {
        "id": "dypybench",
        "title": "DyPyBench Executable Python Benchmark",
        "source_url": "https://github.com/sola-st/DyPyBench",
        "population": "50 executable open-source Python projects with prepared tests and integrated dynamic-analysis support",
        "measures": [
            "static_edge_precision_against_trace",
            "static_edge_recall_against_trace",
            "projects_executable",
            "tests_executed",
            "trace_coverage",
            "runtime_seconds",
        ],
        "use": "Compare static graph and sequence predictions with runtime-observed edges across a diverse executable project population.",
        "limitation": "A dynamic trace is an under-approximation governed by exercised tests and instrumentation; the large historical environment must be pinned, isolated, and lawfully reproduced.",
    },
    {
        "id": "testexplora",
        "title": "TestExplora",
        "source_url": "https://github.com/microsoft/TestExplora",
        "population": "repository-level Python pull-request tasks for proactive latent-defect discovery through generated tests",
        "measures": [
            "fail_to_pass",
            "pass_to_pass",
            "defects_exposed",
            "test_pass_rate",
            "flakiness",
            "unsafe_oracle",
            "latency",
            "cost",
        ],
        "use": "Evaluate whether LLM-generated tests expose a defect on the buggy revision and remain valid on the repaired revision.",
        "limitation": "Historical pull requests may be contaminated by model training, automatically derived task documentation may be imperfect, and benchmark success does not establish safety-requirement coverage.",
    },
    {
        "id": "owasp-benchmark-python",
        "title": "OWASP Benchmark for Python",
        "source_url": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "population": "synthetic Python security test cases with known labels",
        "measures": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
        ],
        "use": "Security finding detection and false-positive characterization.",
        "limitation": "The upstream Python benchmark is preliminary (v0.1) and identifies repository HEAD as its latest version. Every campaign must pin an immutable commit and license evidence; synthetic security cases do not establish performance on operational repositories.",
    },
    {
        "id": "bugsinpy",
        "title": "BugsInPy",
        "source_url": "https://github.com/soarsmu/BugsInPy",
        "population": "reproducible real Python defects",
        "measures": ["defects_detected", "defects_missed", "tests_passing"],
        "use": "Real-defect detection, localization, and regression-test evaluation.",
        "limitation": "Project and defect sampling does not represent every Python domain.",
    },
    {
        "id": "testgeneval",
        "title": "TestGenEval",
        "source_url": "https://github.com/facebookresearch/testgeneval",
        "population": "repository-level Python test-generation tasks",
        "measures": ["test_pass_rate", "coverage_delta", "mutation_score"],
        "use": "Evaluate LLM-generated tests for executability, coverage, and fault sensitivity.",
        "limitation": "Benchmark success is not evidence that generated tests satisfy project safety requirements.",
    },
    {
        "id": "tdd-bench-verified",
        "title": "TDD-Bench Verified",
        "source_url": "https://github.com/IBM/TDD-Bench-Verified",
        "population": "verified issue-driven test-generation tasks",
        "measures": ["resolved", "fail_to_pass", "pass_to_pass"],
        "use": "Evaluate whether generated tests reproduce requested behavior without regressions.",
        "limitation": "Issue resolution is not a substitute for requirements-based verification.",
    },
    {
        "id": "swe-bench-verified",
        "title": "SWE-bench Verified",
        "source_url": "https://www.swebench.com/",
        "population": "human-validated software engineering tasks",
        "measures": ["resolved", "fail_to_pass", "pass_to_pass"],
        "use": "Comparator baseline for repository-level repair and test workflows.",
        "limitation": "A general coding benchmark is indirect evidence for SFMEA accuracy.",
    },
    {
        "id": "realvuln-python",
        "title": "RealVuln Python Benchmark",
        "source_url": "https://github.com/kolega-ai/Real-Vuln-Benchmark",
        "population": "repository-level Python applications with reviewed CWE ground truth and false-positive traps",
        "measures": [
            "true_positive",
            "false_positive",
            "false_negative",
            "precision",
            "recall",
            "f_score",
        ],
        "use": "Characterize scanner behavior on realistic Python applications and negative controls.",
        "limitation": "The evolving community benchmark is not an independent certification program; pin the manifest, ground truth, licenses, and benchmark version.",
    },
    {
        "id": "pysastbench",
        "title": "PySASTBench",
        "source_url": "https://github.com/Victor725/PySASTBench",
        "population": "real Python CVE cases selected for SAST evaluation",
        "measures": [
            "cves_detected",
            "cves_missed",
            "cwe_recall",
            "localization_accuracy",
        ],
        "use": "Evaluate Python SAST detection and localization on disclosed vulnerabilities.",
        "limitation": "CVE selection, build reproducibility, ground-truth precision, and negative controls require independent review.",
    },
    {
        "id": "patcheval-verified",
        "title": "PatchEval-Verified",
        "source_url": "https://github.com/bytedance/PatchEval",
        "population": "Docker-verified real-world vulnerability repair tasks including Python",
        "measures": ["resolved", "exploit_oracle", "functional_oracle", "regressions"],
        "use": "Evaluate whether generated remediation and tests eliminate an exploitable vulnerability without functional regression.",
        "limitation": "Multi-language repair results are indirect evidence for Python SFMEA discovery and must be stratified by language and task type.",
    },
    {
        "id": "nist-sard-control",
        "title": "NIST Software Assurance Reference Dataset control",
        "source_url": "https://samate.nist.gov/SARD/test-suites",
        "population": "NIST-published synthetic, production, and academic weakness cases in supported non-Python languages",
        "measures": [
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
            "cwe_mapping_accuracy",
            "sarif_interoperability",
        ],
        "use": "Independent cross-language control for weakness taxonomy normalization, SARIF interoperability, and overfitting detection. The adapter must pin exact SARD suite ids and versions rather than the changing portal population.",
        "limitation": "SARD does not currently provide a representative Python corpus and cannot establish Python scanner accuracy; use it only alongside governed Python-specific suites.",
    },
    {
        "id": "pysfmea-mutation-proficiency",
        "title": "Python Mutation Proficiency Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/mutation_proficiency_corpus",
        "population": "content-addressed Python subjects with independently reviewable seeded mutants, equivalent-mutant dispositions, expected kill or survival outcomes, and mutmut/Cosmic Ray comparator observations",
        "measures": [
            "mutation_score",
            "seeded_fault_detection_rate",
            "equivalent_mutant_disposition_rate",
            "operator_stratum_coverage",
            "tool_agreement",
            "runtime_seconds",
        ],
        "use": "Measure whether generated and retained tests detect meaningful controlled code faults and compare results across independent mutation engines.",
        "limitation": "Mutation operators are proxies for faults. Qualification requires reviewed equivalence decisions, real-defect correlation, exact tool versions, repeated execution, and retained per-mutant evidence.",
    },
    {
        "id": "pysfmea-fuzz-ground-truth",
        "title": "Python Seeded-Fault Fuzzing Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/fuzz_ground_truth_corpus",
        "population": "deterministic Python and Atheris-compatible targets with seeded parser, state, resource, and boundary faults plus exact triggering inputs and non-trigger controls",
        "measures": [
            "fault_discovery_rate",
            "time_to_first_fault",
            "unique_fault_recall",
            "false_crash_rate",
            "coverage_growth",
            "reproducer_success_rate",
        ],
        "use": "Evaluate fuzz-campaign discovery, crash classification, reproducer preservation, coverage, and stochastic variability against known faults.",
        "limitation": "Bundled targets are regression fixtures. FuzzBench-style repeated trials and independent real-world targets are required before general fuzzer-effectiveness claims.",
    },
    {
        "id": "pysfmea-framework-negative-controls",
        "title": "Python Framework and Metaprogramming Negative-Control Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/framework_negative_controls",
        "population": "benign and hazardous Django, FastAPI, Pydantic, SQLAlchemy, Celery, dependency-injection, decorator, descriptor, plugin, and reflection patterns with explicit positive, negative, and unsupported labels",
        "measures": [
            "finding_precision",
            "finding_recall",
            "false_positive_rate",
            "call_edge_precision",
            "interface_precision",
            "unsupported_feature_rate",
        ],
        "use": "Stress precision and conservative uncertainty handling on framework magic that can resemble hidden control flow or failure behavior.",
        "limitation": "Framework APIs and semantics evolve. Every result must be stratified by exact framework and Python versions and unsupported constructs must remain visible.",
    },
    {
        "id": "pysfmea-python-platform-matrix",
        "title": "Python Interpreter and Platform Qualification Matrix",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/python_platform_matrix",
        "population": "identical governed cases executed across supported CPython and PyPy versions, Windows and Linux, encoding and path variants, dependency-lock modes, and clean package installations",
        "measures": [
            "semantic_equivalence_rate",
            "artifact_equivalence_rate",
            "platform_failure_rate",
            "interpreter_failure_rate",
            "runtime_variance",
            "memory_variance",
        ],
        "use": "Establish whether supported environments preserve analysis semantics, evidence formats, and bounded operational behavior.",
        "limitation": "A declared matrix is not executed evidence. Qualification requires retained CI identities, exact environments, artifacts, exclusions, and investigation of every divergence.",
    },
    {
        "id": "pysfmea-temporal-hidden-holdout",
        "title": "Temporal Hidden-Holdout Qualification Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/temporal_holdout_protocol",
        "population": "independently controlled post-cutoff Python repository revisions and failure cases withheld from scanner, prompt, rule, and threshold development",
        "measures": [
            "finding_precision",
            "finding_recall",
            "propagation_precision",
            "propagation_recall",
            "calibration_error",
            "holdout_non_inferiority",
        ],
        "use": "Detect tuning leakage, benchmark memorization, temporal drift, and loss of generalization on unseen repositories and failures.",
        "limitation": "The repository ships only the protocol and public canary fixtures. Hidden subjects, labels, custody, and blinded execution must remain under an independent authority.",
    },
    {
        "id": "pysfmea-cross-organization-proficiency",
        "title": "Cross-Organization SFMEA Proficiency Scheme",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/proficiency_scheme",
        "population": "content-addressed quantitative and qualitative benchmark items distributed to independent scanner or analyst participants under a controlled proficiency-testing round",
        "measures": [
            "participant_completion_rate",
            "quantitative_z_score",
            "qualitative_agreement_rate",
            "between_participant_dispersion",
            "warning_rate",
            "action_rate",
        ],
        "use": "Compare repeatability, reproducibility, and participant performance under ISO/IEC 17043- and ISO 13528-aligned governance.",
        "limitation": "Bundled material is a scheme scaffold, not an accredited proficiency test. Independent participants, competent governance, assigned values, uncertainty, and authority decisions remain external.",
    },
    {
        "id": "livecodebench-test-generation",
        "title": "LiveCodeBench Test Generation",
        "source_url": "https://github.com/LiveCodeBench/LiveCodeBench",
        "population": "continuously updated, time-indexed code-generation tasks evaluated with hidden tests, stratified to the test-generation scenario and exact release date",
        "measures": [
            "pass_at_1",
            "test_generation_pass_rate",
            "temporal_stratum_performance",
            "contamination_audit_rate",
            "execution_failure_rate",
        ],
        "use": "Provide a temporal external control for LLM-generated tests and detect benchmark contamination or performance concentrated in older public tasks.",
        "limitation": "A general coding benchmark is indirect evidence for SFMEA test adequacy. Pin the exact release and scenario, retain hidden-test execution evidence, and do not infer failure-mode discovery accuracy from pass rates.",
    },
    {
        "id": "fuzzbench-statistical-trials",
        "title": "FuzzBench Repeated-Trial Evaluation",
        "source_url": "https://github.com/google/fuzzbench",
        "population": "containerized benchmark subjects executed through repeated randomized trials using pinned fuzzer, benchmark, runner, and report revisions",
        "measures": [
            "coverage_distribution",
            "median_coverage",
            "time_to_event_distribution",
            "trial_failure_rate",
            "effect_size",
            "confidence_interval",
        ],
        "use": "Apply repeated-trial, distribution-aware evaluation to fuzzing and generated-test campaigns instead of reporting a favorable single stochastic run.",
        "limitation": "FuzzBench primarily evaluates fuzzers and non-Python subjects. It is a statistical-method and external-control benchmark unless an exact compatible Python target population is independently governed.",
    },
    {
        "id": "quixbugs-python",
        "title": "QuixBugs Python Defect Corpus",
        "source_url": "https://github.com/jkoppel/QuixBugs",
        "population": "small algorithmic Python programs with known defects and corresponding corrected versions under a pinned repository revision",
        "measures": [
            "defect_detection_rate",
            "fault_localization_accuracy",
            "generated_test_reveal_rate",
            "repair_validation_rate",
            "regression_rate",
        ],
        "use": "Provide a compact reproducible external defect corpus for generated-test, localization, and repair-validation checks.",
        "limitation": "The algorithms are small and not representative of framework-heavy or distributed Python systems; corrected versions are useful oracles but require independently reviewed task and test mappings.",
    },
    {
        "id": "bigcodebench",
        "title": "BigCodeBench",
        "source_url": "https://github.com/bigcode-project/bigcodebench",
        "population": "practical programming tasks using diverse libraries and instructions, evaluated against pinned tasks, dependencies, harnesses, and tests",
        "measures": [
            "complete_pass_at_1",
            "instruct_pass_at_1",
            "library_stratum_performance",
            "test_generation_pass_rate",
            "sandbox_failure_rate",
        ],
        "use": "Stress LLM test and code generation on library-rich tasks closer to real application composition than isolated algorithm exercises.",
        "limitation": "Task success is indirect evidence for SFMEA discovery, safety, and test adequacy. Preserve release provenance, execute in isolation, and report library and contamination strata.",
    },
    {
        "id": "pysfmea-dual-mutation-engine-qualification",
        "title": "Dual Mutation-Engine Qualification Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/dual_mutation_corpus",
        "population": "content-addressed Python subjects and reviewed mutants executed with two independently implemented mutation engines using common identities and explicit equivalent-mutant adjudication",
        "measures": [
            "engine_mutant_mapping_rate",
            "kill_agreement_rate",
            "discordant_mutants",
            "equivalent_mutant_rate",
            "mutation_score_by_engine",
            "adjudication_completion_rate",
        ],
        "use": "Detect mutation-engine blind spots, mapping errors, and overclaiming by requiring per-mutant differential evidence and reviewed disagreement dispositions.",
        "limitation": "Agreement between engines is not ground truth. Qualification requires exact engine versions, common mutant semantics, isolated execution, independent equivalence review, and real-defect correlation.",
    },
    {
        "id": "pysfmea-scale-resource-exhaustion",
        "title": "Scale and Resource-Exhaustion Qualification Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/scale_resource_corpus",
        "population": "deterministically generated Python repositories and graph shapes spanning file, symbol, edge, recursion, import, encoding, and pathological-input strata under explicit CPU, memory, wall-time, and output limits",
        "measures": [
            "completion_rate_by_scale",
            "runtime_scaling_exponent",
            "peak_memory_scaling",
            "timeout_rate",
            "resource_limit_conformance",
            "semantic_equivalence_rate",
        ],
        "use": "Characterize bounded behavior, graceful degradation, denial-of-service resistance, output completeness, and semantic stability as repository size and graph density grow.",
        "limitation": "Synthetic scale shapes do not establish performance on every real repository. Qualification requires representative external repositories, controlled hardware, repeated trials, retained traces, and predeclared budgets.",
    },
    {
        "id": "cyberseceval-4",
        "title": "CyberSecEval 4",
        "source_url": "https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
        "population": "pinned CyberSecEval 4 cybersecurity suites for insecure code, prompt injection, code-interpreter misuse, offensive autonomy, defensive reasoning, and autonomous patching",
        "measures": [
            "insecure_code_rate",
            "prompt_injection_success_rate",
            "interpreter_abuse_rate",
            "autonomous_operation_success_rate",
            "defensive_reasoning_accuracy",
            "autopatch_success_rate",
            "false_refusal_rate",
        ],
        "use": "Evaluate whether an LLM used for SFMEA discovery and automated test generation can be manipulated into insecure code, unsafe tool use, unauthorized action, or misleading security conclusions.",
        "limitation": "CyberSecEval evaluates model and agent cybersecurity rather than SFMEA correctness. Some suites contain dual-use content, require controlled access, use model judges, or target native-code patching; pin the exact subset, preserve judge and sampling configuration, and report applicability separately.",
    },
    {
        "id": "crosscodeeval-python",
        "title": "CrossCodeEval Python",
        "source_url": "https://github.com/amazon-science/cceval",
        "population": "the pinned Python stratum of CrossCodeEval with cross-file code context, retrieval candidates, task identities, and evaluation harness",
        "measures": [
            "exact_match",
            "edit_similarity",
            "identifier_match",
            "retrieval_recall",
            "dependency_context_precision",
            "execution_success_rate",
        ],
        "use": "Measure whether repository-context selection and generation preserve cross-file dependencies needed to design tests for components, interfaces, and failure paths.",
        "limitation": "Cross-file completion is indirect evidence for test adequacy or failure-mode discovery. Qualification requires a pinned lawful Python split, exact retrieval policy, contamination review, executable follow-up where feasible, and an SFMEA-specific external population.",
    },
    {
        "id": "crosscodelongeval-python",
        "title": "CrossCodeLongEval Python",
        "source_url": "https://github.com/amazon-science/Repoformer/tree/main/crosscodelongeval",
        "population": "the pinned Python stratum of CrossCodeLongEval with long-range repository dependencies and controlled retrieval and generation configurations",
        "measures": [
            "exact_match",
            "edit_similarity",
            "identifier_match",
            "long_range_dependency_recall",
            "retrieval_precision",
            "context_efficiency",
        ],
        "use": "Stress long-range repository understanding and retrieval used when an SFMEA effect chain or generated test spans packages, adapters, configuration, and distant call sites.",
        "limitation": "Completion metrics do not prove semantic correctness, execution safety, or failure-mode coverage. Preserve exact tasks, retrieval corpus, context budget, model configuration, and downstream execution or review evidence.",
    },
    {
        "id": "agentdojo",
        "title": "AgentDojo",
        "source_url": "https://github.com/ethz-spylab/agentdojo",
        "population": "pinned AgentDojo task suites, user tasks, injection tasks, attacks, defenses, tool environments, model configuration, and per-trajectory utility and security results",
        "measures": [
            "benign_utility_rate",
            "utility_under_attack_rate",
            "security_under_attack_rate",
            "attack_success_rate",
            "defense_utility_delta",
            "tool_policy_violation_rate",
            "trajectory_completion_rate",
        ],
        "use": "Dynamically evaluate indirect prompt injection, tool misuse, defense effectiveness, and utility-security tradeoffs for LLM-assisted repository discovery and test generation.",
        "limitation": "AgentDojo evaluates agent behavior in modeled tool environments rather than SFMEA accuracy. Pin the benchmark version, suite, attacks, defenses, model, prompts, sampling, tool-output format, and task logs; preserve utility and security as distinct outcomes.",
    },
    {
        "id": "swe-polybench-verified-python",
        "title": "SWE-PolyBench Verified Python",
        "source_url": "https://github.com/amazon-science/SWE-PolyBench",
        "population": "the 113-task Python stratum of the pinned SWE-PolyBench Verified split with curated annotations, immutable repository revisions, container images, predictions, instance test results, and run logs",
        "measures": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "file_retrieval_precision",
            "file_retrieval_recall",
            "node_retrieval_recall",
            "patch_application_rate",
            "harness_error_rate",
        ],
        "use": "Measure cross-project repository-level generalization and whether generated tests or repairs correctly resolve Python issues without regressions.",
        "limitation": "Repository repair is indirect evidence for SFMEA completeness. Qualification requires the exact Verified Python split and annotations, frozen instance images, pass@1 policy, contamination controls, full per-instance test evidence, and separate harness-failure accounting.",
    },
    {
        "id": "idoft-python",
        "title": "International Dataset of Flaky Tests — Python",
        "source_url": "https://github.com/TestingResearchIllinois/idoft",
        "population": "the pinned Python records in the International Dataset of Flaky Tests joined to immutable detected or fixed revisions, fully qualified test identities, order-dependence labels, and reproducibility observations",
        "measures": [
            "flaky_detection_precision",
            "flaky_detection_recall",
            "order_dependency_accuracy",
            "reproduction_rate",
            "fixed_revision_validation_rate",
            "unavailable_revision_rate",
            "infrastructure_failure_rate",
        ],
        "use": "Provide an independently maintained real-world control population for Python flakiness, order dependence, timing, concurrency, and nondeterminism analysis.",
        "limitation": "Dataset records are not guaranteed reproducible under current dependencies or platforms and do not provide exhaustive negatives. Pin the CSV and project revisions, independently confirm licenses, pre-register eligibility, repeat under isolated schedules, and retain unavailable and non-reproduced cases.",
    },
    {
        "id": "pysfmea-nondeterminism-concurrency",
        "title": "Python Nondeterminism, Concurrency, and Flakiness Corpus",
        "source_url": "https://github.com/willtran87/project-py-sfmea/tree/main/benchmarks/nondeterminism_concurrency_corpus",
        "population": "content-addressed Python scenarios for random, time, scheduling, thread, task, process, filesystem, network, retry, eventual-consistency, and order-dependent test behavior",
        "measures": [
            "flaky_detection_precision",
            "flaky_detection_recall",
            "reproduction_rate",
            "schedule_stratum_coverage",
            "race_detection_rate",
            "order_dependency_detection_rate",
            "stabilization_validation_rate",
            "false_stability_rate",
        ],
        "use": "Validate discovery, test generation, repetition policy, schedule perturbation, timing analysis, and stabilization claims for nondeterministic Python behavior.",
        "limitation": "The bundled scenarios are deterministic governance fixtures, not representative external evidence. Qualification requires independently authored and labelled projects, repeated isolated executions, controlled perturbation, retained seeds and schedules, and explicit statistical decision rules.",
    },
    {
        "id": "swe-bench-live",
        "title": "SWE-bench Live",
        "source_url": "https://github.com/microsoft/SWE-bench-Live",
        "population": "a revision-pinned, time-bounded Python stratum of continuously refreshed real repository issues, instance images, predictions, and per-instance evaluation evidence",
        "measures": [
            "resolved",
            "fail_to_pass",
            "pass_to_pass",
            "patch_application_rate",
            "harness_error_rate",
            "incomplete_rate",
            "contamination_window_days",
            "repository_and_month_stratum_coverage",
        ],
        "use": "Provide fresh, contamination-resistant external evidence for repository understanding, test generation, and repair while retaining explicit temporal and Python applicability strata.",
        "limitation": "A live benchmark changes over time and is not automatically representative of safety-critical Python. Pin exact dataset bytes, creation-month bounds, repository revisions, images, evaluator revision, platform, predictions, exclusions, and item-quality audits; report errors and incomplete instances outside the resolved denominator.",
    },
    {
        "id": "terminal-bench-2",
        "title": "Terminal-Bench 2.0",
        "source_url": "https://github.com/harbor-framework/terminal-bench-2",
        "population": "a revision-pinned set of realistic, containerized terminal tasks with exact task manifests, images, agent trajectories, verifier outcomes, rewards, timeouts, resource limits, and per-task validation evidence",
        "measures": [
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
        "use": "Evaluate whether an LLM test agent can inspect, modify, and execute repository workflows in a controlled terminal environment while retaining complete tool and verifier evidence.",
        "limitation": "Terminal work is indirect evidence for SFMEA accuracy and the Harbor result contract may evolve. Pin exact task, image, Harbor, agent, model, policy, verifier, and platform revisions; audit every item; retain failures, timeouts, unsafe actions, and infrastructure errors outside the success denominator. PySFMEA supports the single-step Harbor TrialResult binary-reward subset; source, runner, and scorer qualification remain separate.",
    },
)


def benchmark_suite_catalog() -> dict[str, Any]:
    return seal(
        {
            "format": BENCHMARK_CATALOG_FORMAT,
            "version": "1.10.0",
            "suites": copy.deepcopy(list(BENCHMARK_SUITES)),
            "notice": "Registry entries are evaluation targets with suite-aware normalization policies, not bundled datasets, completed executions, or endorsements. Pin an exact lawful snapshot and preserve licenses, labels, provenance, exclusions, and independent review.",
        }
    )


def benchmark_execution_template(*, suite_id: str, authority: str) -> dict[str, Any]:
    if suite_id not in {item["id"] for item in BENCHMARK_SUITES}:
        raise ValueError("unknown governed benchmark suite")
    return seal(
        {
            "format": BENCHMARK_EXECUTION_FORMAT,
            "generated_at": utc_now(),
            "suite": {
                "id": suite_id,
                "source_url": next(
                    item["source_url"]
                    for item in BENCHMARK_SUITES
                    if item["id"] == suite_id
                ),
                "revision": "unassigned",
                "snapshot_sha256": "0" * 64,
                "license_evidence_ref": "unassigned",
            },
            "authority": {
                "protocol_owner": bounded_text(authority, "benchmark authority"),
                "execution_operator": "unassigned",
                "label_authority": "unassigned",
                "approval_authority": "unassigned",
                "independence_basis": "unassigned",
            },
            "adapter": {"manifest_sha256": "0" * 64, "evidence_ref": "unassigned"},
            "execution": {
                "runner": "oci",
                "image": "unassigned@sha256:" + "0" * 64,
                "command": [],
                "network": "none",
                "source_mount": "read_only",
                "started_at": "unassigned",
                "completed_at": "unassigned",
                "timeout_seconds": 0,
                "cpu_limit": 0.0,
                "memory_mb": 0,
                "exit_code": None,
            },
            "outcome": {
                "status": "not_run",
                "cases_total": 0,
                "cases_completed": 0,
                "metrics": {},
                "failures": [],
                "excluded_cases": [],
            },
            "evidence_refs": [],
            "limitations": [
                "No benchmark claim is supported until an independently governed execution is complete."
            ],
            "claim_boundary": "The receipt records an exact benchmark snapshot, isolated execution configuration, results, and authorities. It does not prove label correctness, population representativeness, tool qualification, or certification.",
        }
    )


def _execution_semantics(value: dict[str, Any]) -> tuple[bool, bool]:
    try:
        suite = value["suite"]
        authority = value["authority"]
        execution = value["execution"]
        outcome = value["outcome"]
        structure = bool(
            set(value)
            == {
                "format",
                "generated_at",
                "suite",
                "authority",
                "adapter",
                "execution",
                "outcome",
                "evidence_refs",
                "limitations",
                "claim_boundary",
                "content_sha256",
            }
            and set(suite)
            == {
                "id",
                "source_url",
                "revision",
                "snapshot_sha256",
                "license_evidence_ref",
            }
            and set(authority)
            == {
                "protocol_owner",
                "execution_operator",
                "label_authority",
                "approval_authority",
                "independence_basis",
            }
            and set(value["adapter"]) == {"manifest_sha256", "evidence_ref"}
            and set(execution)
            == {
                "runner",
                "image",
                "command",
                "network",
                "source_mount",
                "started_at",
                "completed_at",
                "timeout_seconds",
                "cpu_limit",
                "memory_mb",
                "exit_code",
            }
            and set(outcome)
            == {
                "status",
                "cases_total",
                "cases_completed",
                "metrics",
                "failures",
                "excluded_cases",
            }
            and suite["id"] in {item["id"] for item in BENCHMARK_SUITES}
            and isinstance(execution["command"], list)
            and len(execution["command"]) <= 100
            and all(
                isinstance(item, str) and 0 < len(item) <= 20_000
                for item in execution["command"]
            )
            and execution["network"] == "none"
            and execution["source_mount"] == "read_only"
            and outcome["status"] in {"not_run", "completed", "failed", "aborted"}
            and isinstance(outcome["metrics"], dict)
            and all(
                isinstance(metric, (int, float))
                and not isinstance(metric, bool)
                and math.isfinite(float(metric))
                for metric in outcome["metrics"].values()
            )
            and isinstance(outcome["failures"], list)
            and isinstance(outcome["excluded_cases"], list)
            and all(
                isinstance(outcome[name], int)
                and not isinstance(outcome[name], bool)
                and outcome[name] >= 0
                for name in ("cases_total", "cases_completed")
            )
            and outcome["cases_completed"] <= outcome["cases_total"]
        )
        snapshot = suite["snapshot_sha256"]
        image = execution["image"]
        roles = [
            authority[name]
            for name in (
                "protocol_owner",
                "execution_operator",
                "label_authority",
                "approval_authority",
            )
        ]
        completed = bool(
            outcome["status"] == "completed"
            and re.fullmatch(r"[0-9a-f]{64}", snapshot or "")
            and snapshot != "0" * 64
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image or "")
            and not image.endswith("0" * 64)
            and execution["command"]
            and execution["exit_code"] == 0
            and isinstance(outcome["cases_total"], int)
            and outcome["cases_total"] > 0
            and outcome["cases_completed"] == outcome["cases_total"]
            and outcome["metrics"]
            and len(set(roles)) == len(roles)
            and authority["independence_basis"] != "unassigned"
            and suite["revision"] != "unassigned"
            and suite["license_evidence_ref"] != "unassigned"
            and re.fullmatch(r"[0-9a-f]{64}", value["adapter"]["manifest_sha256"] or "")
            and value["adapter"]["manifest_sha256"] != "0" * 64
            and value["adapter"]["evidence_ref"] != "unassigned"
            and bool(
                unique_text_list(value["evidence_refs"], "benchmark evidence refs")
            )
        )
        return structure, completed
    except (KeyError, TypeError, ValueError):
        return False, False


def seal_benchmark_execution_source(
    source: str | Path, destination: str | Path
) -> Path:
    value = load_json(source, label="benchmark execution")
    value.pop("content_sha256", None)
    value = seal(value)
    structure, _ = _execution_semantics(value)
    if not structure:
        raise ValueError("benchmark execution source fields are invalid")
    return publish_json(value, destination)


def verify_benchmark_execution(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="benchmark execution", format_value=BENCHMARK_EXECUTION_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure, eligible = _execution_semantics(checked)
    if not structure:
        errors.append("benchmark execution fields or isolation policy are invalid")
    if structure and not eligible:
        errors.append("benchmark execution is not complete and independently governed")
    valid = integrity and structure
    return seal(
        {
            "format": BENCHMARK_EXECUTION_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_benchmark_assessment": bool(valid and eligible),
            "checks": {
                "content_integrity": integrity,
                "closed_structure_and_isolation": structure,
                "execution_and_governance_complete": eligible,
            },
            "errors": errors,
            "notice": "Eligibility means the evidence contract is complete; statistical validity and external label correctness require separate assessment.",
        }
    )


def verify_benchmark_execution_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_benchmark_execution(
            load_json(source, label="benchmark execution")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_EXECUTION_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_benchmark_assessment": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure_and_isolation": False,
                    "execution_and_governance_complete": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark execution verification failed closed.",
            }
        )


def export_benchmark_catalog(destination: str | Path) -> Path:
    return publish_json(benchmark_suite_catalog(), destination)


def export_benchmark_execution(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_benchmark_execution(value)["valid"]:
        raise ValueError("benchmark execution source is internally invalid")
    return publish_json(value, destination)

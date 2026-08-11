"""Integrated product-enhancement and assurance-activation workbench."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from math import ceil, log2
from pathlib import Path
from typing import Any, Literal, cast

from .diagnostics import analysis_diagnostics
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id

ENHANCEMENT_WORKBENCH_FORMAT = "pysfmea-enhancement-workbench-7"
ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT = (
    "pysfmea-enhancement-workbench-verification-1"
)
MAX_WORKBENCH_BYTES = 50_000_000
MAX_WORKBENCH_JSON_DEPTH = 100
MAX_WORKBENCH_JSON_NODES = 3_000_000
MAX_CLUSTER_MEMBERS = 250
MAX_CLUSTERS = 1_000
MAX_PORTFOLIO_GROUPS = 500
MAX_SURFACE_RECORDS = 2_000
MAX_DISPOSITION_RECORDS = 1_000
MAX_SCOPE_PREVIEW_VISITED = 100_000
MAX_SCOPE_PREVIEW_MATCHES = 10_000
MAX_EVIDENCE_PREFLIGHT_FILES = 20_000
SCOPE_PREVIEW_PRUNED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
    }
)

Authority = Literal["product", "project_evidence", "human_authority"]
ProductMaturity = Literal["planned", "partial", "implemented", "validated"]


@dataclass(frozen=True)
class EnhancementSpec:
    id: str
    domain: str
    title: str
    authority: Authority
    product_resolution: str
    projection: str


@dataclass(frozen=True)
class HardeningSpec:
    id: str
    priority: str
    domain: str
    title: str
    authority: Authority
    product_resolution: str
    acceptance_criterion: str
    projection: str


def _spec(
    identifier: str,
    domain: str,
    title: str,
    authority: Authority,
    resolution: str,
    projection: str,
) -> EnhancementSpec:
    return EnhancementSpec(identifier, domain, title, authority, resolution, projection)


ENHANCEMENT_SPECS = (
    _spec(
        "P0-01",
        "evidence",
        "One-command evidence acquisition",
        "project_evidence",
        "Generate bounded argv recipes for test, coverage, trace, mutation, and dependency evidence; execution remains opt-in and sandbox-governed.",
        "evidence_acquisition",
    ),
    _spec(
        "P0-02",
        "evidence",
        "Evidence readiness wizard",
        "product",
        "Diagnose missing evidence and emit ordered repository-specific acquisition steps.",
        "evidence_acquisition",
    ),
    _spec(
        "P0-03",
        "review",
        "Root-cause review clustering",
        "product",
        "Cluster findings by rule, failure class, cause, action, hazard, and source area with stable membership.",
        "review_clusters",
    ),
    _spec(
        "P0-04",
        "review",
        "Representative family review",
        "human_authority",
        "Select stable representatives and preserve every member and exception for governed review.",
        "review_clusters",
    ),
    _spec(
        "P0-05",
        "review",
        "Governed rule calibration",
        "human_authority",
        "Expose observed disposition statistics without silently changing rules.",
        "diagnostics.workload.review_calibration",
    ),
    _spec(
        "P0-06",
        "architecture",
        "Bulk architecture mapping review",
        "human_authority",
        "Project bounded mapping proposals as a complete review queue with explicit non-approval authority.",
        "architecture_mapping_queue",
    ),
    _spec(
        "P0-07",
        "interfaces",
        "Interface disposition workflow",
        "human_authority",
        "Create explicit client and server disposition queues; unmatched records remain leads.",
        "interface_disposition_queue",
    ),
    _spec(
        "P0-08",
        "reporting",
        "Large-report optimization",
        "product",
        "Use bounded projections, complete JSON sources, browser budgets, and workload summaries.",
        "budgets",
    ),
    _spec(
        "P0-09",
        "performance",
        "Incremental downstream analysis",
        "product",
        "Expose exact source/cache provenance and phase hotspots; differential equivalence remains a release gate.",
        "performance_plan",
    ),
    _spec(
        "P0-10",
        "evidence",
        "Prioritized evidence portfolio",
        "product",
        "Greedily group obligations by method, rule, hazard, and source area to maximize high-priority coverage.",
        "evidence_portfolio",
    ),
    _spec(
        "P1-01",
        "discovery",
        "Declarative wiring manifest",
        "human_authority",
        "Represent unresolved dynamic wiring as reviewable mapping input instead of executing repository code.",
        "surface_models.dynamic_wiring",
    ),
    _spec(
        "P1-02",
        "interfaces",
        "Expanded web-client analysis",
        "product",
        "Use boundary facts and unresolved client dispositions for wrappers, bases, templates, sockets, and generated-client leads.",
        "interface_disposition_queue",
    ),
    _spec(
        "P1-03",
        "interfaces",
        "OpenAPI reconciliation",
        "project_evidence",
        "Correlate discovered routes and client candidates with bounded local contract inventory.",
        "surface_models.contracts",
    ),
    _spec(
        "P1-04",
        "discovery",
        "Event-driven topology",
        "product",
        "Project task, queue, scheduler, webhook, WebSocket, SSE, and background-worker candidates from semantic facts.",
        "surface_models.events",
    ),
    _spec(
        "P1-05",
        "discovery",
        "Data lineage",
        "product",
        "Project bounded call-linked data-boundary candidates without claiming path-sensitive value flow.",
        "surface_models.data",
    ),
    _spec(
        "P1-06",
        "security",
        "Security-sensitive data flow",
        "product",
        "Identify conservative security-boundary candidates and preserve evidence and uncertainty.",
        "surface_models.security",
    ),
    _spec(
        "P1-07",
        "discovery",
        "Path-sensitive control flow",
        "project_evidence",
        "Expose branches, ordered calls, exceptions, and runtime-corroboration needs; do not overstate lexical context as path proof.",
        "surface_models.control_flow",
    ),
    _spec(
        "P1-08",
        "resilience",
        "Async lifecycle analysis",
        "product",
        "Project concurrency, task, cancellation, lock, queue, and cleanup candidates.",
        "surface_models.concurrency",
    ),
    _spec(
        "P1-09",
        "resilience",
        "Resilience composition analysis",
        "product",
        "Correlate retry, timeout, breaker, fallback, and side-effect signals into review candidates.",
        "surface_models.resilience",
    ),
    _spec(
        "P1-10",
        "security",
        "Authentication and middleware mapping",
        "product",
        "Project route, decorator, middleware, authorization, and rate-limit candidates.",
        "surface_models.security",
    ),
    _spec(
        "P1-11",
        "data",
        "Persistence semantics",
        "product",
        "Project persistence, transaction, atomicity, idempotency, and consistency review candidates.",
        "surface_models.persistence",
    ),
    _spec(
        "P1-12",
        "deployment",
        "Deployment-boundary indexing",
        "product",
        "Classify deployment, proxy, container, infrastructure, and CI artifacts from the governed inventory.",
        "surface_models.deployment",
    ),
    _spec(
        "P1-13",
        "dependencies",
        "Dependency reachability",
        "project_evidence",
        "Bind declared dependencies to observed imports/calls where available and retain unresolved reachability.",
        "surface_models.dependencies",
    ),
    _spec(
        "P1-14",
        "evidence",
        "Framework-specific test synthesis",
        "human_authority",
        "Select existing deterministic scaffold and fault-plugin workflows by verification method.",
        "evidence_portfolio",
    ),
    _spec(
        "P1-15",
        "evidence",
        "Controlled failure campaigns",
        "project_evidence",
        "Generate sandbox-only exception, malformed-result, timing, concurrency, and recovery campaign recipes.",
        "evidence_acquisition",
    ),
    _spec(
        "P1-16",
        "runtime",
        "Automatic runtime instrumentation",
        "project_evidence",
        "Generate scoped runtime-trace acquisition and import recipes with declared instrumentation authority.",
        "evidence_acquisition",
    ),
    _spec(
        "P1-17",
        "runtime",
        "Temporal assertions",
        "project_evidence",
        "Prioritize timing obligations and required deadline, ordering, retry, breaker, cancellation, and recovery observations.",
        "evidence_portfolio",
    ),
    _spec(
        "P1-18",
        "evidence",
        "Evidence sufficiency scoring",
        "human_authority",
        "Retain revision binding, freshness, independence, conflicts, artifacts, and review state as separate gates.",
        "evidence_quality",
    ),
    _spec(
        "P1-19",
        "evidence",
        "Counter-evidence handling",
        "human_authority",
        "Preserve conflicting evidence as adjudication work; never erase the weaker claim automatically.",
        "evidence_quality",
    ),
    _spec(
        "P1-20",
        "traceability",
        "Test-to-finding many-to-many mapping",
        "product",
        "Project tests, obligations, findings, hazards, requirements, components, and methods in one portfolio.",
        "evidence_portfolio",
    ),
    _spec(
        "P1-21",
        "hazards",
        "SFTA authoring assistant",
        "human_authority",
        "Expose top-down and bottom-up reconciliation gaps without inventing gate logic or causal sufficiency.",
        "sfta_queue",
    ),
    _spec(
        "P2-01",
        "guidance",
        "Citation remediation assistant",
        "human_authority",
        "Prioritize contextual/supporting mappings and explain why direct applicability still needs review.",
        "guidance_queue",
    ),
    _spec(
        "P2-02",
        "guidance",
        "Guidance change management",
        "human_authority",
        "Use source revisions and governance digests to identify reapproval work.",
        "guidance_queue",
    ),
    _spec(
        "P2-03",
        "guidance",
        "Domain assurance packs",
        "human_authority",
        "Retain organizational pack extension points and explicit applicability profiles.",
        "capability_register",
    ),
    _spec(
        "P2-04",
        "guidance",
        "Applicability decision workspace",
        "human_authority",
        "Keep applicability, rationale, reviewer, revision, and affected mappings explicit.",
        "guidance_queue",
    ),
    _spec(
        "P2-05",
        "llm",
        "Private and local LLM support",
        "project_evidence",
        "Use provider-neutral bounded evidence packets and closed suggestion schemas; provider execution is explicit opt-in.",
        "capability_register",
    ),
    _spec(
        "P2-06",
        "llm",
        "LLM disagreement mode",
        "human_authority",
        "Represent competing suggestions as independent unapproved claims for reviewer adjudication.",
        "capability_register",
    ),
    _spec(
        "P2-07",
        "llm",
        "Claim-level confidence",
        "human_authority",
        "Require evidence and citation allowlists per suggestion field and retain abstentions.",
        "capability_register",
    ),
    _spec(
        "P2-08",
        "llm",
        "LLM regression cohorts",
        "project_evidence",
        "Use count-backed grounding, citation, unsupported-claim, and independent-review cohorts.",
        "capability_register",
    ),
    _spec(
        "P2-09",
        "lifecycle",
        "Change-focused review",
        "product",
        "Use stable findings, baselines, source state, revalidation, and evidence freshness for delta review.",
        "change_review",
    ),
    _spec(
        "P2-10",
        "review",
        "Reviewer assignment and queues",
        "human_authority",
        "Expose priority reservations, owners, target dates, and bounded representative queues.",
        "review_clusters",
    ),
    _spec(
        "P2-11",
        "governance",
        "Waiver lifecycle",
        "human_authority",
        "Treat accepted risk and not-applicable decisions as exact, reviewed, revalidation-sensitive records.",
        "change_review",
    ),
    _spec(
        "P2-12",
        "review",
        "Review analytics",
        "product",
        "Expose dispositions, throughput-ready counts, family reduction, and rule calibration.",
        "review_analytics",
    ),
    _spec(
        "P2-13",
        "reporting",
        "Accessibility qualification",
        "human_authority",
        "Publish deterministic responsive/browser checks while retaining accessibility and user evaluation as separate evidence.",
        "budgets",
    ),
    _spec(
        "P2-14",
        "reporting",
        "Role-oriented report projections",
        "human_authority",
        "Provide bounded machine data that downstream governed views can project without changing analysis state.",
        "capability_register",
    ),
    _spec(
        "P2-15",
        "reporting",
        "Interactive cascade explorer",
        "product",
        "Reuse evidence-labeled propagation diagrams, static/observed state, controls, timing, and confidence filters.",
        "capability_register",
    ),
    _spec(
        "P2-16",
        "traceability",
        "Evidence drill-down",
        "product",
        "Preserve stable IDs and source, test, execution, artifact, citation, and review bindings.",
        "evidence_portfolio",
    ),
    _spec(
        "P3-01",
        "ci",
        "Reusable CI workflows",
        "project_evidence",
        "Expose argv-only quality recipes compatible with repository CI and existing release gates.",
        "evidence_acquisition",
    ),
    _spec(
        "P3-02",
        "api",
        "Stable automation API",
        "product",
        "Publish a dependency-free Python function and versioned JSON artifact in addition to the CLI.",
        "capability_register",
    ),
    _spec(
        "P3-03",
        "plugins",
        "Plugin SDK",
        "human_authority",
        "Use typed capability descriptors, schemas, trust, lifecycle, isolation, and contribution accounting.",
        "capability_register",
    ),
    _spec(
        "P3-04",
        "qualification",
        "External benchmark corpus",
        "project_evidence",
        "Require independently produced, content-addressed validation cohorts for representative claims.",
        "qualification_plan",
    ),
    _spec(
        "P3-05",
        "qualification",
        "Parser differential testing",
        "project_evidence",
        "Record multi-runtime evaluation and equivalence evidence as external validation cohorts.",
        "qualification_plan",
    ),
    _spec(
        "P3-06",
        "performance",
        "Performance regression service",
        "project_evidence",
        "Use phase telemetry, cold/warm benchmark receipts, cache metrics, and explicit budgets.",
        "performance_plan",
    ),
    _spec(
        "P3-07",
        "security",
        "Adversarial repository corpus",
        "project_evidence",
        "Retain bounded-ingestion, link/race, encoding, archive, JSON, and report-injection cases in release evidence.",
        "qualification_plan",
    ),
    _spec(
        "P3-08",
        "qualification",
        "Reproducible qualification bundle",
        "human_authority",
        "Assemble requirements, tests, coverage, benchmarks, SBOM, security results, limitations, and signatures without self-qualification.",
        "qualification_plan",
    ),
    _spec(
        "P3-09",
        "qualification",
        "Independent validation import",
        "human_authority",
        "Credit only bound, independently reviewed, non-duplicate validation evidence through the assurance program.",
        "qualification_plan",
    ),
)


def _hardening(
    identifier: str,
    priority: str,
    domain: str,
    title: str,
    authority: Authority,
    resolution: str,
    acceptance: str,
    projection: str,
) -> HardeningSpec:
    return HardeningSpec(
        identifier,
        priority,
        domain,
        title,
        authority,
        resolution,
        acceptance,
        projection,
    )


# Append-only register derived from the 76-item real-repository hardening audit.  A
# product resolution may deliberately be an evidence or human-authority gate; those
# states prevent the scanner from converting a useful workflow into a false claim.
HARDENING_SPECS = (
    _hardening(
        "H01",
        "P0",
        "evidence",
        "Evidence acquisition orchestrator",
        "project_evidence",
        "Emit repository-specific, argv-only acquisition steps and route execution through the existing bounded sandbox and external-import contracts.",
        "Every executed step has an exact baseline binding, bounded receipt, and explicit authorization mode.",
        "evidence_acquisition",
    ),
    _hardening(
        "H02",
        "P0",
        "evidence",
        "Automatic test discovery and component attribution",
        "product",
        "Index configured test evidence and retain many-to-many test, component, finding, and obligation relationships.",
        "Attribution coverage and unresolved references are count-backed and visible.",
        "evidence_portfolio",
    ),
    _hardening(
        "H03",
        "P0",
        "evidence",
        "Coverage ingestion pipeline",
        "project_evidence",
        "Use the bounded coverage.py JSON importer with branch metadata, exact bytes, repository containment, and freshness checks.",
        "Current-baseline coverage is imported and reconciles with repository inventory totals.",
        "artifact_freshness",
    ),
    _hardening(
        "H04",
        "P0",
        "runtime",
        "Runtime trace instrumentation",
        "project_evidence",
        "Provide scoped simple/OTLP trace acquisition recipes and the existing bounded runtime import contract.",
        "Observed edges declare instrumentation scope, timing status, mapping method, and baseline identity.",
        "evidence_acquisition",
    ),
    _hardening(
        "H05",
        "P0",
        "integrity",
        "Exact artifact freshness",
        "product",
        "Bind workbench state, baseline, runtime imports, assurance executions, and run manifest in one freshness projection.",
        "No stale or ambiguous artifact is presented as current.",
        "artifact_freshness",
    ),
    _hardening(
        "H06",
        "P0",
        "evidence",
        "Evidence sufficiency dashboard",
        "human_authority",
        "Expose missing, stale, conflicting, reviewed, accepted, and artifact-backed evidence as separate gates.",
        "A named reviewer can explain every sufficiency decision without relying on an aggregate score alone.",
        "evidence_quality",
    ),
    _hardening(
        "H07",
        "P0",
        "verification",
        "Executable assurance campaign",
        "project_evidence",
        "Group obligations into prioritized portfolios and route selected work through scaffold, fault-plan, sandbox, and external-execution workflows.",
        "Each completed test retains stimulus, oracle, artifacts, result, baseline, and evidence review.",
        "evidence_portfolio",
    ),
    _hardening(
        "H08",
        "P0",
        "quality",
        "Rule calibration correctness",
        "product",
        "Represent empty review samples as unavailable rather than as 100 percent acceptance or rejection.",
        "Unreviewed rule rates are null and reviewed rates reconcile exactly with counts.",
        "precision_risks",
    ),
    _hardening(
        "H09",
        "P0",
        "quality",
        "High-volume rule precision review",
        "human_authority",
        "Rank high-volume rules with insufficient dispositions as explicit calibration risks without automatic threshold changes.",
        "Every high-volume rule has a representative reviewed sample or remains visibly uncalibrated.",
        "precision_risks",
    ),
    _hardening(
        "H10",
        "P0",
        "review",
        "Cluster validation",
        "project_evidence",
        "Preserve stable cluster keys, members, omitted counts, representatives, and disposition diversity for labelled-cohort evaluation.",
        "Cluster-coherence precision is measured on a representative independent sample.",
        "review_clusters",
    ),
    _hardening(
        "H11",
        "P0",
        "review",
        "Representative-review sampling",
        "human_authority",
        "Keep representatives as queue aids and require member sampling before any family-level process decision.",
        "Representative review never changes every member disposition implicitly.",
        "review_clusters",
    ),
    _hardening(
        "H12",
        "P0",
        "workflow",
        "Scan-to-review workflow",
        "product",
        "Connect doctor, scan, diagnostics, enhance, review, assurance work, evidence, validation, report, and package actions through explicit status gates.",
        "The next safe command and every simultaneous blocker are machine-readable.",
        "capability_register",
    ),
    _hardening(
        "H13",
        "P1",
        "semantics",
        "Interprocedural control-flow analysis",
        "project_evidence",
        "Retain ordered calls, branches, exceptions, nesting, resolved receivers, and bounded runtime-corroboration needs.",
        "Precision and recall are measured on labelled multi-file paths before path-completeness claims.",
        "surface_models.control_flow",
    ),
    _hardening(
        "H14",
        "P1",
        "semantics",
        "Path-sensitive failure propagation",
        "project_evidence",
        "Expose bounded static cascades, cycles, assumptions, omitted paths, and observed runtime edges without claiming feasibility proof.",
        "Every displayed cascade states its evidence class and completeness limit.",
        "sfta_queue",
    ),
    _hardening(
        "H15",
        "P1",
        "semantics",
        "Type and receiver resolution",
        "product",
        "Use annotations, assignments, imports, nested-call order, and adapter facts to resolve receivers while retaining unresolved calls.",
        "Call-resolution metrics include exact expected and observed counts.",
        "surface_models.control_flow",
    ),
    _hardening(
        "H16",
        "P1",
        "concurrency",
        "Async and concurrency model",
        "product",
        "Project tasks, awaits, cancellation, locks, semaphores, queues, executors, cleanup, and shared-state candidates.",
        "Concurrency candidates retain source evidence and do not imply a proven race.",
        "surface_models.concurrency",
    ),
    _hardening(
        "H17",
        "P1",
        "timing",
        "Temporal contract model",
        "project_evidence",
        "Carry deadline, timeout, retry, ordering, cancellation, recovery, and observation requirements into obligations and diagrams.",
        "Timing claims receive current measured evidence or remain explicitly unverified.",
        "evidence_portfolio",
    ),
    _hardening(
        "H18",
        "P1",
        "resilience",
        "Circuit-breaker semantics",
        "project_evidence",
        "Correlate breaker states, retry/timeout composition, fallback, containment, isolation, and recovery candidates.",
        "Breaker behavior is confirmed by state-transition and timing evidence before control credit.",
        "surface_models.resilience",
    ),
    _hardening(
        "H19",
        "P1",
        "persistence",
        "Transaction and persistence analysis",
        "product",
        "Project transaction, commit, rollback, atomicity, idempotency, consistency, migration, and partial-write candidates.",
        "Persistence findings identify the relevant operation and required verification method.",
        "surface_models.persistence",
    ),
    _hardening(
        "H20",
        "P1",
        "security",
        "Data-flow and trust-boundary analysis",
        "product",
        "Project bounded data, validation, serialization, secret, privilege, storage, logging, and outbound-boundary candidates.",
        "Every candidate retains source provenance and an explicit non-taint-proof limitation.",
        "surface_models.security",
    ),
    _hardening(
        "H21",
        "P1",
        "configuration",
        "Configuration-state analysis",
        "product",
        "Inventory configuration, environment, deployment, feature-flag, and test-override surfaces as governed inputs.",
        "Unresolved configuration regions and precedence assumptions remain visible.",
        "surface_models.deployment",
    ),
    _hardening(
        "H22",
        "P1",
        "dependencies",
        "Dependency reachability",
        "project_evidence",
        "Correlate declared packages with observed imports and call candidates while preserving optional and unresolved use.",
        "Reachability status is corroborated by build/runtime evidence before vulnerability prioritization credit.",
        "surface_models.dependencies",
    ),
    _hardening(
        "H23",
        "P1",
        "architecture",
        "Dynamic wiring manifest",
        "human_authority",
        "Accept reviewed declarative mappings for plugins, dependency injection, generated routes, tasks, and runtime hooks without importing repository code.",
        "Every manual mapping has provenance, rationale, revision, and reviewer.",
        "surface_models.dynamic_wiring",
    ),
    _hardening(
        "H24",
        "P1",
        "quality",
        "Confidence decomposition",
        "product",
        "Keep discovery, source, interface, mapping, evidence, citation, and review authority distinct instead of emitting one opaque confidence value.",
        "Consumers can identify which claim dimension is uncertain.",
        "precision_risks",
    ),
    _hardening(
        "H25",
        "P1",
        "architecture",
        "Evidence-weighted architecture mapping",
        "product",
        "Generate bounded same-file/directory proposals with supporting component IDs and explicit proximity-only confidence.",
        "Proposals cannot become mappings until reviewed; richer adapter evidence can be added without changing authority.",
        "architecture_mapping_queue",
    ),
    _hardening(
        "H26",
        "P1",
        "architecture",
        "Architecture map authoring",
        "human_authority",
        "Use governed configuration mappings and review queues to accept, reject, split, or annotate proposals.",
        "Accepted mappings name the reviewer and affected subsystem, interface, requirement, and hazard IDs.",
        "architecture_mapping_queue",
    ),
    _hardening(
        "H27",
        "P1",
        "interfaces",
        "Complete HTTP normalization",
        "product",
        "Normalize methods, prefixes, mounted routers, parameters, local/client bases, wrappers, Axios instances, WebSockets, and EventSource candidates.",
        "A labelled framework corpus measures route/client matching precision and recall.",
        "interface_disposition_queue",
    ),
    _hardening(
        "H28",
        "P1",
        "interfaces",
        "Route disposition categories",
        "human_authority",
        "Offer bounded intentional-backend, external/generated, deprecated/unreachable, missing-client, and needs-information states.",
        "Unmatched routes remain leads until a named reviewer records rationale.",
        "interface_disposition_queue",
    ),
    _hardening(
        "H29",
        "P1",
        "interfaces",
        "Client disposition categories",
        "human_authority",
        "Offer third-party, dynamic, environment-dependent, dead-code, contract-only, mismatch, and needs-information review outcomes.",
        "No unmatched client becomes a defect automatically.",
        "interface_disposition_queue",
    ),
    _hardening(
        "H30",
        "P1",
        "contracts",
        "Source-derived contract generation",
        "project_evidence",
        "Retain discovered route and data-model facts as provisional interface records when no maintained contract is supplied.",
        "Generated contracts are labelled provisional and compared with an authoritative artifact before contract credit.",
        "surface_models.contracts",
    ),
    _hardening(
        "H31",
        "P1",
        "contracts",
        "Contract drift analysis",
        "project_evidence",
        "Reconcile bounded OpenAPI, Swagger, JSON Schema, protobuf, server-route, client, and runtime interface facts.",
        "Every mismatch identifies both source artifacts and the exact incompatible field or operation.",
        "surface_models.contracts",
    ),
    _hardening(
        "H32",
        "P1",
        "interfaces",
        "Non-HTTP interfaces",
        "product",
        "Index WebSockets, SSE, event/task/queue/scheduler candidates, subprocesses, persistence, and file/deployment boundaries.",
        "Each interface class has typed source evidence and an adapter capability declaration.",
        "surface_models.events",
    ),
    _hardening(
        "H33",
        "P1",
        "traceability",
        "Sequence completeness scoring",
        "project_evidence",
        "Separate static, contract-backed, runtime-observed, timing-observed, failure-tested, and reviewed sequence evidence.",
        "Sequence status never implies a stronger evidence class than its bound artifacts.",
        "evidence_portfolio",
    ),
    _hardening(
        "H34",
        "P2",
        "guidance",
        "Clause-level applicability",
        "human_authority",
        "Preserve source, clause/section, revision, relationship type, rationale, and reviewer applicability records.",
        "Direct applicability is explicitly reviewed for the exact finding relationship.",
        "guidance_queue",
    ),
    _hardening(
        "H35",
        "P2",
        "guidance",
        "Citation strength levels",
        "product",
        "Distinguish direct, contextual, supporting, analogous, and organizational mapping relationships.",
        "Reports and machine outputs never equate citation presence with compliance.",
        "guidance_queue",
    ),
    _hardening(
        "H36",
        "P2",
        "guidance",
        "Unsupported-claim detection",
        "product",
        "Use closed evidence/citation allowlists and claim-count-backed LLM evaluation to reject invented references and expose unsupported claims.",
        "Unsupported claim counts reconcile with exact labelled corpus records.",
        "qualification_plan",
    ),
    _hardening(
        "H37",
        "P2",
        "guidance",
        "Guidance coverage map",
        "product",
        "Project direct, contextual, unresolved, stale, and missing guidance relationships with bounded remediation queues.",
        "Coverage totals reconcile to active findings and mappings.",
        "guidance_queue",
    ),
    _hardening(
        "H38",
        "P2",
        "guidance",
        "Guidance revision management",
        "human_authority",
        "Bind decisions to guidance revisions and governance digests so changed sources trigger reapproval work.",
        "Stale applicability decisions cannot satisfy a current gate.",
        "guidance_queue",
    ),
    _hardening(
        "H39",
        "P2",
        "guidance",
        "Assurance profiles",
        "human_authority",
        "Use explicit NASA, FAA, regulatory, general, and organization-defined guidance profiles with isolated applicability.",
        "Profile selection and tailoring are governed inputs, not inferred compliance.",
        "capability_register",
    ),
    _hardening(
        "H40",
        "P2",
        "review",
        "Traceable rationale templates",
        "human_authority",
        "Retain structured applicability, severity, cause, effect, control, action, verification, and residual-risk fields.",
        "Every accepted or rejected decision meets the validation contract and names its reviewer.",
        "review_clusters",
    ),
    _hardening(
        "H41",
        "P2",
        "evidence",
        "Counter-evidence adjudication",
        "human_authority",
        "Preserve contradictory evidence and route it to explicit sufficiency review instead of overwriting earlier records.",
        "Conflicts remain visible until a named adjudicator records rationale.",
        "evidence_quality",
    ),
    _hardening(
        "H42",
        "P2",
        "review",
        "Review cockpit",
        "human_authority",
        "Use the local review server for filters, keyboard-friendly records, health metrics, source links, decisions, and validation feedback.",
        "All mutations pass schema, revision, and validation checks before persistence.",
        "capability_register",
    ),
    _hardening(
        "H43",
        "P2",
        "review",
        "Finding and cluster comparison",
        "product",
        "Expose stable grouping keys, shared cause/action/hazard/source area, member identities, and exception counts.",
        "A reviewer can explain why records were grouped without hidden model state.",
        "review_clusters",
    ),
    _hardening(
        "H44",
        "P2",
        "lifecycle",
        "Scan-to-scan differential review",
        "product",
        "Use stable/content/context fingerprints to report new, changed, moved, impacted, removed, reopened, and revalidation-sensitive findings.",
        "Diff output is canonical, bounded, and baseline-bound.",
        "change_review",
    ),
    _hardening(
        "H45",
        "P2",
        "review",
        "Review progress forecasting",
        "product",
        "Expose queue size, family reduction, priority reservations, evidence gaps, and rule concentration as deterministic workload indicators.",
        "Forecast inputs and limitations are visible; no completion date is asserted without human planning data.",
        "review_analytics",
    ),
    _hardening(
        "H46",
        "P2",
        "quality",
        "Quality sampling",
        "project_evidence",
        "Generate representative queues and require independently labelled validation cohorts for disposition and clustering quality claims.",
        "Sampling method, corpus digest, producer, reviewer, and metrics are retained.",
        "qualification_plan",
    ),
    _hardening(
        "H47",
        "P2",
        "governance",
        "Waiver lifecycle",
        "human_authority",
        "Bind accepted-risk and not-applicable decisions to exact finding state, rationale, reviewer, approval, and revalidation triggers.",
        "Changed source, evidence, guidance, or risk context reopens the decision.",
        "change_review",
    ),
    _hardening(
        "H48",
        "P2",
        "reporting",
        "Role-oriented projections",
        "human_authority",
        "Publish bounded analysis, evidence, diagnostics, guidance, assurance, architecture, and review-view projections for downstream role views.",
        "Every role view reconciles with the same governed analysis state.",
        "capability_register",
    ),
    _hardening(
        "H49",
        "P2",
        "interchange",
        "Decision exports",
        "human_authority",
        "Export CSV/JSON/Markdown and accept changes only through governed review/import boundaries rather than treating spreadsheets as authority.",
        "Imported decisions retain identity, rationale, reviewer, and baseline checks.",
        "capability_register",
    ),
    _hardening(
        "H50",
        "P2",
        "visualization",
        "Interactive cascade explorer",
        "product",
        "Render evidence-labelled propagation, architecture, sequence, state, SFTA, control, timing, and confidence views in the self-contained report.",
        "Every graph has bounded data and stable links back to findings and source evidence.",
        "capability_register",
    ),
    _hardening(
        "H51",
        "P2",
        "visualization",
        "Architecture overlays",
        "product",
        "Project components, interfaces, hazards, findings, review state, and coverage into general diagram models.",
        "Overlay totals reconcile with the bounded source projection.",
        "capability_register",
    ),
    _hardening(
        "H52",
        "P2",
        "visualization",
        "Sequence overlays",
        "product",
        "Separate static, observed, failure, retry, timeout, breaker, and recovery evidence in sequence and state projections.",
        "Legend and evidence labels prevent observed and inferred paths from being confused.",
        "capability_register",
    ),
    _hardening(
        "H53",
        "P2",
        "reporting",
        "Report comparison",
        "product",
        "Use canonical analysis diff output and change-focused report projections for scan comparison.",
        "Changed records retain previous IDs, reasons, and revalidation state.",
        "change_review",
    ),
    _hardening(
        "H54",
        "P2",
        "reporting",
        "Large-report virtualization",
        "product",
        "Bound embedded review projections, paginate finding views, and preserve complete machine-readable exports outside abbreviated cards.",
        "Browser gates pass at configured record and payload budgets.",
        "budgets",
    ),
    _hardening(
        "H55",
        "P2",
        "reporting",
        "Search and query",
        "product",
        "Provide report search, filters, column controls, stable IDs, priority, disposition, change, source, hazard, and evidence facets.",
        "All active filters are visible and resettable; complete exports remain available.",
        "capability_register",
    ),
    _hardening(
        "H56",
        "P2",
        "explainability",
        "Finding explanation panels",
        "product",
        "Expose source fact, guideword/rule, cause/effect, confidence limits, evidence need, action, and citation relationships.",
        "A finding can be understood without relying on hidden LLM reasoning.",
        "capability_register",
    ),
    _hardening(
        "H57",
        "P2",
        "accessibility",
        "Accessible graph alternatives",
        "project_evidence",
        "Provide semantic tables, ordered lists, text summaries, focusable navigation, responsive checks, and downloadable diagram JSON.",
        "Independent accessibility and multi-browser evidence is attached before qualification credit.",
        "qualification_plan",
    ),
    _hardening(
        "H58",
        "P2",
        "privacy",
        "Redaction profiles",
        "product",
        "Use portable package redaction, bounded LLM evidence-packet redaction, safe HTML encoding, and explicit external-artifact handling.",
        "Redacted outputs contain no configured repository root or detected secret-shaped value.",
        "guardrails",
    ),
    _hardening(
        "H59",
        "P3",
        "adapters",
        "Framework adapter matrix",
        "project_evidence",
        "Publish typed adapter capabilities and contribution accounting for Python, web boundaries, contracts, dependencies, runtime, diagrams, guidance, and planners.",
        "Each claimed framework capability has labelled precision/recall and compatibility evidence.",
        "qualification_plan",
    ),
    _hardening(
        "H60",
        "P3",
        "plugins",
        "Plugin SDK stabilization",
        "human_authority",
        "Use versioned descriptors, schemas, health, trust, isolation, deterministic flags, run receipts, and contribution IDs.",
        "Compatibility and deprecation policy is approved before declaring a stable external SDK.",
        "capability_register",
    ),
    _hardening(
        "H61",
        "P3",
        "interchange",
        "SARIF export",
        "product",
        "Export stable candidate identities, locations, fingerprints, citations, baseline binding, and explicit non-defect semantics in SARIF 2.1.0.",
        "SARIF regenerates exactly from the packaged analysis.",
        "capability_register",
    ),
    _hardening(
        "H62",
        "P3",
        "supply_chain",
        "SBOM and vulnerability correlation",
        "project_evidence",
        "Export CycloneDX declared components and retain dependency-audit acquisition as corroborating evidence.",
        "Reachability and vulnerability prioritization remain separate until current audit evidence is imported.",
        "surface_models.dependencies",
    ),
    _hardening(
        "H63",
        "P3",
        "integration",
        "ALM integrations",
        "human_authority",
        "Expose stable JSON/SARIF/CSV queues and typed automation APIs for external issue systems without equating issue closure with assurance closure.",
        "External synchronization preserves finding identity, baseline, and authority boundaries.",
        "capability_register",
    ),
    _hardening(
        "H64",
        "P3",
        "api",
        "Service and API mode",
        "human_authority",
        "Provide a local review HTTP service and dependency-free Python/CLI automation interfaces; deployment remains an organizational decision.",
        "Any network deployment adds authentication, authorization, audit, TLS, and threat-model evidence.",
        "capability_register",
    ),
    _hardening(
        "H65",
        "P3",
        "configuration",
        "Configuration doctor",
        "product",
        "Check repository scope, configuration, analysis freshness, artifacts, evidence locations, and next workflow action before handoff.",
        "Doctor/status output is machine-readable and nonzero strict gates are available.",
        "capability_register",
    ),
    _hardening(
        "H66",
        "P3",
        "configuration",
        "Baseline templates",
        "product",
        "Ship governed starter configuration and explicit discovery-only authorization with documented assurance limitations.",
        "A new repository can reach a reproducible first scan without hidden defaults.",
        "capability_register",
    ),
    _hardening(
        "H67",
        "P3",
        "qualification",
        "Independent validation corpus",
        "project_evidence",
        "Import content-addressed, independently reviewed representative validation cohorts through the assurance program.",
        "Claims meet configured repository, case, independence, precision, and recall thresholds.",
        "qualification_plan",
    ),
    _hardening(
        "H68",
        "P3",
        "qualification",
        "Per-rule precision and recall",
        "project_evidence",
        "Retain exact expected/actual failure-mode and call-resolution counts, corpus bytes, and verifier provenance.",
        "Metrics reconcile at rule, framework, corpus, macro, and micro levels before release claims.",
        "qualification_plan",
    ),
    _hardening(
        "H69",
        "P3",
        "qualification",
        "Differential parser testing",
        "project_evidence",
        "Use multi-runtime CI and converted validation cohorts to compare parser and schema behavior.",
        "Supported runtimes produce semantically equivalent governed outputs or documented differences.",
        "qualification_plan",
    ),
    _hardening(
        "H70",
        "P3",
        "security",
        "Adversarial repository suite",
        "project_evidence",
        "Exercise bounded ingestion, symlinks, identity races, encoding, archives, JSON depth, report injection, and hostile provider responses.",
        "All adversarial cases fail closed with sanitized, schema-valid receipts.",
        "qualification_plan",
    ),
    _hardening(
        "H71",
        "P3",
        "performance",
        "Performance budgets",
        "project_evidence",
        "Project cold, warm, incremental, phase, cache, report-load, and memory targets without treating telemetry as assurance evidence.",
        "Representative benchmark receipts meet approved budgets with semantic-equivalence checks.",
        "acceptance_targets",
    ),
    _hardening(
        "H72",
        "P3",
        "performance",
        "Incremental analysis graph",
        "product",
        "Reuse exact-byte parser facts and stable fingerprints while rebuilding fresh downstream analysis and canonical diffs.",
        "Cold, warm, and differential results are semantically equivalent for unchanged inputs.",
        "performance_plan",
    ),
    _hardening(
        "H73",
        "P3",
        "ci",
        "CI test sharding",
        "product",
        "Separate release jobs for unit/property tests, security, browser/PDF, package integrity, clean-wheel, and supported runtimes.",
        "Required checks retain full release coverage while reporting independent durations and failures.",
        "qualification_plan",
    ),
    _hardening(
        "H74",
        "P3",
        "security",
        "Cross-platform security tests",
        "project_evidence",
        "Run filesystem link/race and platform-boundary tests on operating systems that support each primitive.",
        "Skipped platform cases are covered by a required compatible-runner receipt.",
        "qualification_plan",
    ),
    _hardening(
        "H75",
        "P3",
        "accessibility",
        "Multi-browser qualification",
        "project_evidence",
        "Run responsive, console, integrity, navigation, and accessibility gates across approved browser engines.",
        "Chromium, Firefox, and WebKit receipts meet the approved browser matrix.",
        "qualification_plan",
    ),
    _hardening(
        "H76",
        "P3",
        "release",
        "Reproducible release bundle",
        "human_authority",
        "Assemble schemas, requirements, tests, coverage, benchmarks, SBOM, security, limitations, signatures, and independent evidence without self-qualification.",
        "A named independent authority approves the exact signed release evidence bundle.",
        "qualification_plan",
    ),
)


# Stable post-hardening audit identities.  The generic resolution engine below keeps
# future audit lists machine-verifiable instead of requiring a bespoke report format
# every time a real repository exposes another product opportunity.
POST_HARDENING_TITLES = (
    "Executable capability attestations",
    "Computed resolution states",
    "Separate freshness, completeness, and sufficiency",
    "Hardening-workbench verifier",
    "Exact repository digest requirement",
    "Evidence-state semantics",
    "Acceptance-target provenance",
    "Target configuration",
    "Claim-to-acceptance reconciliation",
    "Workbench scan comparison",
    "Reviewable configuration patch generator",
    "Scope-preview command",
    "Scope-suggestion validation",
    "Guided rescan workflow",
    "Evidence source autodetection",
    "Monorepo runner detection",
    "Evidence acquisition DAG",
    "Resumable evidence collection",
    "Evidence collection receipts",
    "Evidence-import preview",
    "Statistical calibration plans",
    "Stratified rule sampling",
    "Cluster-cohesion measurement",
    "Cluster split recommendations",
    "Reviewer disagreement tracking",
    "False-positive regression corpus",
    "False-negative discovery workflow",
    "High-volume rule specialization",
    "Rule-volume budgets",
    "Calibration trend analysis",
    "Evidence-weighted mapping proposals",
    "Proposal score decomposition",
    "Architecture mapping patch export",
    "Architecture coverage prioritization",
    "Source-derived provisional OpenAPI",
    "Contract reconciliation workspace",
    "Server-route disposition workflow",
    "Cross-stack rescan gate",
    "Interface precision corpus",
    "Non-HTTP contract inventory",
    "Portfolio-aware test selection",
    "Test scaffold validation",
    "Framework-aware scaffold generation",
    "Coverage merger",
    "JUnit-to-obligation attribution",
    "Mutation evidence integration",
    "Fault-campaign generation",
    "Runtime instrumentation packages",
    "Temporal-oracle library",
    "Evidence conflict UI",
    "Compressed embedded payload",
    "Report target",
    "Virtualized hardening register",
    "Virtualized finding explorer",
    "On-demand graph projection",
    "Query language",
    "Saved views",
    "Role dashboards",
    "Review-session summaries",
    "Report comparison workspace",
    "Accessible graph descriptions",
    "Multi-browser evidence",
    "Direct-citation closure queue",
    "Applicability evidence packets",
    "Citation reuse warnings",
    "Guidance conflict detection",
    "Source revision monitoring",
    "Unsupported rationale linting",
    "Organizational tailoring workspace",
    "Phase-level optimization",
    "Parallel read-only indexing",
    "Incremental derived models",
    "Cold, warm, and incremental benchmark matrix",
    "Memory budgets",
    "Report performance benchmark",
    "Representative multi-repository corpus",
    "Per-framework precision and recall",
    "Independent cluster validation",
    "Cross-platform filesystem evidence",
    "Migration and compatibility testing",
    "Signed capability evidence",
    "Threat-model review",
)


# Stable identities for the 102 recommendations produced by the format-3 real-run
# audit.  Format 4 does not claim that evidence or approval exists: each item is
# bound to an operational projection and the authority that can actually close it.
NEXT_GENERATION_TITLES = (
    "Guided evidence onboarding",
    "Evidence-scope preview scanner",
    "Calibration campaign executor",
    "Rule-level precision dashboard",
    "Priority-starvation-proof review scheduler",
    "Semantic finding consolidation",
    "Module-initialization specialization",
    "Bulk architecture-mapping review",
    "Cross-stack readiness workflow",
    "Server-route disposition workflow",
    "Guidance specificity expansion",
    "Cold-scan performance ratchet",
    "Report payload reduction",
    "Configurable health gate",
    "Finding confidence decomposition",
    "Rule applicability predicates",
    "Reviewed suppression proposals",
    "Project-specific rule overlays",
    "Boilerplate finding consolidation",
    "Reviewer agreement metrics",
    "Calibration drift detection",
    "Uncertainty intervals",
    "Segmented rule precision",
    "Finding explanation panels",
    "Priority rationale decomposition",
    "Test framework discovery",
    "Framework-aware test generation",
    "Failure-path test variants",
    "Test-to-assurance traceability",
    "Coverage delta analysis",
    "OpenTelemetry instrumentation recipes",
    "Runtime trace completeness",
    "Contract-test planning",
    "Failure-mode mutation suggestions",
    "Evidence-quality scoring",
    "Transitive evidence invalidation",
    "Obligation-to-test coverage matrix",
    "Architecture inference enrichment",
    "Deployment and reverse-proxy profiles",
    "Expanded web-client detection",
    "Event-bus interface modeling",
    "Database boundary modeling",
    "Schema and media compatibility",
    "Path-feasibility confidence",
    "Risk-ranked propagation paths",
    "Common-cause region detection",
    "Candidate SFTA decomposition",
    "Bidirectional assurance navigation",
    "Normalized temporal model",
    "Timeout-ladder analysis",
    "Retry-amplification analysis",
    "Clock-domain diagnostics",
    "Concurrency and cancellation analysis",
    "Circuit-breaker framework expansion",
    "Circuit-breaker obligation decomposition",
    "Temporal sequence overlays",
    "Resilience fault-injection recipes",
    "Over-broad citation detection",
    "Citation specificity scoring",
    "Citation applicability explanation",
    "Guidance relationship typing",
    "Guidance revision monitoring",
    "Organizational guidance precedence",
    "Independent mapping approval",
    "Assurance case graph",
    "Dependency and contract fact caching",
    "Deterministic parallel parsing",
    "Incremental affected-region analysis",
    "Resource telemetry",
    "Monorepo analysis federation",
    "Virtualized report tables",
    "Deferred diagram construction",
    "Indexed report search",
    "Compact report with companion JSON",
    "Report quality budgets",
    "Role-specific report profiles",
    "Next-best-action dashboard",
    "Saved review campaigns",
    "Bulk disposition preview",
    "Baseline comparison workspace",
    "ALM and issue export",
    "Reviewer workload analytics",
    "Accessible diagram alternatives",
    "Management report projection",
    "Grounded LLM failure summaries",
    "LLM claim-level evidence",
    "LLM abstention policy",
    "LLM review-only proposals",
    "Local and redacted inference",
    "Unsupported-claim linting",
    "Representative LLM evaluation corpus",
    "LLM subject drift invalidation",
    "Independent repository cohorts",
    "Framework and rule precision claims",
    "Runtime and OS differential analysis",
    "Multi-browser qualification",
    "Comprehensive accessibility qualification",
    "Adversarial repository qualification",
    "Signed reproducible release evidence",
    "Governed plugin SDK",
    "Secured service deployment profile",
    "Artifact migration tooling",
)

# Stable product-outcome register derived from the 2026-08-09 representative scan.
# The identifier/title pair is deliberately data, rather than prose hidden in a report,
# so downstream systems can verify that every recommendation retains a resolution path.
PRODUCT_OUTCOME_TITLES = (
    "End-to-end evidence onboarding command",
    "Coverage artifact preflight and repair guidance",
    "Repository-aware test discovery",
    "Test-to-component mapping",
    "Executable review campaign",
    "Safe cluster adjudication",
    "Rule-level precision measurement",
    "Generic-rule precision refinement",
    "Confidence calibration",
    "Detected-control recall improvement",
    "Evidence-strength scoring",
    "Finding consolidation",
    "Review-ready finding completeness gate",
    "Triage dashboard",
    "Baseline-aware review preservation",
    "Interprocedural data-flow analysis",
    "Alias and object-flow resolution",
    "Framework-aware call resolution",
    "Async and concurrency model",
    "Exception-flow analysis",
    "State-machine extraction",
    "Transaction and consistency analysis",
    "Side-effect and idempotency analysis",
    "Temporal budget propagation",
    "Circuit-breaker semantic analysis",
    "Retry amplification analysis",
    "Resource-bound analysis",
    "Configuration provenance",
    "Authorization and scope-flow analysis",
    "Dynamic-code uncertainty modeling",
    "Cross-language interface discovery",
    "Contract-aware reconciliation",
    "Deployment topology overlay",
    "Common-cause analysis expansion",
    "Explicit analysis limitations per finding",
    "Effect-propagation graph",
    "Sequence reconstruction",
    "Runtime sequence overlays",
    "Timing annotations on sequences",
    "Reviewed SFTA authoring workflow",
    "SFMEA-to-SFTA correlation",
    "Cut-set computation for approved trees",
    "Barrier and control diagrams",
    "Fault-injection campaign binding",
    "Test scaffold generator",
    "Property-test synthesis",
    "Temporal and concurrency tests",
    "Resilience tests",
    "Security-negative tests",
    "Contract-test generation",
    "Controlled test execution sandbox",
    "Evidence receipt ingestion",
    "Finding closure gate",
    "Evidence freshness and invalidation",
    "Close the 15 rule-mapping gaps",
    "Eliminate repeated contextual citations",
    "Pinpoint citation locations",
    "Citation applicability profiles",
    "Independent mapping approval",
    "Citation regression tests",
    "Compliance-claim guardrails",
    "Architecture mapping activation",
    "Unmapped-finding reduction campaign",
    "Hierarchical architecture model",
    "Frontend-scope recommendations",
    "Route disposition workflow",
    "Interface compatibility findings",
    "True compact report mode",
    "Sub-second navigation target",
    "Progressive diagram rendering",
    "Deep links and saved views",
    "Reviewer-oriented comparison view",
    "Management summary mode",
    "Printable and archival output",
    "Comprehensive accessibility qualification",
    "Evidence-grounded summarization",
    "Schema-constrained LLM output",
    "Mandatory abstention",
    "Prompt-injection isolation",
    "LLM deduplication and contradiction detection",
    "Human-editable synthesis workspace",
    "Provider-neutral model gateway",
    "LLM quality benchmark",
    "Pull-request differential analysis",
    "Configurable CI policy gates",
    "Standard export formats",
    "Stable public API and plugin SDK",
    "Artifact migration tooling",
    "Independent repository qualification corpus",
    "Precision and recall release thresholds",
    "Cross-platform qualification",
    "Adversarial repository testing",
    "Memory and large-repository budgets",
    "Reproducible signed releases",
    "Service threat model",
)


# Product maturity is deliberately independent from project evidence and human
# authority.  A projection, queue, schema, or report card is useful integration
# work, but it is not proof that the named analyzer or workflow exists.  These
# exhaustive sets therefore fail closed: adding an E-item requires an explicit
# maturity decision, and no item is called ``validated`` until representative,
# independent evidence exists.
IMPLEMENTED_PRODUCT_OUTCOME_IDS = frozenset(
    {
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        29,
        31,
        32,
        33,
        34,
        28,
        30,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
        61,
        62,
        63,
        64,
        65,
        66,
        67,
        68,
        69,
        70,
        71,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        86,
        87,
        88,
        89,
        90,
        91,
        92,
        93,
        94,
        95,
    }
)
PARTIAL_PRODUCT_OUTCOME_IDS: frozenset[int] = frozenset()
PLANNED_PRODUCT_OUTCOME_IDS: frozenset[int] = frozenset()
PRODUCT_OUTCOME_MATURITIES = ("planned", "partial", "implemented", "validated")

_OUTCOME_IDS = frozenset(range(1, len(PRODUCT_OUTCOME_TITLES) + 1))
if (
    IMPLEMENTED_PRODUCT_OUTCOME_IDS
    | PARTIAL_PRODUCT_OUTCOME_IDS
    | PLANNED_PRODUCT_OUTCOME_IDS
) != _OUTCOME_IDS or any(
    left & right
    for left, right in (
        (IMPLEMENTED_PRODUCT_OUTCOME_IDS, PARTIAL_PRODUCT_OUTCOME_IDS),
        (IMPLEMENTED_PRODUCT_OUTCOME_IDS, PLANNED_PRODUCT_OUTCOME_IDS),
        (PARTIAL_PRODUCT_OUTCOME_IDS, PLANNED_PRODUCT_OUTCOME_IDS),
    )
):
    raise RuntimeError(
        "product-outcome maturity assignments must be exhaustive and disjoint"
    )


_PARTIAL_OUTCOME_GAPS: dict[int, str] = {}

_PLANNED_OUTCOME_GAPS: dict[int, str] = {}

_OUTCOME_EVIDENCE_GROUPS: tuple[tuple[range, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        range(1, 5),
        (
            "src/pysfmea/enhancements.py",
            "src/pysfmea/evidence_onboarding.py",
            "src/pysfmea/scanner.py",
        ),
        (
            "tests/test_enhancements.py",
            "tests/test_evidence_onboarding.py",
            "tests/test_scanner.py",
        ),
    ),
    (
        range(5, 16),
        (
            "src/pysfmea/activation.py",
            "src/pysfmea/diagnostics.py",
            "src/pysfmea/discovery.py",
            "src/pysfmea/server.py",
        ),
        (
            "tests/test_activation.py",
            "tests/test_diagnostics.py",
            "tests/test_evaluation.py",
            "tests/test_server.py",
        ),
    ),
    (
        range(16, 36),
        ("src/pysfmea/scanner.py", "src/pysfmea/architecture.py"),
        ("tests/test_scanner.py", "tests/test_evaluation.py"),
    ),
    (
        range(36, 45),
        (
            "src/pysfmea/diagrams.py",
            "src/pysfmea/runtime.py",
            "src/pysfmea/sfta.py",
            "src/pysfmea/sfta_authoring.py",
        ),
        (
            "tests/test_diagrams.py",
            "tests/test_runtime.py",
            "tests/test_sfta.py",
            "tests/test_sfta_authoring.py",
        ),
    ),
    (
        range(45, 55),
        (
            "src/pysfmea/assurance.py",
            "src/pysfmea/assurance_synthesis.py",
            "src/pysfmea/execution.py",
            "src/pysfmea/fault_injection.py",
        ),
        (
            "tests/test_assurance.py",
            "tests/test_fault_injection.py",
        ),
    ),
    (
        range(55, 62),
        (
            "src/pysfmea/configuration_authoring.py",
            "src/pysfmea/guidance.py",
        ),
        ("tests/test_configuration_authoring.py", "tests/test_guidance.py"),
    ),
    (
        range(62, 68),
        (
            "src/pysfmea/configuration_authoring.py",
            "src/pysfmea/interface_reconciliation.py",
        ),
        (
            "tests/test_configuration_authoring.py",
            "tests/test_scanner.py",
        ),
    ),
    (
        range(68, 76),
        (
            "src/pysfmea/html_report.py",
            "src/pysfmea/pdf_report.py",
            "src/pysfmea/accessibility.py",
            "scripts/report_browser_gate.py",
        ),
        (
            "tests/test_accessibility.py",
            "tests/test_html_report.py",
            "tests/test_pdf_report.py",
        ),
    ),
    (
        range(76, 84),
        (
            "src/pysfmea/discovery.py",
            "src/pysfmea/llm_quality.py",
            "src/pysfmea/synthesis.py",
        ),
        (
            "tests/test_extensions.py",
            "tests/test_llm_quality_tool.py",
            "tests/test_synthesis.py",
        ),
    ),
    (
        range(84, 96),
        (
            "src/pysfmea/interchange.py",
            "src/pysfmea/program.py",
            "src/pysfmea/schemas.py",
            "src/pysfmea/signing.py",
            "src/pysfmea/store.py",
            "src/pysfmea/validation.py",
            "src/pysfmea/security.py",
            "src/pysfmea/pull_request.py",
            "src/pysfmea/sdk/__init__.py",
            "src/pysfmea/sdk/host.py",
            "scripts/benchmark_scan.py",
            "scripts/platform_qualification.py",
            "scripts/report_browser_gate.py",
            ".github/workflows/ci.yml",
        ),
        (
            "tests/test_interchange.py",
            "tests/test_program.py",
            "tests/test_schemas.py",
            "tests/test_store.py",
            "tests/test_validation.py",
            "tests/test_security.py",
            "tests/test_pull_request.py",
            "tests/test_sdk.py",
            "tests/test_performance_benchmark.py",
            "tests/test_platform_qualification.py",
        ),
    ),
)


def _text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(entry) for entry in value if entry not in (None, "")]


def _active_items(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        value
        for value in analysis.get("items", [])
        if isinstance(value, dict) and value.get("source_status", "active") == "active"
    ]


def _source_area(path: str) -> str:
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    return "/".join(parts[:3]) if parts else "unassigned"


def _priority(value: dict[str, Any]) -> str:
    return str(value.get("scanner", {}).get("screening_priority", "manual"))


def _priority_score(value: str) -> int:
    return {"high": 8, "medium": 3, "low": 1, "manual": 2}.get(value, 1)


def _review_clusters(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for item in items:
        scanner = item.get("scanner", {})
        review = item.get("review", {})
        source = item.get("source", item.get("component", {}).get("source", {}))
        causes = _text_list(review.get("causes"))
        actions = _text_list(review.get("recommended_actions"))
        hazards = sorted(_text_list(review.get("linked_hazards")))
        key = (
            str(scanner.get("rule_id", "unclassified")),
            str(scanner.get("failure_class", "unclassified")),
            causes[0] if causes else "cause-unresolved",
            actions[0] if actions else "action-unresolved",
            hazards[0] if hazards else "hazard-unmapped",
            _source_area(str(source.get("path", ""))),
        )
        grouped[key].append(item)
    clusters: list[dict[str, Any]] = []
    for key, members in grouped.items():
        ordered = sorted(
            members,
            key=lambda value: (
                -_priority_score(_priority(value)),
                str(value.get("id", "")),
            ),
        )
        dispositions = Counter(
            str(value.get("review", {}).get("disposition", "unreviewed"))
            for value in members
        )
        clusters.append(
            {
                "id": stable_id("CLUSTER", *key),
                "rule_id": key[0],
                "failure_class": key[1],
                "shared_cause": key[2],
                "shared_action": key[3],
                "hazard": key[4],
                "source_area": key[5],
                "representative_finding_id": str(ordered[0].get("id", "")),
                "members": [
                    str(value.get("id", "")) for value in ordered[:MAX_CLUSTER_MEMBERS]
                ],
                "members_omitted": max(0, len(ordered) - MAX_CLUSTER_MEMBERS),
                "finding_count": len(ordered),
                "priorities": dict(
                    sorted(Counter(_priority(value) for value in members).items())
                ),
                "dispositions": dict(sorted(dispositions.items())),
                "review_authority": "representative_is_a_queue_aid_not_a_family_disposition",
            }
        )
    return sorted(
        clusters,
        key=lambda value: (
            -sum(
                count * _priority_score(priority)
                for priority, count in value["priorities"].items()
            ),
            -int(value["finding_count"]),
            str(value["id"]),
        ),
    )[:MAX_CLUSTERS]


def _evidence_portfolio(
    analysis: dict[str, Any], items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_finding = {str(value.get("id", "")): value for value in items}
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    obligations = analysis.get("assurance", {}).get("obligations", [])
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        finding = by_finding.get(str(obligation.get("finding_id", "")), {})
        scanner = finding.get("scanner", {})
        source = finding.get("source", finding.get("component", {}).get("source", {}))
        hazards = sorted(_text_list(finding.get("review", {}).get("linked_hazards")))
        key = (
            str(obligation.get("verification_method", "unclassified")),
            str(scanner.get("rule_id", "unclassified")),
            hazards[0] if hazards else "hazard-unmapped",
            _source_area(str(source.get("path", ""))),
        )
        groups[key].append(obligation)
    portfolio: list[dict[str, Any]] = []
    for key, members in groups.items():
        finding_ids = sorted(
            {
                str(value.get("finding_id", ""))
                for value in members
                if value.get("finding_id")
            }
        )
        priorities = Counter(
            _priority(by_finding.get(finding_id, {})) for finding_id in finding_ids
        )
        score = sum(
            count * _priority_score(priority) for priority, count in priorities.items()
        )
        portfolio.append(
            {
                "id": stable_id("PORTFOLIO", *key),
                "verification_method": key[0],
                "rule_id": key[1],
                "hazard": key[2],
                "source_area": key[3],
                "priority_score": score,
                "finding_count": len(finding_ids),
                "obligation_count": len(members),
                "priorities": dict(sorted(priorities.items())),
                "finding_ids": finding_ids[:MAX_CLUSTER_MEMBERS],
                "finding_ids_omitted": max(0, len(finding_ids) - MAX_CLUSTER_MEMBERS),
                "obligation_ids": sorted(
                    str(value.get("id", "")) for value in members if value.get("id")
                )[:MAX_CLUSTER_MEMBERS],
                "recommended_command": "sfmea assurance-scaffold ANALYSIS --queue WORK_QUEUE --output TEST_DIRECTORY",
                "authority": "portfolio_optimization_not_test_implementation_or_evidence",
            }
        )
    return sorted(
        portfolio,
        key=lambda value: (
            -int(value["priority_score"]),
            -int(value["finding_count"]),
            str(value["id"]),
        ),
    )[:MAX_PORTFOLIO_GROUPS]


_SURFACE_RULES: dict[str, tuple[str, ...]] = {
    "events": (
        "celery",
        "queue",
        "publish",
        "subscribe",
        "websocket",
        "eventsource",
        "webhook",
        "schedule",
        "background",
        "task",
    ),
    "data": (
        "serialization",
        "validation",
        "input",
        "output",
        "schema",
        "model",
        "payload",
    ),
    "security": (
        "auth",
        "permission",
        "authorize",
        "credential",
        "secret",
        "token",
        "rate_limit",
        "middleware",
        "subprocess",
    ),
    "control_flow": ("control_logic", "state_mutation", "exception", "fallback"),
    "concurrency": (
        "concurrency",
        "asyncio",
        "create_task",
        "gather",
        "lock",
        "semaphore",
        "cancel",
        "shield",
    ),
    "resilience": (
        "retry",
        "timeout",
        "circuit",
        "breaker",
        "fallback",
        "backoff",
        "deadline",
        "idempot",
    ),
    "persistence": (
        "persistence",
        "database",
        "repository",
        "transaction",
        "commit",
        "rollback",
        "atomic",
        "idempot",
    ),
    "dependencies": (
        "external_interface",
        "external_interface_candidate",
        "runtime_environment",
    ),
    "dynamic_wiring": ("entrypoint", "router", "plugin", "factory", "registry"),
}


def _component_surface_models(analysis: dict[str, Any]) -> dict[str, Any]:
    models: dict[str, list[dict[str, Any]]] = {key: [] for key in _SURFACE_RULES}
    components = [
        value for value in analysis.get("components", []) if isinstance(value, dict)
    ]
    for component in components:
        evidence_values = [
            *_text_list(component.get("signals")),
            *_text_list(component.get("frameworks")),
            *_text_list(component.get("decorators")),
            *_text_list(component.get("calls")),
            *_text_list(component.get("entrypoint_types")),
        ]
        searchable = " ".join(evidence_values).casefold()
        for category, tokens in _SURFACE_RULES.items():
            matched = sorted({token for token in tokens if token in searchable})
            if not matched and not (
                category == "resilience" and component.get("detected_controls")
            ):
                continue
            models[category].append(
                {
                    "id": stable_id("SURFACE", category, str(component.get("id", ""))),
                    "component_id": str(component.get("id", "")),
                    "component": str(
                        component.get("qualname", component.get("name", ""))
                    ),
                    "source": component.get("source", {}),
                    "matched_signals": matched,
                    "calls": _text_list(component.get("calls"))[:50],
                    "controls": component.get("detected_controls", [])[:25],
                    "confidence": "static_semantic_candidate",
                    "authority": "review_lead_not_path_sensitive_runtime_or_effectiveness_evidence",
                }
            )
    for category in models:
        models[category] = sorted(
            models[category],
            key=lambda value: (
                str(value.get("source", {}).get("path", "")),
                int(value.get("source", {}).get("line", 0) or 0),
                str(value.get("component_id", "")),
            ),
        )[:MAX_SURFACE_RECORDS]

    inventory = analysis.get("repository_inventory", {}).get("entries", [])
    deployment_tokens = (
        "dockerfile",
        "compose",
        "kubernetes",
        "k8s",
        "helm",
        "terraform",
        ".github/workflows",
        "gitlab-ci",
        "jenkins",
        "nginx",
        "traefik",
        "deployment",
        "service.yaml",
        "service.yml",
    )
    deployment = []
    for entry in inventory:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path", ""))
        matched = [token for token in deployment_tokens if token in path.casefold()]
        if matched:
            deployment.append(
                {
                    "id": stable_id("DEPLOY", path),
                    "path": path,
                    "kind": entry.get("kind", "unknown"),
                    "status": entry.get("status", "unknown"),
                    "matched_signals": matched,
                    "authority": "artifact_presence_not_deployed_topology_or_control_effectiveness",
                }
            )
    models["deployment"] = deployment[:MAX_SURFACE_RECORDS]
    models["contracts"] = [
        {
            "id": str(value.get("id", "")),
            "kind": value.get("kind", "unknown"),
            "source": value.get("source", value.get("path", "")),
            "operations": len(value.get("operations", []))
            if isinstance(value.get("operations"), list)
            else 0,
            "authority": "local_contract_inventory_not_deployed_compatibility",
        }
        for value in analysis.get("context", {}).get("contracts", [])
        if isinstance(value, dict)
    ][:MAX_SURFACE_RECORDS]
    return models


def _evidence_acquisition(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    paths = {
        str(value.get("path", "")).casefold()
        for value in analysis.get("repository_inventory", {}).get("entries", [])
        if isinstance(value, dict)
    }
    pytest_detected = any(
        path.endswith(("pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg"))
        or "/test" in path
        or path.startswith("test")
        for path in paths
    )
    steps: list[dict[str, Any]] = []

    def add(
        identifier: str,
        priority: str,
        reason: str,
        argv: list[str],
        outputs: list[str],
        execution: str = "approved_sandbox",
        details: dict[str, Any] | None = None,
    ) -> None:
        step = {
            "id": identifier,
            "priority": priority,
            "reason": reason,
            "argv": argv,
            "outputs": outputs,
            "execution_boundary": execution,
        }
        if details:
            step.update(details)
        steps.append(step)

    evidence = diagnostics.get("evidence", {})
    scope_conflicts = diagnostics.get("evidence_scope", {}).get("conflicts", [])
    if scope_conflicts:
        add(
            "review_evidence_scope",
            "P0",
            "Semantic exclusions hide configured test or web-boundary evidence.",
            ["sfmea", "diagnostics", "ANALYSIS", "--json"],
            ["reviewed sfmea.toml evidence-only include decision"],
            "read_only_planning",
            {
                "configuration_suggestions": [
                    value.get("suggested_config", {})
                    for value in scope_conflicts
                    if isinstance(value, dict) and value.get("suggested_config")
                ],
                "authority": "configuration_suggestion_requires_review",
            },
        )
    if not evidence.get("components_with_test_references"):
        add(
            "index_tests",
            "P0",
            "No component has indexed test references.",
            ["sfmea", "scan", "REPOSITORY", "--config", "sfmea.toml"],
            ["sfmea-analysis.json"],
            "read_only_scanner",
        )
    if not evidence.get("components_with_coverage"):
        add(
            "collect_coverage",
            "P0",
            "No executed coverage evidence is bound to the analysis.",
            ["python", "-m", "coverage", "run", "--branch", "-m", "pytest"],
            [".coverage"],
        )
        add(
            "export_coverage_json",
            "P0",
            "Create the bounded coverage.py input consumed by the scanner.",
            ["python", "-m", "coverage", "json", "-o", ".artifacts/coverage.json"],
            [".artifacts/coverage.json"],
        )
    if pytest_detected:
        add(
            "collect_junit",
            "P0",
            "A conventional Python test surface is present.",
            ["python", "-m", "pytest", "--junitxml=.artifacts/junit.xml"],
            [".artifacts/junit.xml"],
        )
    if not evidence.get("runtime_imports"):
        add(
            "collect_runtime_trace",
            "P1",
            "No runtime relation or timing evidence is imported.",
            ["sfmea", "trace-import", "ANALYSIS", ".artifacts/runtime-trace.json"],
            ["updated analysis with bound runtime import"],
        )
    add(
        "generate_assurance_work",
        "P1",
        "Generate lifecycle-aware verification work before scaffolding tests.",
        ["sfmea", "assurance-work", "ANALYSIS", "-o", ".artifacts/assurance-work.json"],
        [".artifacts/assurance-work.json"],
        "read_only_planning",
    )
    add(
        "dependency_audit",
        "P2",
        "Corroborate declared dependency inventory with a current vulnerability audit.",
        ["python", "-m", "pip_audit", ".", "--strict", "--progress-spinner", "off"],
        ["captured CI log or imported external evidence manifest"],
    )
    return {
        "mode": "plan_only_no_repository_execution",
        "steps": steps,
        "notice": "Argv recipes are inert planning data. Execute repository code only in an approved disposable sandbox and import immutable evidence for independent review.",
    }


def _interface_queue(analysis: dict[str, Any]) -> dict[str, Any]:
    model = analysis.get("interface_reconciliation", {})
    matched_clients = {
        str(value.get("client_endpoint_id", ""))
        for value in model.get("matches", [])
        if isinstance(value, dict)
    }
    matched_servers = {
        str(value.get("server_route_id", ""))
        for value in model.get("matches", [])
        if isinstance(value, dict)
    }
    clients = [
        {
            "id": str(value.get("id", "")),
            "source_path": value.get("source_path", ""),
            "line": value.get("line", 0),
            "method": value.get("method", "UNKNOWN"),
            "paths": [
                candidate
                for candidate in [
                    value.get("normalized_path"),
                    *value.get("composed_normalized_paths", []),
                ]
                if candidate
            ],
            "suggested_dispositions": [
                "confirmed_compatible",
                "deployment_prefix_or_proxy",
                "generated_or_external_server",
                "test_only",
                "confirmed_mismatch",
                "needs_information",
            ],
            "authority": "unmatched_static_candidate_not_defect",
        }
        for value in model.get("client_endpoints", [])
        if isinstance(value, dict)
        and value.get("classification") == "endpoint_candidate"
        and str(value.get("id", "")) not in matched_clients
    ]
    servers = [
        {
            "id": str(value.get("id", "")),
            "component_id": value.get("component_id", ""),
            "path": value.get("normalized_path", value.get("path", "")),
            "methods": value.get("methods", []),
            "source": value.get("source", {}),
            "suggested_dispositions": [
                "intentional_backend_only",
                "external_or_generated_client",
                "deprecated_or_unreachable",
                "missing_client_coverage",
                "needs_information",
            ],
            "authority": "unmatched_server_route_not_defect_or_required_client",
        }
        for value in model.get("server_routes", [])
        if isinstance(value, dict) and str(value.get("id", "")) not in matched_servers
    ]
    return {
        "clients": clients[:MAX_DISPOSITION_RECORDS],
        "clients_omitted": max(0, len(clients) - MAX_DISPOSITION_RECORDS),
        "servers": servers[:MAX_DISPOSITION_RECORDS],
        "servers_omitted": max(0, len(servers) - MAX_DISPOSITION_RECORDS),
        "authority": "review_queue_only_no_automatic_compatibility_or_defect_decision",
    }


def _capability_register(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    run_status = {
        str(value.get("adapter_id", "")): str(value.get("status", "unknown"))
        for value in analysis.get("adapter_runs", {}).get("runs", [])
        if isinstance(value, dict)
    }
    return [
        {
            **asdict(spec),
            "status": (
                "available_product_capability"
                if spec.authority == "product"
                else "awaiting_project_evidence"
                if spec.authority == "project_evidence"
                else "awaiting_human_authority"
            ),
            "adapter_context": dict(sorted(run_status.items()))
            if spec.id == "P3-03"
            else None,
        }
        for spec in ENHANCEMENT_SPECS
    ]


def _project_evidence_signals(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, bool]:
    evidence = diagnostics.get("evidence", {})
    assurance = evidence.get("assurance", {})
    interfaces = diagnostics.get("interfaces", {})
    interface_summary = (
        interfaces.get("summary", {}) if isinstance(interfaces, dict) else {}
    )
    contracts = analysis.get("interface_contracts", {})
    contract_count = (
        int(contracts.get("summary", {}).get("contracts", 0) or 0)
        if isinstance(contracts, dict)
        else 0
    )
    baseline_id = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
    runtime_available = any(
        isinstance(value, dict) and str(value.get("baseline_id", "")) == baseline_id
        for value in analysis.get("runtime_evidence", {}).get("imports", [])
    )
    qualification_evidence = bool(
        analysis.get("assurance_program", {}).get("validation", {}).get("cohorts")
    )
    return {
        "H01": bool(assurance.get("executions")),
        "H03": bool(evidence.get("components_with_coverage")),
        "H04": runtime_available,
        "H07": bool(assurance.get("executions")),
        "H10": qualification_evidence,
        "H13": qualification_evidence,
        "H14": runtime_available,
        "H17": runtime_available,
        "H18": runtime_available,
        "H22": bool(analysis.get("repository_inventory", {}).get("entries")),
        "H30": contract_count > 0,
        "H31": contract_count > 0 and bool(interface_summary),
        "H33": runtime_available or contract_count > 0,
        "H46": qualification_evidence,
        "H57": False,
        "H59": qualification_evidence,
        "H62": bool(assurance.get("evidence_artifacts")),
        "H67": qualification_evidence,
        "H68": qualification_evidence,
        "H69": qualification_evidence,
        "H70": qualification_evidence,
        "H71": False,
        "H74": False,
        "H75": False,
    }


def _hardening_register(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> list[dict[str, Any]]:
    evidence_signals = _project_evidence_signals(analysis, diagnostics)
    register: list[dict[str, Any]] = []
    for spec in HARDENING_SPECS:
        if spec.authority == "product":
            state = "resolved_product_capability"
        elif spec.authority == "project_evidence":
            state = (
                "project_evidence_available_for_review"
                if evidence_signals.get(spec.id, False)
                else "project_evidence_required"
            )
        else:
            state = "human_decision_required"
        register.append({**asdict(spec), "resolution_state": state})
    return register


def _artifact_freshness(analysis: dict[str, Any]) -> dict[str, Any]:
    baseline = analysis.get("project", {}).get("baseline", {})
    baseline_id = str(baseline.get("id", ""))
    runtime_imports = [
        value
        for value in analysis.get("runtime_evidence", {}).get("imports", [])
        if isinstance(value, dict)
    ]
    executions = [
        value
        for value in analysis.get("assurance", {}).get("executions", [])
        if isinstance(value, dict)
    ]
    run_manifest = analysis.get("run_manifest", {})
    manifest_baseline = str(run_manifest.get("repository", {}).get("baseline_id", ""))
    coverage = (
        analysis.get("project", {}).get("settings", {}).get("coverage_evidence", {})
    )

    def status_for(values: list[dict[str, Any]]) -> dict[str, Any]:
        current = sum(
            str(value.get("baseline_id", "")) == baseline_id for value in values
        )
        stale = len(values) - current
        return {
            "records": len(values),
            "current": current,
            "stale": stale,
            "status": "missing" if not values else "stale" if stale else "current",
        }

    return {
        "analysis_state_sha256": canonical_json_sha256(analysis),
        "baseline_id": baseline_id,
        "repository_sha256": str(baseline.get("repository_sha256", "")),
        "run_manifest": {
            "baseline_id": manifest_baseline,
            "status": (
                "missing"
                if not manifest_baseline
                else "current"
                if manifest_baseline == baseline_id
                else "stale"
            ),
        },
        "coverage": {
            "present": isinstance(coverage, dict) and bool(coverage.get("sha256")),
            "sha256": str(coverage.get("sha256", ""))
            if isinstance(coverage, dict)
            else "",
            "status": (
                "current_scan_input"
                if isinstance(coverage, dict) and coverage.get("sha256")
                else "missing"
            ),
        },
        "runtime_imports": status_for(runtime_imports),
        "assurance_executions": status_for(executions),
        "status": (
            "stale"
            if (
                (manifest_baseline and manifest_baseline != baseline_id)
                or any(
                    str(value.get("baseline_id", "")) != baseline_id
                    for value in [*runtime_imports, *executions]
                )
            )
            else "current"
        ),
        "authority": "exact_identity_and_digest_freshness_not_evidence_sufficiency",
    }


def _artifact_health(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    freshness = _artifact_freshness(analysis)
    evidence = diagnostics.get("evidence", {})
    assurance = evidence.get("assurance", {})
    completeness_checks = {
        "repository_identity": bool(
            freshness.get("repository_sha256")
            or analysis.get("project", {})
            .get("baseline", {})
            .get("source_snapshot_sha256")
        ),
        "run_manifest": freshness.get("run_manifest", {}).get("status") == "current",
        "test_references": bool(evidence.get("components_with_test_references")),
        "coverage": freshness.get("coverage", {}).get("status") == "current_scan_input",
        "runtime": freshness.get("runtime_imports", {}).get("status") == "current",
        "executions": freshness.get("assurance_executions", {}).get("status")
        == "current",
        "contracts": bool(analysis.get("context", {}).get("contracts")),
    }
    sufficient = int(assurance.get("by_evidence_status", {}).get("sufficient", 0) or 0)
    active = int(assurance.get("active_obligations", 0) or 0)
    sufficiency_percent = round(100 * sufficient / active, 1) if active else 100.0
    return {
        "freshness": freshness,
        "completeness": {
            "checks": completeness_checks,
            "complete": all(completeness_checks.values()),
            "passed": sum(completeness_checks.values()),
            "total": len(completeness_checks),
            "missing": sorted(
                key for key, value in completeness_checks.items() if not value
            ),
            "authority": "artifact_presence_and_binding_not_evidence_adequacy",
        },
        "sufficiency": {
            "active_obligations": active,
            "sufficient_obligations": sufficient,
            "percent": sufficiency_percent,
            "status": "complete" if sufficient == active else "gap",
            "authority": "recorded_governed_evidence_state_not_automatic_control_credit",
        },
        "overall_status": (
            "stale"
            if freshness.get("status") == "stale"
            else "incomplete"
            if not all(completeness_checks.values())
            else "insufficient"
            if sufficient != active
            else "ready_for_named_review"
        ),
    }


def _scope_patch(diagnostics: dict[str, Any]) -> dict[str, Any]:
    conflicts = [
        value
        for value in diagnostics.get("evidence_scope", {}).get("conflicts", [])
        if isinstance(value, dict)
    ]
    changes: dict[str, list[str]] = {}
    for conflict in conflicts:
        suggestion = conflict.get("suggested_config", {})
        if not isinstance(suggestion, dict):
            continue
        for key, values in suggestion.items():
            if not isinstance(values, list):
                continue
            normalized = sorted(
                {str(value) for value in values if isinstance(value, str) and value}
            )
            if normalized:
                changes[str(key)] = normalized

    lines = ["[scan]"]
    for dotted_key, values in sorted(changes.items()):
        key = dotted_key.rpartition(".")[2]
        encoded = ", ".join(json.dumps(value, ensure_ascii=False) for value in values)
        lines.append(f"{key} = [{encoded}]")
    return {
        "status": "review_required" if changes else "not_required",
        "changes": changes,
        "toml_preview": "\n".join(lines) + "\n" if changes else "",
        "apply_mode": "preview_only_no_configuration_write",
        "validation_steps": [
            "confirm each pattern is inside the intended repository boundary",
            "preview selected evidence-only files",
            "apply the patch through normal configuration review",
            "rescan and compare the exact analysis diff",
        ],
        "authority": "reviewable_patch_preview_not_configuration_approval",
    }


def _scope_preview_plan(scope_patch: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": "pysfmea-enhancement-scope-preview-plan-1",
        "status": "review_required" if scope_patch.get("changes") else "not_required",
        "argv": [
            "sfmea",
            "enhance-scope-preview",
            "ANALYSIS",
            "REPOSITORY",
            "--output",
            ".artifacts/enhancement-scope-preview.json",
        ],
        "proposed_changes": scope_patch.get("changes", {}),
        "authority": "read_only_metadata_preview_not_scope_approval_or_file_content_evidence",
    }


def _scope_pattern_matches(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/").lstrip("./")
    normalized_pattern = pattern.replace("\\", "/").lstrip("./")
    if normalized_pattern.endswith("/**"):
        prefix = normalized_pattern[:-3].rstrip("/")
        return normalized_path == prefix or normalized_path.startswith(prefix + "/")
    return fnmatchcase(normalized_path, normalized_pattern)


def enhancement_scope_preview(
    analysis: dict[str, Any], repository: str | Path
) -> dict[str, Any]:
    """Preview metadata for files admitted by proposed evidence-only scope changes."""

    root = Path(repository).absolute()
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ValueError(
            "scope-preview repository must be a regular directory, not a link"
        )
    diagnostics = analysis_diagnostics(analysis)
    patch = _scope_patch(diagnostics)
    patterns: list[tuple[str, str]] = []
    for config_key, values in sorted(patch.get("changes", {}).items()):
        for value in values:
            patterns.append((str(config_key), str(value)))

    records: list[dict[str, Any]] = []
    rejected_links = 0
    rejected_non_files = 0
    pruned_directories = 0
    visited = 0
    truncated = False
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(
                os.scandir(directory), key=lambda value: value.name.casefold()
            )
        except OSError:
            rejected_non_files += 1
            continue
        for entry in entries:
            visited += 1
            if visited > MAX_SCOPE_PREVIEW_VISITED:
                truncated = True
                stack.clear()
                break
            try:
                if entry.is_symlink():
                    rejected_links += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SCOPE_PREVIEW_PRUNED_DIRS:
                        pruned_directories += 1
                        continue
                    stack.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    rejected_non_files += 1
                    continue
                relative = Path(entry.path).relative_to(root).as_posix()
                matched = [
                    {"config_key": key, "pattern": pattern}
                    for key, pattern in patterns
                    if _scope_pattern_matches(relative, pattern)
                ]
                if not matched:
                    continue
                stat = entry.stat(follow_symlinks=False)
                records.append(
                    {
                        "path": relative,
                        "size": stat.st_size,
                        "matches": matched,
                        "classification": (
                            "test_evidence_candidate"
                            if any(
                                value["config_key"].endswith("test_evidence_include")
                                for value in matched
                            )
                            else "web_boundary_candidate"
                        ),
                    }
                )
                if len(records) >= MAX_SCOPE_PREVIEW_MATCHES:
                    truncated = True
                    stack.clear()
                    break
            except OSError:
                rejected_non_files += 1
    records.sort(key=lambda value: str(value["path"]))
    material: dict[str, Any] = {
        "format": "pysfmea-enhancement-scope-preview-1",
        "analysis_binding": {
            "baseline_id": analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "analysis_state_sha256": canonical_json_sha256(analysis),
        },
        "repository": str(root),
        "proposed_changes": patch.get("changes", {}),
        "summary": {
            "visited_entries": min(visited, MAX_SCOPE_PREVIEW_VISITED),
            "matched_files": len(records),
            "matched_bytes": sum(int(value["size"]) for value in records),
            "rejected_links": rejected_links,
            "rejected_non_files": rejected_non_files,
            "pruned_directories": pruned_directories,
            "truncated": truncated,
        },
        "files": records,
        "authority": "read_only_metadata_preview_not_scope_approval_content_evidence_or_semantic_analysis",
    }
    material["content_sha256"] = canonical_json_sha256(material)
    return material


def evidence_preflight(
    analysis: dict[str, Any],
    repository: str | Path,
    *,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect evidence readiness without importing or executing repository code."""

    root = Path(os.path.abspath(Path(repository).expanduser()))
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence preflight repository must be a regular directory")
    test_files: list[str] = []
    test_configs: list[str] = []
    contracts: list[str] = []
    visited = 0
    truncated = False
    config_names = {
        "pyproject.toml",
        "pytest.ini",
        "tox.ini",
        "noxfile.py",
        "setup.cfg",
    }
    contract_suffixes = (
        ".schema.json",
        ".openapi.json",
        ".openapi.yaml",
        ".openapi.yml",
        ".proto",
        ".graphql",
        ".gql",
    )
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        directories[:] = sorted(
            value
            for value in directories
            if value not in SCOPE_PREVIEW_PRUNED_DIRS
            and not (Path(current) / value).is_symlink()
        )
        for filename in sorted(filenames):
            visited += 1
            if visited > MAX_EVIDENCE_PREFLIGHT_FILES:
                truncated = True
                break
            candidate = Path(current) / filename
            if candidate.is_symlink() or not candidate.is_file():
                continue
            relative = candidate.relative_to(root).as_posix()
            lowered = filename.lower()
            parts = {value.lower() for value in Path(relative).parts}
            if (
                (lowered.startswith("test_") and lowered.endswith(".py"))
                or lowered.endswith("_test.py")
                or "tests" in parts
            ):
                test_files.append(relative)
            if lowered in config_names:
                test_configs.append(relative)
            if lowered.endswith(contract_suffixes):
                contracts.append(relative)
        if truncated:
            break

    configured_coverage = str(
        analysis.get("project", {}).get("settings", {}).get("coverage_json", "") or ""
    )
    candidates: list[Path] = []
    if configured_coverage:
        configured_path = Path(configured_coverage).expanduser()
        candidates.append(
            configured_path if configured_path.is_absolute() else root / configured_path
        )
    candidates.extend((root / ".artifacts" / "coverage.json", root / "coverage.json"))
    coverage: dict[str, Any] = {
        "status": "missing",
        "path": configured_coverage,
        "files": 0,
        "diagnostics": [],
    }
    seen_candidates: set[str] = set()
    for candidate in candidates:
        key = str(candidate.absolute()).casefold()
        if key in seen_candidates:
            continue
        seen_candidates.add(key)
        if not candidate.exists():
            continue
        try:
            document = load_bounded_json_document(
                candidate,
                label="coverage JSON",
                max_bytes=50_000_000,
                max_depth=100,
                max_nodes=2_000_000,
            )
            value = document.value
            files = value.get("files") if isinstance(value, dict) else None
            if not isinstance(files, dict):
                coverage.update(
                    {
                        "status": "invalid",
                        "path": str(document.path),
                        "diagnostics": ["coverage JSON has no files object"],
                    }
                )
            else:
                coverage.update(
                    {
                        "status": "ready",
                        "path": str(document.path),
                        "files": len(files),
                        "sha256": hashlib.sha256(document.raw).hexdigest(),
                        "diagnostics": [],
                    }
                )
            break
        except (OSError, ValueError) as exc:
            coverage.update(
                {
                    "status": "invalid",
                    "path": str(candidate.absolute()),
                    "diagnostics": [str(exc)],
                }
            )
            break

    evidence = (diagnostics or analysis_diagnostics(analysis)).get("evidence", {})
    material: dict[str, Any] = {
        "format": "pysfmea-evidence-preflight-1",
        "analysis_binding": {
            "baseline_id": analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "analysis_state_sha256": canonical_json_sha256(analysis),
        },
        "repository": str(root),
        "summary": {
            "visited_files": min(visited, MAX_EVIDENCE_PREFLIGHT_FILES),
            "test_files": len(test_files),
            "test_configurations": len(test_configs),
            "contracts": len(contracts),
            "coverage_status": coverage["status"],
            "runtime_imports": int(evidence.get("runtime_imports", 0) or 0),
            "components_with_test_references": int(
                evidence.get("components_with_test_references", 0) or 0
            ),
            "truncated": truncated,
        },
        "discovery": {
            "test_files": test_files,
            "test_configurations": test_configs,
            "contracts": contracts,
            "coverage": coverage,
        },
        "ordered_actions": [
            {
                "id": "configure_test_scope",
                "required": bool(test_files)
                and not evidence.get("components_with_test_references"),
                "argv": ["sfmea", "enhance-scope-preview", "ANALYSIS", str(root)],
            },
            {
                "id": "regenerate_coverage",
                "required": coverage["status"] != "ready",
                "argv": [
                    "python",
                    "-m",
                    "coverage",
                    "json",
                    "-o",
                    ".artifacts/coverage.json",
                ],
            },
            {
                "id": "import_runtime_trace",
                "required": not evidence.get("runtime_imports"),
                "argv": [
                    "sfmea",
                    "trace-import",
                    "ANALYSIS",
                    ".artifacts/runtime-trace.json",
                ],
            },
            {
                "id": "generate_assurance_work",
                "required": True,
                "argv": [
                    "sfmea",
                    "assurance-work",
                    "ANALYSIS",
                    "-o",
                    ".artifacts/assurance-work.json",
                ],
            },
        ],
        "authority": (
            "read_only_evidence_preflight_not_permission_to_execute_or_credit_evidence"
        ),
    }
    material["content_sha256"] = canonical_json_sha256(material)
    return material


def _calibration_campaign(diagnostics: dict[str, Any]) -> dict[str, Any]:
    rules = (
        diagnostics.get("workload", {}).get("review_calibration", {}).get("rules", [])
    )
    campaigns: list[dict[str, Any]] = []
    for value in rules:
        if not isinstance(value, dict):
            continue
        findings = int(value.get("findings", 0) or 0)
        reviewed = int(value.get("reviewed", 0) or 0)
        # Deterministic planning heuristic only. Independent qualification chooses
        # the statistical method, confidence level, and acceptable error margin.
        target = min(findings, max(5, min(30, ceil(log2(findings + 1) * 2))))
        campaigns.append(
            {
                "rule_id": str(value.get("rule_id", "")),
                "population": findings,
                "reviewed": reviewed,
                "planning_sample_target": target,
                "remaining_sample": max(0, target - reviewed),
                "stratify_by": [
                    "screening_priority",
                    "source_area",
                    "component_kind",
                    "failure_effect",
                ],
                "status": "sample_ready" if reviewed >= target else "sample_required",
            }
        )
    campaigns.sort(
        key=lambda value: (
            -int(value["remaining_sample"]),
            -int(value["population"]),
            str(value["rule_id"]),
        )
    )
    return {
        "campaigns": campaigns[:100],
        "campaigns_omitted": max(0, len(campaigns) - 100),
        "total_sample_remaining": sum(
            int(value["remaining_sample"]) for value in campaigns
        ),
        "method": "bounded_log_population_planning_heuristic",
        "authority": "review_workload_planning_not_statistical_validation",
    }


def _metric_provenance(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    telemetry = (
        analysis.get("project", {}).get("settings", {}).get("scan_telemetry", {})
    )
    cache = analysis.get("run_manifest", {}).get("cache", {})
    scope_conflicts = diagnostics.get("evidence_scope", {}).get("conflicts", [])
    return {
        "scan_runtime": {
            "value": telemetry.get("total_seconds")
            if isinstance(telemetry, dict)
            else None,
            "mode": (
                "warm_cache"
                if cache.get("used")
                else "cold_no_fact_cache"
                if cache.get("enabled") is False
                else "cold_or_recomputed_cache"
            ),
            "telemetry_authority": telemetry.get("authority", "")
            if isinstance(telemetry, dict)
            else "",
        },
        "cross_stack": {
            "status": "unmeasured" if scope_conflicts else "measured_static",
            "scope_conflicts": len(scope_conflicts),
        },
        "evidence": {
            "status": "diagnostic_only",
            "notice": "Readiness percentages do not establish evidence sufficiency.",
        },
        "authority": "metric_context_not_qualification_evidence",
    }


def _report_scale(analysis: dict[str, Any]) -> dict[str, Any]:
    active_findings = len(_active_items(analysis))
    analysis_bytes = len(
        json.dumps(
            analysis,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    recommended_records = min(10_000, max(500, ceil(active_findings / 500) * 500))
    return {
        "active_findings": active_findings,
        "canonical_analysis_bytes": analysis_bytes,
        "recommended_embedded_record_limit": recommended_records,
        "budgets": {
            "target_html_bytes": 10 * 1024 * 1024,
            "target_browser_load_seconds": 1.0,
            "maximum_verifiable_html_bytes": 100 * 1024 * 1024,
        },
        "strategies": [
            "bounded prioritized record projection with complete external JSON",
            "paginated and deferred DOM construction",
            "on-demand bounded diagram selection",
            "browser receipt with explicit size and load budgets",
        ],
        "authority": "planning_budget_requires_generated_report_browser_receipt",
    }


def _review_campaign(
    items: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    diagnostics: dict[str, Any],
    calibration: dict[str, Any],
) -> dict[str, Any]:
    """Build deterministic, diverse review units without applying dispositions."""

    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        by_rule[str(item.get("scanner", {}).get("rule_id", "unclassified"))].append(
            item
        )
    target_by_rule = {
        str(value.get("rule_id", "")): int(value.get("remaining_sample", 0) or 0)
        for value in calibration.get("campaigns", [])
        if isinstance(value, dict)
    }
    samples: list[dict[str, Any]] = []
    for rule_id, target in sorted(target_by_rule.items()):
        if target <= 0:
            continue
        buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in by_rule.get(rule_id, []):
            source = item.get("source", item.get("component", {}).get("source", {}))
            key = (
                _priority(item),
                _source_area(str(source.get("path", ""))),
                str(item.get("component", {}).get("kind", "unknown")),
            )
            buckets[key].append(item)
        for values in buckets.values():
            values.sort(key=lambda value: str(value.get("id", "")))
        selected = 0
        while selected < target and any(buckets.values()):
            for key in sorted(
                buckets,
                key=lambda value: (-_priority_score(value[0]), *value[1:]),
            ):
                if selected >= target:
                    break
                values = buckets[key]
                if not values:
                    continue
                item = values.pop(0)
                samples.append(
                    {
                        "finding_id": str(item.get("id", "")),
                        "rule_id": rule_id,
                        "priority": key[0],
                        "source_area": key[1],
                        "component_kind": key[2],
                        "selection_reason": "deterministic_stratified_calibration",
                    }
                )
                selected += 1

    cluster_units = [
        {
            "cluster_id": str(value.get("id", "")),
            "representative_finding_id": str(
                value.get("representative_finding_id", "")
            ),
            "finding_count": int(value.get("finding_count", 0) or 0),
            "priorities": value.get("priorities", {}),
            "authority": "representative_review_does_not_dispose_cluster_members",
        }
        for value in clusters
    ]
    queue = diagnostics.get("workload", {}).get("queue_projection", {})
    configured_limit = max(1, int(queue.get("configured_limit", 1000) or 1000))
    lanes = queue.get(
        "recommended_reserved_slots", {"high": 800, "medium": 150, "low": 50}
    )
    units = [
        {
            "kind": "cluster_representative",
            "id": value["representative_finding_id"],
            "parent_id": value["cluster_id"],
        }
        for value in cluster_units
    ]
    known_ids = {str(value["id"]) for value in units}
    units.extend(
        {
            "kind": "calibration_sample",
            "id": value["finding_id"],
            "parent_id": value["rule_id"],
        }
        for value in samples
        if value["finding_id"] not in known_ids
    )
    batches: list[dict[str, Any]] = [
        {
            "id": f"REVIEW-BATCH-{index // 100 + 1:03d}",
            "units": units[index : index + 100],
            "unit_count": len(units[index : index + 100]),
        }
        for index in range(0, min(len(units), configured_limit), 100)
    ]
    return {
        "format": "pysfmea-review-campaign-1",
        "strategy": "root_cause_representatives_plus_stratified_calibration",
        "priority_lanes": lanes,
        "cluster_units": cluster_units,
        "calibration_samples": samples,
        "batches": batches,
        "units_total": len(units),
        "units_projected": sum(int(value["unit_count"]) for value in batches),
        "units_omitted": max(0, len(units) - configured_limit),
        "authority": "assignable_review_plan_not_finding_disposition_or_rule_tuning",
    }


def _finding_consolidation_program(
    analysis: dict[str, Any], clusters: list[dict[str, Any]]
) -> dict[str, Any]:
    registry = analysis.get("finding_consolidation", {})
    if not isinstance(registry, dict):
        registry = {}
    records = registry.get("records", [])
    if not isinstance(records, list):
        records = []
    eligible = [
        value
        for value in clusters
        if int(value.get("finding_count", 0) or 0) >= 2
        and int(value.get("members_omitted", 0) or 0) == 0
        and int(value.get("finding_count", 0) or 0) == len(value.get("members", []))
    ]
    return {
        "format": "pysfmea-finding-consolidation-program-1",
        "status": "implemented",
        "candidate_groups": len(eligible),
        "candidate_memberships": sum(
            int(value.get("finding_count", 0) or 0) for value in eligible
        ),
        "canonical_groups": len(records),
        "commands": [
            "sfmea activate-init ANALYSIS REPOSITORY -o activation.json",
            "sfmea activate-decide activation.json consolidation CANDIDATE_ID consolidate --reviewer NAME --rationale TEXT",
            "sfmea activate-verify activation.json --analysis ANALYSIS",
            "sfmea activate-apply ANALYSIS activation.json -o activated.json",
        ],
        "decision_choices": [
            "consolidate",
            "retain_separate",
            "needs_information",
        ],
        "preservation_contract": {
            "source_findings_removed": False,
            "member_dispositions_propagated": False,
            "member_evidence_and_citations_preserved": True,
            "exact_analysis_binding_required": True,
            "named_reviewer_and_rationale_required": True,
        },
        "authority": "human_adjudicated_canonical_review_groups_not_automatic_semantic_equivalence_or_shared_risk_acceptance",
    }


def _evidence_onboarding_program(
    analysis: dict[str, Any], diagnostics: dict[str, Any], health: dict[str, Any]
) -> dict[str, Any]:
    evidence = diagnostics.get("evidence", {})
    completeness = health.get("completeness", {}).get("checks", {})
    categories = [
        ("tests", bool(completeness.get("test_references")), "index_test_sources"),
        ("coverage", bool(completeness.get("coverage")), "export_coverage_json"),
        ("runtime", bool(completeness.get("runtime")), "collect_runtime_trace"),
        ("executions", bool(completeness.get("executions")), "generate_assurance_work"),
        ("contracts", bool(completeness.get("contracts")), "discover_contracts"),
    ]
    recipes = {
        str(value.get("id", "")): value
        for value in _evidence_acquisition(analysis, diagnostics).get("steps", [])
        if isinstance(value, dict)
    }
    states = []
    for identifier, available, recipe_id in categories:
        states.append(
            {
                "id": identifier,
                "status": "available_for_review" if available else "missing",
                "recipe": recipes.get(recipe_id),
                "completion_gate": "exact_baseline_binding_and_independent_review",
            }
        )
    return {
        "format": "pysfmea-evidence-onboarding-1",
        "workflow": {
            "status": "implemented",
            "command": "sfmea evidence-onboard",
            "receipt_format": "pysfmea-evidence-onboarding-receipt-1",
            "verification_format": (
                "pysfmea-evidence-onboarding-receipt-verification-1"
            ),
            "selected_evidence": [
                "coverage.py_json",
                "runtime_trace_json",
                "obligation_bound_external_execution_manifest",
            ],
            "modes": ["validated_plan", "applied"],
            "publication": (
                "updated_analysis_plus_verified_assurance_work_queue_plus_exact_bound_receipt"
            ),
            "repository_execution": "prohibited",
        },
        "states": states,
        "missing": [value["id"] for value in states if value["status"] == "missing"],
        "ordered_next_steps": [
            value["id"] for value in states if value["status"] == "missing"
        ],
        "evidence_counts": {
            "runtime_imports": int(evidence.get("runtime_imports", 0) or 0),
            "components_with_coverage": int(
                evidence.get("components_with_coverage", 0) or 0
            ),
            "components_with_test_references": int(
                evidence.get("components_with_test_references", 0) or 0
            ),
        },
        "authority": "guided_acquisition_state_machine_not_permission_to_execute_or_evidence_credit",
    }


def _precision_program(
    items: list[dict[str, Any]], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    calibration = diagnostics.get("workload", {}).get("review_calibration", {})
    rules = [value for value in calibration.get("rules", []) if isinstance(value, dict)]
    module_items = [
        value
        for value in items
        if str(value.get("component", {}).get("name", "")) == "<module initialization>"
        or str(value.get("component", {}).get("qualname", ""))
        == "<module initialization>"
    ]
    total = max(1, len(items))
    high_volume = [
        {
            "rule_id": str(value.get("rule_id", "")),
            "findings": int(value.get("findings", 0) or 0),
            "share_percent": round(100 * int(value.get("findings", 0) or 0) / total, 1),
            "reviewed": int(value.get("reviewed", 0) or 0),
            "specialization_required": int(value.get("findings", 0) or 0)
            >= max(100, ceil(total * 0.05)),
        }
        for value in rules
    ]
    return {
        "format": "pysfmea-precision-program-1",
        "rules": high_volume,
        "module_initialization": {
            "findings": len(module_items),
            "specialized_categories": [
                "import_time_side_effect",
                "registration",
                "configuration",
                "singleton_initialization",
                "declarative_definition",
            ],
            "status": "specialization_required" if module_items else "not_present",
        },
        "confidence_dimensions": [
            "ast_trigger",
            "framework_role",
            "call_resolution",
            "interface_evidence",
            "runtime_corroboration",
            "review_calibration",
        ],
        "suppression_policy": {
            "mode": "proposal_only",
            "requires_named_approval": True,
            "requires_regression_case": True,
            "automatic_rule_tuning": False,
        },
        "authority": "precision_improvement_program_not_ground_truth_or_automatic_suppression",
    }


def _architecture_program(diagnostics: dict[str, Any]) -> dict[str, Any]:
    proposals = [
        value
        for value in diagnostics.get("evidence", {}).get(
            "architecture_mapping_candidates", []
        )
        if isinstance(value, dict)
    ]
    domains = {
        str(value.get("id", "")): float(value.get("score", 0.0) or 0.0)
        for value in diagnostics.get("qualification", {}).get("domains", [])
        if isinstance(value, dict)
    }
    return {
        "format": "pysfmea-architecture-activation-1",
        "current_traceability_percent": domains.get("architecture_traceability", 0.0),
        "proposals": proposals,
        "review_actions": ["accept", "reject", "edit", "needs_information"],
        "patch_mode": "reviewed_records_only",
        "score_dimensions": [
            "source_proximity",
            "import_relationship",
            "interface_relationship",
            "shared_requirement",
            "shared_hazard",
            "runtime_corroboration",
        ],
        "authority": "bulk_review_workflow_not_architecture_or_hazard_approval",
    }


def _interface_program(
    analysis: dict[str, Any], diagnostics: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any]:
    summary = diagnostics.get("interfaces", {}).get("summary", {})
    queue = _interface_queue(analysis)
    hidden = any(
        key.endswith("boundary_evidence_include") for key in scope.get("changes", {})
    )
    return {
        "format": "pysfmea-interface-activation-1",
        "measurement_status": "blocked_by_scope" if hidden else "measured_static",
        "summary": summary,
        "server_disposition_campaign": queue.get("servers", []),
        "server_disposition_omitted": queue.get("servers_omitted", 0),
        "client_disposition_campaign": queue.get("clients", []),
        "client_disposition_omitted": queue.get("clients_omitted", 0),
        "supported_profile_inputs": [
            "reverse_proxy_prefix",
            "environment_base_url",
            "generated_client_manifest",
            "websocket_and_streaming_contract",
            "event_bus_contract",
            "database_transaction_boundary",
        ],
        "next_gate": "review_scope_then_rescan"
        if hidden
        else "disposition_unmatched_interfaces",
        "authority": "static_reconciliation_and_review_queue_not_deployed_compatibility",
    }


def _temporal_resilience_program(
    items: list[dict[str, Any]], surfaces: dict[str, Any]
) -> dict[str, Any]:
    selected = []
    for item in items:
        rule = str(item.get("scanner", {}).get("rule_id", ""))
        failure_class = str(item.get("scanner", {}).get("failure_class", ""))
        if rule.startswith(("timing.", "resilience.")) or failure_class in {
            "timing",
            "concurrency",
            "resource",
        }:
            selected.append(
                {
                    "finding_id": str(item.get("id", "")),
                    "rule_id": rule,
                    "priority": _priority(item),
                    "required_oracles": [
                        "deadline_or_timeout",
                        "bounded_retry_count",
                        "safe_degraded_state",
                        "recovery_and_containment",
                    ],
                }
            )
    return {
        "format": "pysfmea-temporal-resilience-program-1",
        "candidate_findings": selected[:1000],
        "candidate_findings_omitted": max(0, len(selected) - 1000),
        "surface_counts": {
            "concurrency": len(surfaces.get("concurrency", [])),
            "resilience": len(surfaces.get("resilience", [])),
        },
        "normalized_fields": [
            "deadline",
            "timeout",
            "retry_count",
            "backoff",
            "queue_or_lease_ttl",
            "clock_domain",
            "cancellation",
            "breaker_state",
            "isolation_key",
        ],
        "fault_campaigns": [
            "slow_response",
            "partial_failure",
            "recovery_flapping",
            "malformed_result",
            "resource_exhaustion",
            "task_cancellation",
        ],
        "authority": "test_and_model_plan_not_observed_timing_or_control_effectiveness",
    }


def _guidance_specificity_program(diagnostics: dict[str, Any]) -> dict[str, Any]:
    guidance = diagnostics.get("guidance", {})
    missing = sorted(
        str(value) for value in guidance.get("rules_without_direct_mapping", [])
    )
    reused = guidance.get("broadly_reused_citations", {})
    closure = [
        {
            "rule_id": rule_id,
            "required_relationship": "direct_or_documented_not_applicable",
            "review_actions": [
                "map_direct",
                "supporting_only",
                "not_applicable",
                "needs_source",
            ],
        }
        for rule_id in missing
    ]
    return {
        "format": "pysfmea-guidance-specificity-program-1",
        "current_direct_percent": guidance.get("direct_finding_coverage_percent", 0.0),
        "closure_queue": closure,
        "overbroad_citations": [
            {"citation_id": str(key), "finding_count": int(value or 0)}
            for key, value in sorted(reused.items())
        ],
        "relationship_types": ["direct", "supporting", "contextual", "not_applicable"],
        "approval_gate": "independent_mapping_reviewer",
        "authority": "mapping_workflow_not_regulatory_applicability_or_compliance",
    }


def _performance_ratchet(analysis: dict[str, Any]) -> dict[str, Any]:
    settings = analysis.get("project", {}).get("settings", {})
    telemetry = settings.get("scan_telemetry", {})
    phases = telemetry.get("phases_seconds", {}) if isinstance(telemetry, dict) else {}
    current = (
        float(telemetry.get("total_seconds", 0.0) or 0.0)
        if isinstance(telemetry, dict)
        else 0.0
    )
    target = float(settings.get("target_cold_scan_seconds", 10) or 10)
    factor = min(1.0, target / current) if current else 1.0
    phase_targets = [
        {
            "phase": str(name),
            "current_seconds": float(seconds or 0.0),
            "target_seconds": round(float(seconds or 0.0) * factor, 6),
            "status": "gap"
            if current > target and float(seconds or 0.0) > 0
            else "met",
        }
        for name, seconds in sorted(
            phases.items(), key=lambda value: -float(value[1] or 0.0)
        )
    ]
    return {
        "format": "pysfmea-performance-ratchet-1",
        "current_total_seconds": current or None,
        "target_total_seconds": target,
        "status": "unmeasured"
        if not current
        else "met"
        if current <= target
        else "gap",
        "phase_targets": phase_targets,
        "optimization_order": [value["phase"] for value in phase_targets],
        "required_equivalence": [
            "canonical_analysis_state",
            "finding_ids_and_content",
            "call_and_interface_relations",
            "guidance_and_manifest_bindings",
        ],
        "benchmark_modes": ["clean", "cold_cache", "warm_cache", "incremental"],
        "authority": "performance_budget_requires_representative_repeatable_receipts",
    }


def _report_delivery_program(analysis: dict[str, Any]) -> dict[str, Any]:
    scale = _report_scale(analysis)
    return {
        "format": "pysfmea-report-delivery-program-1",
        "scale": scale,
        "modes": [
            {
                "id": "self_contained",
                "integrity": "embedded_payload_and_document_digest",
                "use": "portable review and archival",
            },
            {
                "id": "compact_companion",
                "integrity": "content_addressed_companion_json",
                "use": "large analyses and low-bandwidth delivery",
            },
            {
                "id": "management",
                "integrity": "state_bound_bounded_projection",
                "use": "decision summary with engineering appendix link",
            },
        ],
        "client_strategies": [
            "virtualized_tables",
            "deferred_diagrams",
            "indexed_search",
            "saved_filters",
            "role_profiles",
            "accessible_table_alternatives",
        ],
        "required_receipt_checks": [
            "integrity",
            "payload_size",
            "load_time",
            "dom_budget",
            "navigation",
            "responsive_layout",
            "accessibility",
            "console_and_page_errors",
        ],
        "authority": "delivery_modes_do_not_change_governed_analysis_or_review_authority",
    }


def _llm_governance_program() -> dict[str, Any]:
    return {
        "format": "pysfmea-llm-governance-program-1",
        "allowed_outputs": [
            "grounded_summary",
            "cluster_proposal",
            "cause_or_effect_proposal",
            "test_proposal",
            "control_gap_proposal",
        ],
        "required_claim_fields": [
            "claim",
            "evidence_ids",
            "citation_ids",
            "confidence",
            "limitations",
            "provider_model_prompt_subject",
        ],
        "mandatory_behaviors": [
            "abstain_when_evidence_is_missing_or_contradictory",
            "reject_unknown_evidence_or_citations",
            "invalidate_on_subject_or_analysis_drift",
            "retain_human_review_state_separately",
        ],
        "prohibited_authority": [
            "approve_finding",
            "approve_control",
            "credit_evidence",
            "set_residual_risk",
            "claim_compliance_or_qualification",
        ],
        "quality_metrics": [
            "groundedness",
            "citation_correctness",
            "failure_mode_recall",
            "unsupported_claim_rate",
            "abstention_correctness",
        ],
        "authority": "provider_neutral_review_assistance_not_engineering_authority",
    }


def _qualification_program() -> dict[str, Any]:
    return {
        "format": "pysfmea-qualification-program-1",
        "evidence_matrix": [
            "independent_repository_cohorts",
            "per_framework_and_rule_precision_recall",
            "python_runtime_and_os_differential_results",
            "chromium_firefox_webkit_receipts",
            "comprehensive_accessibility_receipts",
            "adversarial_repository_results",
            "signed_reproducible_release_bundle",
            "sbom_security_build_and_performance_receipts",
        ],
        "governance_decisions": [
            "plugin_sdk_compatibility_and_deprecation_policy",
            "service_threat_model_and_security_profile",
            "independent_release_approval",
        ],
        "migration_requirements": [
            "version_detection",
            "lossless_supported_upgrade",
            "downgrade_refusal_when_lossy",
            "before_and_after_digest_receipt",
        ],
        "authority": "qualification_plan_requires_independent_evidence_and_named_approval",
    }


def _evidence_preflight_plan(analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": "pysfmea-evidence-preflight-plan-1",
        "argv": [
            "sfmea",
            "enhance-evidence-preflight",
            "ANALYSIS",
            "REPOSITORY",
            "--output",
            ".artifacts/evidence-preflight.json",
        ],
        "analysis_binding": {
            "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", "")
        },
        "next_command": [
            "sfmea",
            "evidence-onboard",
            "ANALYSIS",
            "REPOSITORY",
            "--receipt",
            ".artifacts/evidence-onboarding-plan.json",
        ],
        "apply_requires": "explicit_--apply_and_distinct_analysis_receipt_queue_outputs",
        "authority": "inert_recipe_until_explicitly_run_against_an_authorized_repository",
    }


def _analysis_fidelity_program(
    analysis: dict[str, Any], surfaces: dict[str, Any]
) -> dict[str, Any]:
    items = _active_items(analysis)
    signals = Counter(
        str(signal)
        for item in items
        for signal in item.get("scanner", {}).get("signals", [])
    )
    unresolved = sum(
        bool(
            item.get("scanner", {}).get("upstream_path_analysis", {}).get("limitations")
        )
        for item in items
    )
    data_flow = analysis.get("interprocedural_data_flow", {})
    data_flow_summary = (
        data_flow.get("summary", {}) if isinstance(data_flow, dict) else {}
    )
    alias_flow = analysis.get("alias_object_flow", {})
    alias_flow_summary = (
        alias_flow.get("summary", {}) if isinstance(alias_flow, dict) else {}
    )
    concurrency = analysis.get("concurrency_model", {})
    concurrency_summary = (
        concurrency.get("summary", {}) if isinstance(concurrency, dict) else {}
    )
    exception_model = analysis.get("exception_propagation", {})
    exception_summary = (
        exception_model.get("summary", {}) if isinstance(exception_model, dict) else {}
    )
    state_model = analysis.get("state_machine_model", {})
    state_summary = (
        state_model.get("summary", {}) if isinstance(state_model, dict) else {}
    )
    resilience_model = analysis.get("resilience_semantics", {})
    resilience_summary = (
        resilience_model.get("summary", {})
        if isinstance(resilience_model, dict)
        else {}
    )
    authorization_model = analysis.get("authorization_scope_flow", {})
    authorization_summary = (
        authorization_model.get("summary", {})
        if isinstance(authorization_model, dict)
        else {}
    )
    contract_model = analysis.get("contract_semantics", {})
    contract_summary = (
        contract_model.get("summary", {}) if isinstance(contract_model, dict) else {}
    )
    deployment_model = analysis.get("deployment_topology", {})
    deployment_summary = (
        deployment_model.get("summary", {})
        if isinstance(deployment_model, dict)
        else {}
    )
    shared_fate_model = analysis.get("shared_fate_analysis", {})
    shared_fate_summary = (
        shared_fate_model.get("summary", {})
        if isinstance(shared_fate_model, dict)
        else {}
    )
    hierarchy_model = analysis.get("architecture_hierarchy", {})
    hierarchy_summary = (
        hierarchy_model.get("summary", {}) if isinstance(hierarchy_model, dict) else {}
    )
    return {
        "format": "pysfmea-analysis-fidelity-program-1",
        "capabilities": [
            "bounded_interprocedural_call_graph",
            "bounded_interprocedural_parameter_return_attribute_container_flow",
            "bounded_local_alias_and_object_flow_resolution",
            "bounded_task_spawn_join_cancel_synchronization_and_lexical_order_model",
            "framework_route_and_dependency_models",
            "bounded_openapi_asyncapi_protobuf_graphql_json_schema_avro_semantics_and_compatibility",
            "async_concurrency_and_cancellation_surfaces",
            "exception_and_masked_failure_candidates",
            "bounded_typed_raise_handler_and_interprocedural_exception_propagation",
            "state_transition_candidates",
            "bounded_guarded_state_assignment_and_state_node_model",
            "persistence_transaction_and_side_effect_surfaces",
            "bounded_compositional_transaction_effect_timing_retry_breaker_and_resource_semantics",
            "configuration_dependency_and_dynamic_wiring_inventory",
            "authorization_scope_and_common_cause_candidates",
            "bounded_identity_tenant_role_scope_credential_argument_flow_and_guard_model",
            "bounded_declared_deployment_topology_with_exact_artifact_provenance",
            "automatic_static_shared_fate_region_candidates",
            "deterministic_nested_architecture_and_upward_trace_inheritance",
            "explicit_bounded_path_limitations",
        ],
        "observations": {
            "active_findings": len(items),
            "signal_counts": dict(sorted(signals.items())),
            "unresolved_or_bounded_paths": unresolved,
            "surface_counts": {
                key: len(value)
                for key, value in surfaces.items()
                if isinstance(value, list)
            },
            "interprocedural_data_flow": data_flow_summary,
            "alias_object_flow": alias_flow_summary,
            "concurrency_model": concurrency_summary,
            "exception_propagation": exception_summary,
            "state_machine_model": state_summary,
            "resilience_semantics": resilience_summary,
            "authorization_scope_flow": authorization_summary,
            "contract_semantics": contract_summary,
            "deployment_topology": deployment_summary,
            "shared_fate_analysis": shared_fate_summary,
            "architecture_hierarchy": hierarchy_summary,
        },
        "non_claims": [
            "whole_program_soundness",
            "runtime_reachability",
            "path_feasibility",
            "complete_dynamic_dispatch_resolution",
            "whole_program_alias_or_taint_soundness",
            "complete_path_sensitive_happens_before_or_race_proof",
            "complete_runtime_exception_inheritance_or_path_proof",
            "formal_state_machine_reachability_liveness_or_completeness_proof",
            "runtime_atomicity_exactly_once_latency_breaker_effectiveness_or_resource_complexity_proof",
            "authorization_dominance_tenant_isolation_least_privilege_or_token_validity_proof",
            "runtime_serialization_generated_client_or_authoritative_version_policy_proof",
            "observed_runtime_deployment_routing_replicas_health_or_reachability_proof",
            "correlated_failure_probability_or_independence_proof",
            "project_architecture_approval_or_invented_trace_relationships",
        ],
        "authority": "bounded_static_models_not_whole_program_proof",
    }


def _sequence_sfta_program(analysis: dict[str, Any]) -> dict[str, Any]:
    sfta = analysis.get("sfta", {})
    trees = [value for value in sfta.get("trees", []) if isinstance(value, dict)]
    reconciliation = sfta.get("reconciliation", {})
    interface_sequences = analysis.get("interface_reconciliation", {}).get(
        "sequences", []
    )
    runtime = analysis.get("runtime_evidence", {})
    return {
        "format": "pysfmea-sequence-sfta-program-1",
        "static_sequences": len(interface_sequences),
        "runtime_edges": len(runtime.get("edges", [])),
        "trees": len(trees),
        "generated_placeholders": sum(
            value.get("source") == "generated_placeholder" for value in trees
        ),
        "reviewed_gate_trees": sum(bool(value.get("gates")) for value in trees),
        "approved_trees": sum(
            value.get("logic_status") == "approved_for_qualitative_cut_sets"
            for value in trees
        ),
        "cut_set_trees": sum(
            value.get("cut_set_analysis", {}).get("status") == "computed"
            for value in trees
        ),
        "qualitative_cut_sets": sum(
            int(value.get("cut_set_analysis", {}).get("cut_set_count", 0))
            for value in trees
        ),
        "reconciliation_summary": reconciliation.get("summary", {}),
        "supported_views": [
            "effect_propagation",
            "static_sequence",
            "runtime_overlay",
            "timing_and_resilience",
            "software_fault_tree",
            "barrier_and_control",
            "approved_tree_qualitative_minimal_cut_sets",
        ],
        "gate_policy": (
            "cut_sets_require_exact_authoring_approval_and_explicit_boolean_gates_and_are_never_inferred_from_call_reachability"
        ),
        "authority": "model_and_review_workflow_not_causal_sufficiency_or_hazard_completeness",
    }


def _assurance_automation_program(analysis: dict[str, Any]) -> dict[str, Any]:
    assurance = analysis.get("summary", {}).get("assurance", {})
    return {
        "format": "pysfmea-assurance-automation-program-1",
        "planned_methods": assurance.get("by_method", {}),
        "implemented_tests": int(assurance.get("implemented_tests", 0) or 0),
        "executions": int(assurance.get("executions", 0) or 0),
        "reviewed_executions": int(assurance.get("reviewed_executions", 0) or 0),
        "commands": [
            ["sfmea", "assurance", "ANALYSIS", "--format", "work-json"],
            ["sfmea", "assurance-scaffold", "ANALYSIS", "-o", "OUTPUT"],
            [
                "sfmea",
                "assurance-fault-plan",
                "ANALYSIS",
                "OBLIGATION",
                "-o",
                "fault-plan.json",
            ],
            [
                "sfmea",
                "assurance-evidence-import",
                "ANALYSIS",
                "OBLIGATION",
                "--manifest",
                "EVIDENCE",
                "--initiated-by",
                "IDENTITY",
            ],
        ],
        "test_families": [
            "unit",
            "property",
            "integration",
            "contract",
            "state_transition",
            "temporal_and_concurrency",
            "resilience_and_fault_injection",
            "security_negative",
        ],
        "synthesized_test_designs": {
            "property_tests": {
                "status": "implemented",
                "engine": "hypothesis",
                "inputs": "bounded_annotation_and_name_derived_strategies",
                "oracle_contract": "project_adapter_must_report_every_oracle_and_acceptance_criterion",
            },
            "contract_tests": {
                "status": "implemented",
                "cases": [
                    "conforming_exchange",
                    "missing_required_input",
                    "malformed_input",
                    "incompatible_response",
                    "declared_error_exchange",
                    "establish_contract_binding",
                ],
                "binding": "exact_contract_digest_candidate_mapping_requires_project_review",
            },
            "manifest_format": "pysfmea-pytest-assurance-scaffold-7",
            "authority": "executable_starting_points_not_project_test_implementation_or_evidence",
        },
        "closure_gate": (
            "reviewed_current_baseline_bound_execution_evidence_addressing_the_specific_failure_mode"
        ),
        "authority": "planning_and_bounded_execution_contract_not_automatic_finding_closure",
    }


def _architecture_interface_program(
    diagnostics: dict[str, Any], interface_program: dict[str, Any]
) -> dict[str, Any]:
    architecture = _architecture_program(diagnostics)
    return {
        "format": "pysfmea-architecture-interface-program-1",
        "architecture_traceability_percent": architecture.get(
            "current_traceability_percent", 0.0
        ),
        "mapping_proposals": len(architecture.get("proposals", [])),
        "interface_measurement_status": interface_program.get("measurement_status", ""),
        "interface_summary": interface_program.get("summary", {}),
        "workflows": [
            "hierarchical_architecture_mapping_review",
            "evidence_only_frontend_scope_preview",
            "server_and_client_route_disposition",
            "contract_backed_interface_reconciliation",
        ],
        "authority": "activation_workflows_require_named_mapping_and_interface_dispositions",
    }


def _projection_value(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _capability_attestations(
    workbench: dict[str, Any], register: list[dict[str, Any]]
) -> dict[str, Any]:
    source_by_domain = {
        "architecture": ["src/pysfmea/architecture.py", "tests/test_scanner.py"],
        "evidence": ["src/pysfmea/assurance.py", "tests/test_assurance.py"],
        "guidance": ["src/pysfmea/guidance.py", "tests/test_guidance.py"],
        "interfaces": [
            "src/pysfmea/interface_reconciliation.py",
            "tests/test_scanner.py",
        ],
        "performance": [
            "src/pysfmea/scan_cache.py",
            "tests/test_performance_benchmark.py",
        ],
        "reporting": ["src/pysfmea/html_report.py", "tests/test_html_report.py"],
        "review": ["src/pysfmea/server.py", "tests/test_server.py"],
        "qualification": ["src/pysfmea/program.py", "tests/test_program.py"],
    }
    attestations: list[dict[str, Any]] = []
    for value in register:
        projection = str(value.get("projection", ""))
        projection_present = _projection_value(workbench, projection) is not None
        authority_value = str(value.get("authority", "human_authority"))
        authority = cast(
            Authority,
            authority_value
            if authority_value in {"product", "project_evidence", "human_authority"}
            else "human_authority",
        )
        sources = source_by_domain.get(
            str(value.get("domain", "")),
            ["src/pysfmea/enhancements.py", "tests/test_enhancements.py"],
        )
        maturity_value = value.get("product_maturity")
        maturity = (
            cast(ProductMaturity, maturity_value)
            if maturity_value in {"planned", "partial", "implemented", "validated"}
            else None
        )
        implementation_evidence = value.get("implementation_evidence", sources)
        test_evidence = value.get("test_evidence", sources)
        limitations = value.get("known_limitations", [])
        expected_resolution = (
            _product_outcome_resolution_state(authority, maturity)
            if maturity is not None
            else ""
        )
        overclaim = (
            bool(expected_resolution)
            and value.get("resolution_state") != expected_resolution
        )
        if maturity == "validated":
            status = (
                "validated_capability_attested"
                if projection_present
                and implementation_evidence
                and test_evidence
                and value.get("representative_validation_evidence")
                and not overclaim
                else "product_evidence_missing"
            )
        elif maturity == "implemented":
            status = (
                "implemented_capability_attested"
                if projection_present
                and implementation_evidence
                and test_evidence
                and limitations
                and not overclaim
                else "product_evidence_missing"
            )
        elif maturity == "partial":
            status = (
                "partial_capability_disclosed"
                if projection_present
                and implementation_evidence
                and test_evidence
                and limitations
                and not overclaim
                else "product_evidence_missing"
            )
        elif maturity == "planned":
            status = (
                "planned_capability_disclosed"
                if projection_present
                and not implementation_evidence
                and not test_evidence
                and limitations
                and not overclaim
                else "product_evidence_missing"
            )
        else:
            status = (
                "product_projection_attested"
                if authority == "product" and projection_present
                else "product_projection_missing"
                if authority == "product"
                else "project_evidence_gate_attested"
                if authority == "project_evidence"
                else "human_authority_gate_attested"
            )
        attestations.append(
            {
                "id": str(value.get("id", "")),
                "title": str(value.get("title", "")),
                "projection": projection,
                "projection_present": projection_present,
                "product_maturity": maturity or "legacy_projection",
                "implementation_evidence": implementation_evidence,
                "test_evidence": test_evidence,
                "known_limitations": limitations,
                "acceptance_criterion": str(value.get("acceptance_criterion", "")),
                "authority": authority,
                "status": status,
                "overclaim": overclaim,
                "notice": (
                    "Maturity is explicitly curated and separately attested from projection "
                    "presence, project evidence, human approval, and qualification."
                    if maturity
                    else "Source and test references attest the product projection boundary, not project evidence or approval."
                ),
            }
        )
    counts = Counter(str(value["status"]) for value in attestations)
    return {
        "attestations": attestations,
        "status_counts": dict(sorted(counts.items())),
        "product_projection_gaps": sum(
            value["status"] == "product_projection_missing" for value in attestations
        ),
        "product_evidence_gaps": sum(
            value["status"] == "product_evidence_missing" for value in attestations
        ),
        "overclaim_gaps": sum(bool(value["overclaim"]) for value in attestations),
        "authority": "curated_product_maturity_attestation_not_independent_qualification",
    }


def _post_hardening_register() -> list[dict[str, Any]]:
    human_ids = {
        8,
        20,
        25,
        27,
        33,
        36,
        37,
        50,
        57,
        58,
        59,
        64,
        66,
        69,
        82,
    }
    project_ids = {
        15,
        16,
        18,
        19,
        21,
        22,
        23,
        24,
        26,
        28,
        30,
        35,
        39,
        40,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        62,
        67,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        81,
    }
    register: list[dict[str, Any]] = []
    for index, title in enumerate(POST_HARDENING_TITLES, 1):
        authority: Authority = (
            "human_authority"
            if index in human_ids
            else "project_evidence"
            if index in project_ids
            else "product"
        )
        projection = (
            "artifact_health"
            if index <= 10
            else "scope_patch"
            if index <= 20
            else "calibration_campaign"
            if index <= 30
            else "architecture_mapping_queue"
            if index <= 40
            else "evidence_portfolio"
            if index <= 50
            else "report_scale"
            if index <= 62
            else "guidance_queue"
            if index <= 69
            else "performance_plan"
            if index <= 75
            else "qualification_plan"
        )
        register.append(
            {
                "id": f"N{index:02d}",
                "priority": "P0"
                if index <= 30
                else "P1"
                if index <= 50
                else "P2"
                if index <= 69
                else "P3",
                "title": title,
                "authority": authority,
                "projection": projection,
                "product_resolution": f"Expose {title.casefold()} through the bounded {projection.replace('_', ' ')} projection and retain the governing authority boundary.",
                "acceptance_criterion": f"{title} has a versioned machine projection, deterministic counts, and no stronger claim than its bound evidence permits.",
                "resolution_state": (
                    "resolved_product_projection"
                    if authority == "product"
                    else "project_evidence_required"
                    if authority == "project_evidence"
                    else "human_decision_required"
                ),
            }
        )
    return register


def _next_generation_register() -> list[dict[str, Any]]:
    human_ids = {8, 10, 17, 18, 47, 63, 64, 99, 100, 101}
    project_ids = {22, 91, 93, 94, 95, 96, 97, 98}
    direct_projection = {
        1: "evidence_onboarding",
        2: "scope_preview",
        3: "review_campaign",
        4: "precision_program",
        5: "review_campaign",
        6: "review_clusters",
        7: "precision_program",
        8: "architecture_program",
        9: "interface_program",
        10: "interface_program",
        11: "guidance_specificity_program",
        12: "performance_ratchet",
        13: "report_delivery_program",
        14: "artifact_health",
    }
    register: list[dict[str, Any]] = []
    for index, title in enumerate(NEXT_GENERATION_TITLES, 1):
        authority: Authority = (
            "human_authority"
            if index in human_ids
            else "project_evidence"
            if index in project_ids
            else "product"
        )
        projection = direct_projection.get(
            index,
            "precision_program"
            if index <= 25
            else "evidence_onboarding"
            if index <= 37
            else "architecture_program"
            if index <= 48
            else "temporal_resilience_program"
            if index <= 57
            else "guidance_specificity_program"
            if index <= 65
            else "performance_ratchet"
            if index <= 70
            else "report_delivery_program"
            if index <= 84
            else "llm_governance_program"
            if index <= 92
            else "qualification_program",
        )
        state = (
            "resolved_product_capability"
            if authority == "product"
            else "project_evidence_required"
            if authority == "project_evidence"
            else "human_decision_required"
        )
        register.append(
            {
                "id": f"R{index:03d}",
                "priority": "P0" if index <= 14 else "P1" if index <= 65 else "P2",
                "title": title,
                "authority": authority,
                "projection": projection,
                "product_resolution": (
                    f"Operationalize {title.casefold()} through the versioned "
                    f"{projection.replace('_', ' ')} artifact with deterministic, bounded inputs."
                ),
                "acceptance_criterion": (
                    "The machine projection is present, deterministically regenerates from the "
                    "governed analysis, retains complete counts or omission accounting, and does "
                    "not claim evidence or approval outside its authority."
                ),
                "resolution_state": state,
            }
        )
    return register


def _product_outcome_maturity(index: int) -> ProductMaturity:
    if index in IMPLEMENTED_PRODUCT_OUTCOME_IDS:
        return "implemented"
    if index in PARTIAL_PRODUCT_OUTCOME_IDS:
        return "partial"
    if index in PLANNED_PRODUCT_OUTCOME_IDS:
        return "planned"
    raise RuntimeError(f"E{index:03d} has no explicit product-maturity decision")


def _product_outcome_evidence(index: int) -> tuple[list[str], list[str]]:
    for indices, implementation, tests in _OUTCOME_EVIDENCE_GROUPS:
        if index in indices:
            return list(implementation), list(tests)
    raise RuntimeError(f"E{index:03d} has no evidence group")


def _product_outcome_resolution_state(
    authority: Authority, maturity: ProductMaturity
) -> str:
    if authority == "project_evidence":
        return "project_evidence_required"
    if authority == "human_authority":
        return "human_decision_required"
    return {
        "planned": "planned_product_capability",
        "partial": "partial_product_capability",
        "implemented": "implemented_product_capability",
        "validated": "validated_product_capability",
    }[maturity]


def _product_outcome_register() -> list[dict[str, Any]]:
    """Return E001-E095 without deriving implementation from projection presence."""

    human_ids = {6, 13, 40, 41, 42, 53, 55, 59, 61, 62, 63, 66, 67, 87, 94, 95}
    evidence_ids = {4, 7, 8, 9, 10, 38, 44, 52, 54, 60, 69, 75, 83, 89, 90, 91, 92, 93}
    register: list[dict[str, Any]] = []
    for index, title in enumerate(PRODUCT_OUTCOME_TITLES, 1):
        authority: Authority = (
            "human_authority"
            if index in human_ids
            else "project_evidence"
            if index in evidence_ids
            else "product"
        )
        projection = (
            "evidence_preflight"
            if index <= 4
            else "review_campaign"
            if index <= 15
            else "analysis_fidelity_program"
            if index <= 35
            else "sequence_sfta_program"
            if index <= 44
            else "assurance_automation_program"
            if index <= 54
            else "guidance_specificity_program"
            if index <= 61
            else "architecture_interface_program"
            if index <= 67
            else "report_delivery_program"
            if index <= 75
            else "llm_governance_program"
            if index <= 83
            else "qualification_program"
        )
        maturity = _product_outcome_maturity(index)
        related_sources, related_tests = _product_outcome_evidence(index)
        limitation = (
            _PLANNED_OUTCOME_GAPS[index]
            if maturity == "planned"
            else _PARTIAL_OUTCOME_GAPS[index]
            if maturity == "partial"
            else (
                "Internal product tests demonstrate the bounded implementation; they do not "
                "constitute independent representative-repository qualification."
            )
        )
        implementation_evidence = related_sources if maturity != "planned" else []
        test_evidence = related_tests if maturity != "planned" else []
        maturity_basis = (
            "Executable source and focused regression tests exist for the bounded product "
            "behavior; independent representative validation is still a separate gate."
            if maturity == "implemented"
            else "Related executable behavior exists, but the named outcome remains materially incomplete."
            if maturity == "partial"
            else "Only related planning or prerequisite capabilities exist; no complete executable implementation is claimed."
        )
        next_action = (
            "Supply and govern the required repository evidence through the implemented workflow."
            if authority == "project_evidence" and maturity == "implemented"
            else "Record the required named engineering decision through the implemented workflow."
            if authority == "human_authority" and maturity == "implemented"
            else f"Close the disclosed capability gap: {limitation}"
            if maturity in {"planned", "partial"}
            else "Validate the implementation on an independent representative corpus before qualification credit."
        )
        register.append(
            {
                "id": f"E{index:03d}",
                "priority": "P0" if index <= 15 else "P1" if index <= 67 else "P2",
                "title": title,
                "authority": authority,
                "projection": projection,
                "product_resolution": (
                    f"{maturity.capitalize()} product support for {title.casefold()}; "
                    "repository evidence and authorized engineering decisions retain their "
                    "separate gates."
                ),
                "acceptance_criterion": (
                    "The named outcome may advance only when its specific executable behavior, "
                    "focused tests, known limitations, and any required representative evidence "
                    "or named approval are all present and independently reconcilable."
                ),
                "product_maturity": maturity,
                "maturity_basis": maturity_basis,
                "implementation_evidence": implementation_evidence,
                "test_evidence": test_evidence,
                "representative_validation_evidence": [],
                "related_evidence": sorted(set(related_sources + related_tests)),
                "known_limitations": [limitation],
                "next_action": next_action,
                "resolution_state": _product_outcome_resolution_state(
                    authority, maturity
                ),
            }
        )
    return register


def _outcome_scorecard(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    """Measure whether a target repository has realized product outcomes."""

    summary = analysis.get("summary", {})
    assurance = summary.get("assurance", {})
    items = _active_items(analysis)
    reviewed = sum(
        value.get("review", {}).get("disposition", "unreviewed") != "unreviewed"
        for value in items
    )
    rated = sum(
        all(
            value.get("review", {}).get(key) is not None
            for key in ("severity", "occurrence", "detection")
        )
        for value in items
    )
    sfta_trees = analysis.get("sfta", {}).get("trees", [])
    reviewed_sfta = sum(
        bool(value.get("gates") or value.get("events"))
        and value.get("source") != "generated_placeholder"
        for value in sfta_trees
        if isinstance(value, dict)
    )
    interfaces = diagnostics.get("interfaces", {}).get("summary", {})
    guidance = diagnostics.get("qualification", {}).get("domains", [])
    guidance_score = next(
        (
            float(value.get("score", 0.0) or 0.0)
            for value in guidance
            if value.get("id") == "guidance_specificity"
        ),
        0.0,
    )
    measures = [
        {
            "id": "reviewed_findings",
            "current": reviewed,
            "total": len(items),
            "status": "met" if reviewed == len(items) else "gap",
        },
        {
            "id": "fully_sod_rated",
            "current": rated,
            "total": len(items),
            "status": "met" if rated == len(items) else "gap",
        },
        {
            "id": "evidence_artifacts",
            "current": int(assurance.get("evidence_artifacts", 0) or 0),
            "target": 1,
            "status": "met" if assurance.get("evidence_artifacts") else "gap",
        },
        {
            "id": "reviewed_executions",
            "current": int(assurance.get("reviewed_executions", 0) or 0),
            "target": 1,
            "status": "met" if assurance.get("reviewed_executions") else "gap",
        },
        {
            "id": "runtime_imports",
            "current": int(summary.get("runtime_imports", 0) or 0),
            "target": 1,
            "status": "met" if summary.get("runtime_imports") else "gap",
        },
        {
            "id": "reviewed_sfta",
            "current": reviewed_sfta,
            "total": len(sfta_trees),
            "status": "met" if reviewed_sfta else "gap",
        },
        {
            "id": "cross_stack_matches",
            "current": int(interfaces.get("exact_matches", 0) or 0),
            "target": 1,
            "status": "met" if interfaces.get("exact_matches") else "unmeasured",
        },
        {
            "id": "guidance_specificity_percent",
            "current": guidance_score,
            "target": 95.0,
            "status": "met" if guidance_score >= 95 else "gap",
        },
    ]
    counts = Counter(str(value["status"]) for value in measures)
    return {
        "format": "pysfmea-product-outcome-scorecard-1",
        "measures": measures,
        "status_counts": dict(sorted(counts.items())),
        "next_actions": [value["id"] for value in measures if value["status"] != "met"],
        "authority": "measured_repository_state_not_product_completion_or_risk_acceptance",
    }


def _activation_progress(analysis: dict[str, Any]) -> dict[str, Any]:
    activation = analysis.get("activation", {})
    if not isinstance(activation, dict):
        activation = {}
    history = [
        value
        for value in activation.get("decision_history", [])
        if isinstance(value, dict)
    ]
    by_kind = Counter(str(value.get("kind", "unknown")) for value in history)
    return {
        "format": "pysfmea-activation-progress-1",
        "status": "active" if history else "not_started",
        "decisions": len(history),
        "decisions_by_kind": dict(sorted(by_kind.items())),
        "last_applied_at": str(activation.get("last_applied_at", "")),
        "last_workspace_sha256": str(activation.get("last_workspace_sha256", "")),
        "next_command": "sfmea activate-init ANALYSIS REPOSITORY -o .artifacts/activation.json",
        "authority": "governed_review_progress_not_closure_compliance_or_risk_acceptance",
    }


def _precision_risks(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    calibration = diagnostics.get("workload", {}).get("review_calibration", {})
    rules = [value for value in calibration.get("rules", []) if isinstance(value, dict)]
    insufficient: list[dict[str, Any]] = sorted(
        (
            {
                "rule_id": str(value.get("rule_id", "")),
                "findings": int(value.get("findings", 0) or 0),
                "reviewed": int(value.get("reviewed", 0) or 0),
                "acceptance_percent": value.get("acceptance_percent"),
                "rejection_percent": value.get("rejection_percent"),
                "status": str(value.get("calibration_status", "unreviewed")),
            }
            for value in rules
            if int(value.get("reviewed", 0) or 0) < 5
        ),
        key=lambda value: (-int(value["findings"]), str(value["rule_id"])),
    )
    mapping_candidates = diagnostics.get("evidence", {}).get(
        "architecture_mapping_candidates", []
    )
    mapping_confidence = Counter(
        str(value.get("confidence", "unclassified"))
        for value in mapping_candidates
        if isinstance(value, dict)
    )
    interfaces = diagnostics.get("interfaces", {}).get("summary", {})
    active_findings = int(
        diagnostics.get("workload", {}).get("active_findings", 0) or 0
    )
    top_count = int(insufficient[0]["findings"]) if insufficient else 0
    contracts = analysis.get("interface_contracts", {})
    contract_count = (
        int(contracts.get("summary", {}).get("contracts", 0) or 0)
        if isinstance(contracts, dict)
        else 0
    )
    return {
        "minimum_observed_review_sample": 5,
        "insufficiently_calibrated_rules": insufficient[:50],
        "insufficiently_calibrated_rules_omitted": max(0, len(insufficient) - 50),
        "largest_uncalibrated_rule_share_percent": (
            round(100 * top_count / active_findings, 1) if active_findings else 0.0
        ),
        "architecture_proposal_confidence": dict(sorted(mapping_confidence.items())),
        "unmatched_client_endpoints": int(
            interfaces.get("unmatched_client_endpoints", 0) or 0
        ),
        "unmatched_server_routes": int(
            interfaces.get("unmatched_server_routes", 0) or 0
        ),
        "interface_contracts": contract_count,
        "risks": [
            "Human disposition statistics are observational and cannot tune rules automatically.",
            "Static call and surface candidates do not prove path feasibility or runtime reachability.",
            "Proximity-based architecture proposals require named review.",
            "Unmatched interfaces require disposition before they can be treated as defects or dead code.",
        ],
        "authority": "precision_risk_projection_not_validation_or_ground_truth",
    }


def _acceptance_targets(
    analysis: dict[str, Any], diagnostics: dict[str, Any]
) -> dict[str, Any]:
    settings = analysis.get("project", {}).get("settings", {})
    domains = {
        str(value.get("id", "")): float(value.get("score", 0.0) or 0.0)
        for value in diagnostics.get("qualification", {}).get("domains", [])
        if isinstance(value, dict)
    }
    telemetry = (
        analysis.get("project", {}).get("settings", {}).get("scan_telemetry", {})
    )
    total_seconds = (
        float(telemetry.get("total_seconds", 0.0) or 0.0)
        if isinstance(telemetry, dict)
        else 0.0
    )

    def score_target(
        identifier: str, label: str, domain: str, target: float
    ) -> dict[str, Any]:
        current = domains.get(domain, 0.0)
        return {
            "id": identifier,
            "label": label,
            "current": current,
            "target": target,
            "unit": "percent",
            "comparison": "at_least",
            "status": "met" if current >= target else "gap",
        }

    cross_stack_target = score_target(
        "cross-stack",
        "Client endpoint reconciliation",
        "cross_stack_interfaces",
        float(settings.get("target_cross_stack_percent", 90) or 90),
    )
    hidden_web_scope = any(
        isinstance(value, dict)
        and value.get("kind") == "web_boundary_hidden_by_semantic_exclusion"
        for value in diagnostics.get("evidence_scope", {}).get("conflicts", [])
    )
    if hidden_web_scope:
        cross_stack_target.update(
            {
                "current": None,
                "status": "unmeasured",
                "reason": "Configured semantic exclusions hide the web boundary; review the proposed evidence-only include before scoring reconciliation.",
            }
        )
    targets = [
        score_target(
            "evidence-readiness",
            "Corroborating evidence readiness",
            "corroborating_evidence",
            float(settings.get("target_evidence_readiness_percent", 70) or 70),
        ),
        score_target(
            "architecture-traceability",
            "Governed architecture traceability",
            "architecture_traceability",
            float(settings.get("target_architecture_traceability_percent", 90) or 90),
        ),
        cross_stack_target,
        score_target(
            "guidance-specificity",
            "Direct guidance specificity",
            "guidance_specificity",
            float(settings.get("target_guidance_specificity_percent", 95) or 95),
        ),
        {
            "id": "scan-runtime",
            "label": "Representative cold scan runtime",
            "current": total_seconds if total_seconds else None,
            "target": float(settings.get("target_cold_scan_seconds", 10) or 10),
            "unit": "seconds",
            "comparison": "at_most",
            "status": "unmeasured"
            if not total_seconds
            else "met"
            if total_seconds
            <= float(settings.get("target_cold_scan_seconds", 10) or 10)
            else "gap",
        },
    ]
    return {
        "targets": targets,
        "met": sum(value["status"] == "met" for value in targets),
        "gaps": sum(value["status"] == "gap" for value in targets),
        "unmeasured": sum(value["status"] == "unmeasured" for value in targets),
        "authority": "proposed_product_targets_require_approved_representative_evidence",
    }


def _bounded_sfta_queue(reconciliation: Any) -> dict[str, Any]:
    if not isinstance(reconciliation, dict):
        reconciliation = {}
    projected: dict[str, Any] = {
        "summary": reconciliation.get("summary", {}),
        "authority": "bounded_reconciliation_queue_not_fault_tree_approval",
    }
    for key in (
        "finding_to_events",
        "top_down_uncovered_events",
        "bottom_up_unmapped_findings",
        "hazard_link_mismatches",
    ):
        values = reconciliation.get(key, [])
        values = values if isinstance(values, list) else []
        projected[key] = values[:MAX_DISPOSITION_RECORDS]
        projected[f"{key}_omitted"] = max(0, len(values) - MAX_DISPOSITION_RECORDS)
    return projected


def enhancement_workbench(
    analysis: dict[str, Any], *, diagnostics: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a bounded activation plan spanning the complete enhancement register."""

    diagnostics = diagnostics or analysis_diagnostics(analysis)
    items = _active_items(analysis)
    clusters = _review_clusters(items)
    portfolio = _evidence_portfolio(analysis, items)
    surfaces = _component_surface_models(analysis)
    mapping_candidates = diagnostics.get("evidence", {}).get(
        "architecture_mapping_candidates", []
    )
    sfta = _bounded_sfta_queue(analysis.get("sfta", {}).get("reconciliation", {}))
    guidance = analysis.get("guidance", {})
    register = _capability_register(analysis)
    hardening = _hardening_register(analysis, diagnostics)
    post_hardening = _post_hardening_register()
    next_generation = _next_generation_register()
    product_outcomes = _product_outcome_register()
    hardening_status_counts = Counter(value["resolution_state"] for value in hardening)
    post_status_counts = Counter(value["resolution_state"] for value in post_hardening)
    next_status_counts = Counter(value["resolution_state"] for value in next_generation)
    outcome_status_counts = Counter(
        value["resolution_state"] for value in product_outcomes
    )
    outcome_maturity_counts = Counter(
        value["product_maturity"] for value in product_outcomes
    )
    status_counts = Counter(value["status"] for value in register)
    artifact_health = _artifact_health(analysis, diagnostics)
    scope_patch = _scope_patch(diagnostics)
    calibration = _calibration_campaign(diagnostics)
    review_campaign = _review_campaign(items, clusters, diagnostics, calibration)
    evidence_onboarding = _evidence_onboarding_program(
        analysis, diagnostics, artifact_health
    )
    precision_program = _precision_program(items, diagnostics)
    architecture_program = _architecture_program(diagnostics)
    interface_program = _interface_program(analysis, diagnostics, scope_patch)
    temporal_program = _temporal_resilience_program(items, surfaces)
    material = {
        "format": ENHANCEMENT_WORKBENCH_FORMAT,
        "analysis_binding": {
            "baseline_id": analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "repository_sha256": analysis.get("project", {})
            .get("baseline", {})
            .get("repository_sha256", ""),
        },
        "summary": {
            "enhancements": len(register),
            "capability_statuses": dict(sorted(status_counts.items())),
            "hardening_items": len(hardening),
            "hardening_statuses": dict(sorted(hardening_status_counts.items())),
            "post_hardening_items": len(post_hardening),
            "post_hardening_statuses": dict(sorted(post_status_counts.items())),
            "next_generation_items": len(next_generation),
            "next_generation_statuses": dict(sorted(next_status_counts.items())),
            "product_outcome_items": len(product_outcomes),
            "product_outcome_statuses": dict(sorted(outcome_status_counts.items())),
            "product_outcome_maturity": {
                maturity: int(outcome_maturity_counts.get(maturity, 0))
                for maturity in PRODUCT_OUTCOME_MATURITIES
            },
            "active_findings": len(items),
            "review_clusters": len(clusters),
            "cluster_reduction_percent": round(
                100 * (len(items) - len(clusters)) / len(items), 1
            )
            if items
            else 100.0,
            "portfolio_groups": len(portfolio),
            "architecture_mapping_candidates": len(mapping_candidates),
            "unmatched_client_endpoints": diagnostics.get("interfaces", {})
            .get("summary", {})
            .get("unmatched_client_endpoints", 0),
            "unmatched_server_routes": diagnostics.get("interfaces", {})
            .get("summary", {})
            .get("unmatched_server_routes", 0),
        },
        "capability_register": register,
        "hardening_register": hardening,
        "post_hardening_register": post_hardening,
        "next_generation_register": next_generation,
        "product_outcome_register": product_outcomes,
        "artifact_freshness": _artifact_freshness(analysis),
        "artifact_health": artifact_health,
        "scope_patch": scope_patch,
        "scope_preview": _scope_preview_plan(scope_patch),
        "evidence_preflight": _evidence_preflight_plan(analysis),
        "calibration_campaign": calibration,
        "review_campaign": review_campaign,
        "finding_consolidation_program": _finding_consolidation_program(
            analysis, clusters
        ),
        "evidence_onboarding": evidence_onboarding,
        "precision_program": precision_program,
        "architecture_program": architecture_program,
        "interface_program": interface_program,
        "temporal_resilience_program": temporal_program,
        "guidance_specificity_program": _guidance_specificity_program(diagnostics),
        "performance_ratchet": _performance_ratchet(analysis),
        "report_delivery_program": _report_delivery_program(analysis),
        "llm_governance_program": _llm_governance_program(),
        "qualification_program": _qualification_program(),
        "analysis_fidelity_program": _analysis_fidelity_program(analysis, surfaces),
        "sequence_sfta_program": _sequence_sfta_program(analysis),
        "assurance_automation_program": _assurance_automation_program(analysis),
        "architecture_interface_program": _architecture_interface_program(
            diagnostics, interface_program
        ),
        "product_outcome_scorecard": _outcome_scorecard(analysis, diagnostics),
        "activation_progress": _activation_progress(analysis),
        "metric_provenance": _metric_provenance(analysis, diagnostics),
        "report_scale": _report_scale(analysis),
        "precision_risks": _precision_risks(analysis, diagnostics),
        "acceptance_targets": _acceptance_targets(analysis, diagnostics),
        "evidence_acquisition": _evidence_acquisition(analysis, diagnostics),
        "review_clusters": clusters,
        "review_clusters_omitted": max(
            0, len(items) - sum(int(value["finding_count"]) for value in clusters)
        ),
        "evidence_portfolio": portfolio,
        "architecture_mapping_queue": {
            "proposals": mapping_candidates,
            "proposals_omitted": diagnostics.get("evidence", {}).get(
                "architecture_mapping_candidates_omitted", 0
            ),
            "authority": "reviewer_confirmation_required",
        },
        "interface_disposition_queue": _interface_queue(analysis),
        "surface_models": surfaces,
        "evidence_quality": {
            "assurance": diagnostics.get("evidence", {}).get("assurance", {}),
            "runtime_imports": diagnostics.get("evidence", {}).get(
                "runtime_imports", 0
            ),
            "coverage_percent": diagnostics.get("evidence", {}).get(
                "coverage_evidence_percent", 0.0
            ),
            "test_reference_percent": diagnostics.get("evidence", {}).get(
                "test_reference_coverage_percent", 0.0
            ),
            "authority": "diagnostic_inputs_not_evidence_sufficiency_or_control_credit",
        },
        "sfta_queue": sfta,
        "guidance_queue": {
            "traceability": guidance.get("traceability", {}),
            "applicability": guidance.get("applicability", []),
            "notice": "Citation presence is not applicability, compliance, or an accepted finding relationship.",
        },
        "change_review": {
            "source_changes": dict(
                sorted(
                    Counter(
                        str(value.get("source_change", "unknown")) for value in items
                    ).items()
                )
            ),
            "revalidation_required": sum(
                bool(value.get("review", {}).get("revalidation_required"))
                for value in items
            ),
        },
        "review_analytics": diagnostics.get("workload", {}),
        "performance_plan": {
            "telemetry": analysis.get("project", {})
            .get("settings", {})
            .get("scan_telemetry", {}),
            "cache": analysis.get("run_manifest", {}).get("cache", {}),
            "next_gate": "Compare clean, cold-cache, warm-cache, and differential outputs for semantic equivalence and phase budgets.",
        },
        "qualification_plan": {
            "required_evidence": [
                "independently labelled representative validation cohorts",
                "multi-version parser and schema compatibility results",
                "adversarial bounded-ingestion corpus results",
                "cold and warm performance receipts",
                "coverage, mutation, security, dependency, build, and browser receipts",
                "signed release artifacts, SBOM, requirements traceability, and known limitations",
            ],
            "authority": "qualification_and_compliance_require_independent_human_authority",
        },
        "budgets": {
            "cluster_members": MAX_CLUSTER_MEMBERS,
            "clusters": MAX_CLUSTERS,
            "portfolio_groups": MAX_PORTFOLIO_GROUPS,
            "surface_records_per_category": MAX_SURFACE_RECORDS,
            "disposition_records_per_side": MAX_DISPOSITION_RECORDS,
        },
        "guardrails": [
            "Repository commands are inert argv recipes until explicitly run in an approved sandbox.",
            "Static surface and interface candidates are review leads, not runtime reachability or defects.",
            "Representative clusters do not apply one disposition to every member.",
            "Mapping, SFTA, guidance applicability, severity, evidence sufficiency, waiver, qualification, and residual-risk decisions require named human authority.",
            "LLM suggestions cannot approve findings, controls, evidence, risk, or compliance.",
            "Calibration and reviewer statistics cannot automatically tune, suppress, or approve scanner rules.",
            "Performance changes require exact semantic-equivalence receipts before release credit.",
            "A planning projection never establishes implementation maturity; each E-item carries an explicit evidence-backed maturity and limitation.",
        ],
    }
    material["capability_attestations"] = _capability_attestations(material, hardening)
    material["resolution_attestations"] = _capability_attestations(
        material, next_generation
    )
    material["product_outcome_attestations"] = _capability_attestations(
        material, product_outcomes
    )
    material["content_sha256"] = hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    return material


def enhancement_workbench_markdown(workbench: dict[str, Any]) -> str:
    """Render the bounded workbench summary without weakening the JSON authority."""

    summary = workbench.get("summary", {})
    lines = [
        "# PySFMEA enhancement workbench",
        "",
        f"- Enhancements accounted for: {summary.get('enhancements', 0)}",
        f"- Real-repository hardening items accounted for: {summary.get('hardening_items', 0)}",
        f"- Post-hardening audit items accounted for: {summary.get('post_hardening_items', 0)}",
        f"- Real-run recommendations accounted for: {summary.get('next_generation_items', 0)}",
        f"- Product outcomes maturity-assessed: {summary.get('product_outcome_items', 0)}",
        (
            "- Product maturity: "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(
                    summary.get("product_outcome_maturity", {}).items()
                )
            )
        ),
        f"- Artifact health: {workbench.get('artifact_health', {}).get('overall_status', 'unknown')}",
        f"- Active findings: {summary.get('active_findings', 0)}",
        f"- Root-cause review clusters: {summary.get('review_clusters', 0)}",
        f"- Estimated clustering reduction: {summary.get('cluster_reduction_percent', 0)}%",
        f"- Prioritized evidence portfolio groups: {summary.get('portfolio_groups', 0)}",
        "",
        "## Evidence acquisition",
        "",
    ]
    for step in workbench.get("evidence_acquisition", {}).get("steps", []):
        lines.extend(
            [
                f"- **{step.get('priority')} · {step.get('id')}** — {step.get('reason')}",
                f"  - `{' '.join(step.get('argv', []))}`",
            ]
        )
    lines.extend(["", "## Highest-value review clusters", ""])
    for value in workbench.get("review_clusters", [])[:25]:
        lines.append(
            f"- `{value.get('id')}` — {value.get('finding_count')} findings · "
            f"{value.get('rule_id')} · {value.get('source_area')}"
        )
    lines.extend(["", "## Hardening resolution register", ""])
    for value in workbench.get("hardening_register", []):
        lines.append(
            f"- **{value.get('id')} · {value.get('title')}** — "
            f"{value.get('resolution_state')}"
        )
        lines.append(f"  - Acceptance: {value.get('acceptance_criterion')}")
    lines.extend(["", "## Post-hardening resolution register", ""])
    for value in workbench.get("post_hardening_register", []):
        lines.append(
            f"- **{value.get('id')} · {value.get('title')}** — "
            f"{value.get('resolution_state')}"
        )
    lines.extend(["", "## Real-run resolution register", ""])
    for value in workbench.get("next_generation_register", []):
        lines.append(
            f"- **{value.get('id')} - {value.get('title')}** - "
            f"{value.get('resolution_state')}"
        )
    lines.extend(["", "## Product-outcome resolution register", ""])
    for value in workbench.get("product_outcome_register", []):
        lines.append(
            f"- **{value.get('id')} - {value.get('title')}** - "
            f"{value.get('product_maturity')} / {value.get('resolution_state')}"
        )
        lines.append(f"  - Limitation: {' '.join(value.get('known_limitations', []))}")
        lines.append(f"  - Next: {value.get('next_action')}")
    lines.extend(["", "## Guardrails", ""])
    lines.extend(f"- {value}" for value in workbench.get("guardrails", []))
    return "\n".join(lines) + "\n"


def export_enhancement_workbench(
    analysis: dict[str, Any], destination: str | Path, *, output_format: str = "json"
) -> Path:
    """Atomically publish one enhancement-workbench projection."""

    workbench = enhancement_workbench(analysis)
    if output_format == "json":
        rendered = json.dumps(workbench, indent=2, ensure_ascii=False) + "\n"
    elif output_format == "markdown":
        rendered = enhancement_workbench_markdown(workbench)
    else:
        raise ValueError("enhancement workbench format must be json or markdown")
    return atomic_publish_text(destination, rendered, label="enhancement workbench")


def verify_enhancement_workbench_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify a bounded workbench internally and optionally against exact analysis state."""

    findings: list[dict[str, str]] = []
    checks: dict[str, bool] = {}

    def check(name: str, passed: bool, code: str, message: str) -> None:
        checks[name] = passed
        if not passed:
            findings.append({"code": code, "message": message})

    try:
        document = load_bounded_json_document(
            source,
            label="enhancement workbench",
            max_bytes=MAX_WORKBENCH_BYTES,
            max_depth=MAX_WORKBENCH_JSON_DEPTH,
            max_nodes=MAX_WORKBENCH_JSON_NODES,
        )
    except ValueError as exc:
        return {
            "format": ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "source": str(Path(source).absolute()),
            "source_bytes": 0,
            "source_sha256": "",
            "analysis_checked": analysis is not None,
            "checks": {"bounded_ingestion": False},
            "findings": [
                {
                    "code": "workbench.ingestion_failed",
                    "message": str(exc),
                }
            ],
        }
    value = document.value
    shape_valid = isinstance(value, dict)
    check(
        "object_shape",
        shape_valid,
        "workbench.invalid_shape",
        "The enhancement workbench root must be an object.",
    )
    if not shape_valid or not isinstance(value, dict):
        return {
            "format": ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "source": str(document.path),
            "source_bytes": document.size,
            "source_sha256": hashlib.sha256(document.raw).hexdigest(),
            "analysis_checked": analysis is not None,
            "checks": checks,
            "findings": findings,
        }
    check(
        "format",
        value.get("format") == ENHANCEMENT_WORKBENCH_FORMAT,
        "workbench.unsupported_format",
        "The workbench uses an unsupported format.",
    )
    supplied_digest = value.get("content_sha256")
    canonical = dict(value)
    canonical.pop("content_sha256", None)
    check(
        "content_integrity",
        isinstance(supplied_digest, str)
        and len(supplied_digest) == 64
        and supplied_digest == canonical_json_sha256(canonical),
        "workbench.content_digest_mismatch",
        "The workbench content does not match its declared SHA-256 digest.",
    )
    expected_registers = {
        "capability_register": len(ENHANCEMENT_SPECS),
        "hardening_register": len(HARDENING_SPECS),
        "post_hardening_register": len(POST_HARDENING_TITLES),
        "next_generation_register": len(NEXT_GENERATION_TITLES),
        "product_outcome_register": len(PRODUCT_OUTCOME_TITLES),
    }
    for register_name, expected_count in expected_registers.items():
        register = value.get(register_name)
        ids = (
            [str(entry.get("id", "")) for entry in register if isinstance(entry, dict)]
            if isinstance(register, list)
            else []
        )
        check(
            f"{register_name}_complete",
            isinstance(register, list)
            and len(register) == expected_count
            and len(ids) == len(set(ids))
            and all(ids),
            "workbench.register_incomplete",
            f"{register_name} must contain {expected_count} unique identified records.",
        )
    expected_outcomes = _product_outcome_register()
    supplied_outcomes = value.get("product_outcome_register")
    check(
        "product_outcome_semantics",
        supplied_outcomes == expected_outcomes,
        "workbench.product_outcome_semantics_mismatch",
        (
            "The E001-E095 register must exactly match the curated product maturity, "
            "authority, evidence, limitations, and next actions."
        ),
    )
    expected_maturity_counter = Counter(
        entry["product_maturity"] for entry in expected_outcomes
    )
    expected_maturity_counts = {
        maturity: int(expected_maturity_counter.get(maturity, 0))
        for maturity in PRODUCT_OUTCOME_MATURITIES
    }
    supplied_summary = value.get("summary")
    check(
        "product_outcome_summary",
        isinstance(supplied_summary, dict)
        and supplied_summary.get("product_outcome_maturity")
        == expected_maturity_counts,
        "workbench.product_outcome_summary_mismatch",
        "The product-outcome maturity summary does not reconcile to E001-E095.",
    )
    expected_outcome_attestations = _capability_attestations(value, expected_outcomes)
    check(
        "product_outcome_attestations",
        value.get("product_outcome_attestations") == expected_outcome_attestations
        and expected_outcome_attestations.get("product_evidence_gaps") == 0
        and expected_outcome_attestations.get("overclaim_gaps") == 0,
        "workbench.product_outcome_attestation_mismatch",
        (
            "Product-outcome attestations must reconcile projection presence to explicit "
            "maturity evidence without an overclaim."
        ),
    )
    if analysis is not None:
        expected = enhancement_workbench(analysis)
        check(
            "analysis_binding",
            value.get("analysis_binding") == expected.get("analysis_binding"),
            "workbench.analysis_binding_mismatch",
            "The workbench baseline binding differs from the supplied analysis.",
        )
        check(
            "analysis_state_binding",
            value.get("artifact_health", {})
            .get("freshness", {})
            .get("analysis_state_sha256")
            == canonical_json_sha256(analysis),
            "workbench.analysis_state_mismatch",
            "The workbench analysis-state digest differs from the supplied analysis.",
        )
        check(
            "exact_regeneration",
            value.get("content_sha256") == expected.get("content_sha256"),
            "workbench.regeneration_mismatch",
            "The workbench does not exactly regenerate from the supplied analysis.",
        )
    valid = all(checks.values())
    return {
        "format": ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT,
        "valid": valid,
        "status": (
            "matched"
            if valid and analysis is not None
            else "internally_valid"
            if valid
            else "invalid"
        ),
        "source": str(document.path),
        "source_bytes": document.size,
        "source_sha256": hashlib.sha256(document.raw).hexdigest(),
        "analysis_checked": analysis is not None,
        "checks": checks,
        "findings": findings,
    }

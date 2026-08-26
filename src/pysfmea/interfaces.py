"""Stable typed interfaces shared by PySFMEA subsystems.

The runtime analysis document remains JSON-compatible and versioned by its public
schema.  These narrow interfaces provide an internal compatibility seam so large
scanner, assurance, execution, and reporting modules do not need to depend on one
another's implementation details.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol, TypedDict, runtime_checkable

JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class SourceLocation(TypedDict, total=False):
    path: str
    line_start: int
    line_end: int


class ComponentReference(TypedDict, total=False):
    id: str
    qualname: str
    kind: str


class AutomationContract(TypedDict, total=False):
    framework: str
    proposed_test_path: str
    proposed_test_name: str
    command_argv: list[str]
    implementation_status: str
    execution_policy: str
    network_policy: str
    implemented_test_path: str
    test_sha256: str
    implementation_origin: str
    implemented_by: str
    implemented_at: str
    fault_injection_plugins: list[str]


class AssuranceObligation(TypedDict, total=False):
    id: str
    finding_id: str
    component_id: str
    source_status: str
    baseline_id: str
    source_fingerprint: str
    rule_id: str
    failure_class: str
    priority: str
    component: str
    source: SourceLocation
    title: str
    objective: str
    failure_condition: str
    detected_control_model: dict[str, Any] | None
    control_review_questions: list[str]
    cascade_context: dict[str, Any]
    operational_context: dict[str, Any]
    preconditions: list[str]
    stimulus: dict[str, Any]
    expected_results: dict[str, Any]
    oracles: list[str]
    verification_method: str
    method_rationale: str
    acceptance_criteria: list[str]
    required_environment: list[str]
    repeatability: dict[str, Any]
    planning_gaps: list[str]
    automation: AutomationContract
    existing_test_candidates: list[str]
    evidence_requirements: list[str]
    citation_ids: list[str]
    assurance_status: str
    evidence_status: str
    evidence_artifact_ids: list[str]
    executions: list[str]
    review: dict[str, Any]
    provenance: dict[str, Any]
    history: list[dict[str, Any]]


class AssuranceRegister(TypedDict, total=False):
    schema_version: str
    planner_version: str
    baseline_id: str
    generated_at: str
    notice: str
    obligations: list[AssuranceObligation]
    executions: list[dict[str, Any]]
    evidence_artifacts: list[dict[str, Any]]
    summary: dict[str, Any]


class FindingRecord(TypedDict, total=False):
    id: str
    component_id: str
    component: ComponentReference
    source: SourceLocation
    source_status: str
    scanner: dict[str, Any]
    review: dict[str, Any]


class AnalysisDocument(TypedDict, total=False):
    schema_version: str
    project: dict[str, Any]
    items: list[FindingRecord]
    assurance: AssuranceRegister
    history: list[dict[str, Any]]
    summary: dict[str, Any]


FaultOutcome = Literal["returns", "raises"]


class FaultObservation(TypedDict, total=False):
    outcome: FaultOutcome
    value: JSONValue
    exception_type: str
    message: str
    elapsed_ms: float


class FaultInjectionResult(TypedDict):
    plugin_id: str
    stimulus_observed: bool
    patch_calls: int
    observations: list[FaultObservation]


@runtime_checkable
class FaultInjectionPlugin(Protocol):
    """Executable fault plugin contract used only by explicit test code."""

    @property
    def id(self) -> str:
        """Stable plugin identifier."""

    @property
    def version(self) -> str:
        """Plugin contract version."""

    @property
    def title(self) -> str:
        """Human-readable plugin title."""

    @property
    def fault_kinds(self) -> tuple[str, ...]:
        """Supported fault stimulus categories."""

    def validate(self, case: Mapping[str, Any]) -> None:
        """Reject an unsafe or incomplete explicit case."""

    def execute(self, case: Mapping[str, Any]) -> FaultInjectionResult:
        """Execute an explicitly bound case and return observed evidence facts."""


@runtime_checkable
class SuggestionProviderContract(Protocol):
    """Stable provider seam for optional model-assisted operations."""

    name: str
    model: str

    def generate(self, payload: Mapping[str, Any], *, task: str) -> Mapping[str, Any]:
        """Return one provider result for a closed, task-specific payload."""


@runtime_checkable
class ArtifactPublisher(Protocol):
    """Minimal publication seam for deterministic encoded artifacts."""

    def publish(self, content: bytes, destination: str) -> Mapping[str, Any]:
        """Publish bytes and return a machine-readable receipt."""


def text_sequence(value: object) -> Sequence[str]:
    """Return a read-only string sequence without accepting scalar strings."""

    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if item not in (None, ""))

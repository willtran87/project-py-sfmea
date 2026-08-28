"""PySFMEA: a reviewable Software FMEA starter for Python repositories."""

from .activation import (
    activation_records_template,
    activation_workspace,
    apply_activation_workspace,
    import_activation_records,
    record_activation_assignment,
    record_activation_decision,
    test_attribution,
    verify_activation_workspace_file,
)
from .assurance_case import assurance_case, verify_assurance_case_file
from .browser_quality import (
    bind_browser_quality_receipt,
    verify_browser_quality_receipt,
    verify_browser_quality_receipt_file,
)
from .configuration_authoring import (
    apply_configuration_authoring,
    configuration_authoring_draft,
    verify_configuration_authoring_file,
)
from .conformance import (
    assess_objective,
    conformance_workspace,
    standards_catalog,
    verify_conformance_workspace_file,
)
from .enhancements import (
    enhancement_scope_preview,
    enhancement_workbench,
    evidence_preflight,
    verify_enhancement_workbench_file,
)
from .evidence_onboarding import (
    onboard_evidence,
    verify_evidence_onboarding_receipt,
    verify_evidence_onboarding_receipt_file,
)
from .qualification import (
    build_qualification_campaign,
    load_qualification_campaign_manifest,
    load_qualification_campaign_result,
    qualification_validation_cohorts,
    verify_qualification_campaign,
    verify_qualification_campaign_file,
)
from .qualification_report import (
    export_qualification_report,
    verify_qualification_report_file,
)
from .scanner import scan_repository
from .sfta_authoring import (
    apply_sfta_authoring,
    sfta_authoring_draft,
    verify_sfta_authoring_file,
)
from .slsa import slsa_provenance_statement, verify_slsa_provenance_file
from .synthesis import (
    verify_synthesis_apply_receipt,
    verify_synthesis_apply_receipt_file,
)
from .version import __version__

__all__ = [
    "__version__",
    "activation_workspace",
    "assurance_case",
    "activation_records_template",
    "apply_activation_workspace",
    "apply_configuration_authoring",
    "assess_objective",
    "apply_sfta_authoring",
    "bind_browser_quality_receipt",
    "build_qualification_campaign",
    "evidence_preflight",
    "export_qualification_report",
    "onboard_evidence",
    "configuration_authoring_draft",
    "conformance_workspace",
    "import_activation_records",
    "load_qualification_campaign_manifest",
    "load_qualification_campaign_result",
    "qualification_validation_cohorts",
    "enhancement_workbench",
    "enhancement_scope_preview",
    "scan_repository",
    "slsa_provenance_statement",
    "standards_catalog",
    "sfta_authoring_draft",
    "record_activation_assignment",
    "record_activation_decision",
    "test_attribution",
    "verify_activation_workspace_file",
    "verify_browser_quality_receipt",
    "verify_browser_quality_receipt_file",
    "verify_assurance_case_file",
    "verify_conformance_workspace_file",
    "verify_configuration_authoring_file",
    "verify_enhancement_workbench_file",
    "verify_evidence_onboarding_receipt",
    "verify_evidence_onboarding_receipt_file",
    "verify_qualification_campaign",
    "verify_qualification_campaign_file",
    "verify_qualification_report_file",
    "verify_sfta_authoring_file",
    "verify_slsa_provenance_file",
    "verify_synthesis_apply_receipt",
    "verify_synthesis_apply_receipt_file",
]

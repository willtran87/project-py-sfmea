from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.html_report import (
    HTML_REPORT_FORMAT,
    MAX_REPORT_ASSURANCE_OBLIGATIONS,
    MAX_REPORT_SFTA_GAPS_PER_CLASS,
    _read_bounded_report_notes,
    _report_sfta_projection,
    build_html_report_data,
    export_html_report,
    verify_html_report_file,
)
from pysfmea.report import analysis_state_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import save_analysis
from pysfmea.system_context import build_system_context
from pysfmea.version import __version__


class HtmlReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def validate(value):\n    return bool(value)\n\n"
            "def publish(value):\n    return value\n\n"
            "def checkout(value):\n    validate(value)\n    return publish(value)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "project": {
                    "name": "Checkout <Service>",
                    "purpose": "Review '</script><script>alert(1)</script>' safely.",
                    "boundary": "Local test boundary.",
                    "operating_context": "Unit test.",
                },
                "requirements": [
                    {
                        "id": "REQ-1",
                        "text": "Publish valid transactions.",
                        "source": "SRS",
                        "hazards": ["HZ-1"],
                    }
                ],
                "hazards": [
                    {
                        "id": "HZ-1",
                        "description": "Incorrect transaction",
                        "end_effect": "A transaction is processed incorrectly.",
                    }
                ],
                "system_interfaces": [
                    {
                        "id": "IF-API",
                        "source": "Client",
                        "target": "Service",
                        "description": "Transaction requests",
                    }
                ],
                "component_mappings": [
                    {
                        "pattern": "service.py:checkout",
                        "requirements": ["REQ-1"],
                        "hazards": ["HZ-1"],
                        "interfaces": ["IF-API"],
                        "subsystem": "Transactions",
                    }
                ],
            },
        )

    def test_report_output_budget_fails_without_replacing_destination(self) -> None:
        output = self.root / "budgeted-report.html"
        output.write_text("trusted prior report", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "publication limit"):
            export_html_report(self.analysis, output, max_output_bytes=100)
        self.assertEqual(output.read_text(encoding="utf-8"), "trusted prior report")

    def test_report_exposes_typed_exception_precision_summary(self) -> None:
        (self.root / "exceptions.py").write_text(
            "class DomainError(Exception):\n"
            "    pass\n\n"
            "def leaf():\n"
            "    raise DomainError('failed')\n\n"
            "def caller():\n"
            "    try:\n"
            "        leaf()\n"
            "    except DomainError:\n"
            "        raise RuntimeError('translated')\n"
            "    finally:\n"
            "        return None\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)

        payload = build_html_report_data(analysis)

        exception_analysis = payload["exception_analysis"]
        self.assertEqual(
            exception_analysis["summary"]["edge_dispositions"]["caught_and_translates"],
            1,
        )
        self.assertEqual(
            exception_analysis["summary"]["project_exception_types_indexed"],
            1,
        )
        self.assertTrue(exception_analysis["edges"])
        self.assertEqual(
            exception_analysis["summary"]["unconditional_terminal_finalizers"], 1
        )
        self.assertEqual(exception_analysis["finalizers"][0]["terminal_kind"], "return")
        self.assertEqual(
            exception_analysis["summary"]["handler_outcome_certainties"]["uniform"],
            1,
        )
        report_path = export_html_report(analysis, self.root / "exception-report.html")
        report_html = report_path.read_text(encoding="utf-8")
        self.assertIn("translated exception edges", report_html)
        self.assertIn("indeterminate exception matches", report_html)
        self.assertIn("terminal finally overrides", report_html)
        self.assertIn("exceptions suppressed by finally", report_html)
        self.assertIn("conditional handler outcomes", report_html)
        self.assertIn("conditional rethrow edges", report_html)

    def test_report_exposes_static_control_flow_pruning_evidence(self) -> None:
        (self.root / "branches.py").write_text(
            "def choose():\n    return publish(1) if True else missing()\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        payload = build_html_report_data(analysis)

        control_flow = payload["static_control_flow_analysis"]
        self.assertEqual(control_flow["summary"]["decisions_discovered"], 1)
        self.assertEqual(control_flow["decisions"][0]["kind"], "if_expression")
        self.assertNotIn(
            "missing",
            next(
                value for value in analysis["components"]
                if value["qualname"] == "choose"
            )["calls"],
        )
        report_path = export_html_report(analysis, self.root / "branch-report.html")
        report_html = report_path.read_text(encoding="utf-8")
        self.assertIn("static control-flow decisions", report_html)
        self.assertIn("unreachable statements pruned", report_html)
        self.assertIn("short-circuit operands pruned", report_html)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_report_projects_machine_assistance_without_promoting_it(self) -> None:
        finding = self.analysis["items"][0]
        self.analysis["suggestions"] = [
            {
                "id": "SUG-REPORT",
                "component_id": finding["component_id"],
                "component_reference": "service.py:validate",
                "origin": "machine_suggestion",
                "status": "proposed",
                "content": {"failure_mode": "Generated review claim."},
                "evidence_ids": [finding["id"]],
                "proposed_citation_ids": [],
                "confidence": "low",
                "provenance": {},
                "reviewer": "",
                "materialized_item_id": "",
            }
        ]

        report = build_html_report_data(self.analysis)
        machine = report["cross_reference"]["machine_assistance_provenance"]
        chain = next(
            value
            for value in report["cross_reference"]["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(machine["suggestion_profiles"][0]["status"], "proposed")
        self.assertIn(
            "machine_suggestion:SUG-REPORT",
            chain["machine_assistance_entity_ids"],
        )
        self.assertTrue(chain["dimensions"]["machine_assistance"])
        self.assertIn("non-authoritative", machine["notice"])

    def test_report_projects_guidance_source_lineage(self) -> None:
        report = build_html_report_data(self.analysis)
        guidance = report["cross_reference"]["guidance_provenance"]
        chain = next(
            value
            for value in report["cross_reference"]["finding_chains"]
            if value["citation_ids"]
        )

        self.assertTrue(guidance["source_profiles"])
        self.assertTrue(guidance["citation_profiles"])
        self.assertTrue(guidance["review_check_profiles"])
        self.assertEqual(guidance["unresolved_methodology_source_ids"], [])
        self.assertEqual(guidance["mismatched_methodology_source_ids"], [])
        self.assertEqual(guidance["unresolved_citation_source_ids"], [])
        self.assertEqual(chain["guidance_lineage_status"], "complete")
        self.assertTrue(chain["guidance_source_entity_ids"])
        self.assertIn("traceability only", guidance["notice"])

        output = export_html_report(self.analysis, self.root / "guidance-report.html")
        document = output.read_text(encoding="utf-8")
        self.assertIn('"guidance_provenance":', document)
        self.assertIn("citations with source lineage", document)
        self.assertIn("Guidance source lineage", document)

    def test_report_projects_analysis_output_coverage(self) -> None:
        report = build_html_report_data(self.analysis)
        cross_reference = report["cross_reference"]
        coverage = cross_reference["analysis_projection_coverage"]
        profiles = {value["section"]: value for value in coverage["section_profiles"]}

        self.assertEqual(set(profiles), set(self.analysis))
        self.assertEqual(coverage["coverage_percent"], 100.0)
        self.assertEqual(coverage["material_coverage_percent"], 100.0)
        self.assertEqual(coverage["record_coverage_percent"], 100.0)
        self.assertEqual(coverage["unresolved_record_count"], 0)
        self.assertEqual(
            coverage["semantically_projected_record_count"],
            coverage["semantic_record_count"],
        )
        self.assertEqual(
            coverage["record_profiles_embedded_count"],
            len(coverage["record_profiles"]),
        )
        self.assertFalse(coverage["record_profiles_truncated_for_report"])
        self.assertEqual(coverage["unmapped_section_names"], [])
        self.assertEqual(cross_reference["summary"]["unmapped_analysis_sections"], 0)

        output = export_html_report(self.analysis, self.root / "coverage-report.html")
        document = output.read_text(encoding="utf-8")
        self.assertIn('"analysis_projection_coverage":', document)
        self.assertIn("declared analysis-output coverage", document)
        self.assertIn("material analysis-output coverage", document)
        self.assertIn("nested record witness coverage", document)
        self.assertIn("projectable nested records", document)
        self.assertIn("records without semantic witness", document)
        self.assertIn("Output coverage:", document)
        self.assertIn("unmapped analysis sections", document)

    def test_report_projects_context_alignment_and_lifecycle_provenance(self) -> None:
        finding = self.analysis["items"][0]
        self.analysis["system_context"] = build_system_context(
            {
                "project": {
                    "purpose": "Checkout",
                    "boundary": "Repository",
                    "operating_context": "Hosted service",
                    "operational_modes": ["Normal"],
                }
            }
        )
        finding["review"]["operational_mode"] = "normal"
        finding["review_history"] = [
            {
                "event": "review_update",
                "at": "2026-08-13T12:00:00Z",
                "reviewer": "Jordan",
                "changes": {"operational_mode": {"before": "", "after": "normal"}},
            }
        ]

        report = build_html_report_data(self.analysis)
        context = report["cross_reference"]["system_context_provenance"]
        lifecycle = report["cross_reference"]["lifecycle_provenance"]
        chain = next(
            value
            for value in report["cross_reference"]["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(
            context["finding_claim_profiles"][0]["alignment_status"], "matched"
        )
        self.assertEqual(
            lifecycle["finding_review_event_profiles"][0]["event"],
            "review_update",
        )
        self.assertTrue(chain["dimensions"]["system_context"])
        self.assertTrue(chain["dimensions"]["lifecycle_history"])
        self.assertIn("exact case-folded", context["notice"])
        self.assertIn("not authenticated", lifecycle["notice"])

    def test_report_is_self_contained_navigable_and_safely_embedded(self) -> None:
        included_id = self.analysis["items"][-1]["id"]
        notes = self.root / "notes.md"
        notes.write_text(
            "# Review leads\n\n- Confirm <authorization>.\n- </script><script>bad()</script>\n",
            encoding="utf-8",
        )
        output = export_html_report(
            self.analysis,
            self.root / "report.html",
            notes=notes,
            propagation_record_limit=2,
            propagation_path_limit=1,
            propagation_depth=1,
            propagation_include_finding_ids=[included_id],
        )
        document = output.read_text(encoding="utf-8")
        self.assertTrue(document.startswith("<!doctype html>"))
        self.assertIn("Content-Security-Policy", document)
        self.assertIn(
            f'<meta name="pysfmea-report-format" content="{HTML_REPORT_FORMAT}">',
            document,
        )
        self.assertIn(
            f'<meta name="pysfmea-analysis-state-sha256" content="{analysis_state_sha256(self.analysis)}">',
            document,
        )
        self.assertRegex(
            document,
            r'<meta name="pysfmea-report-data-sha256" content="[0-9a-f]{64}">',
        )
        self.assertRegex(
            document,
            r'<meta name="pysfmea-document-sha256" content="[0-9a-f]{64}">',
        )
        self.assertIn('data-view="failure-modes"', document)
        self.assertIn('data-view="coverage"', document)
        self.assertIn('data-view="architecture"', document)
        self.assertIn('data-view="cross-reference"', document)
        self.assertIn('id="crossReferenceChains"', document)
        self.assertIn('id="crossReferenceSemanticCoverage"', document)
        self.assertIn('id="crossReferenceCompoundExposure"', document)
        self.assertIn('id="crossReferenceVerificationLifecycle"', document)
        self.assertIn('id="crossReferenceEvidencePosture"', document)
        self.assertIn('id="crossReferenceReadinessGaps"', document)
        self.assertIn('id="crossReferenceReviewGovernance"', document)
        self.assertIn('id="crossReferenceQualityDiagnostics"', document)
        self.assertIn('id="crossReferenceSourceChanges"', document)
        self.assertIn('"semantic_profiles":', document)
        self.assertIn('"verification_readiness_profiles":', document)
        self.assertIn('"review_governance_profiles":', document)
        self.assertIn('"quality_gate_projection":', document)
        self.assertIn('"adapter_provenance":', document)
        self.assertIn('"repository_provenance":', document)
        self.assertIn('"machine_assistance_provenance":', document)
        self.assertIn('"system_context_provenance":', document)
        self.assertIn('"lifecycle_provenance":', document)
        self.assertIn("verification_profiles_with_signals", document)
        self.assertIn("value.verification_lifecycle_state", document)
        self.assertIn("value.verification_evidence_posture", document)
        self.assertIn("value.verification_next_action_id", document)
        self.assertIn("value.review_governance_state", document)
        self.assertIn("value.review_next_action_id", document)
        self.assertIn("value.quality_diagnostic_counts", document)
        self.assertIn("value.adapter_statuses", document)
        self.assertIn("value.system_context_alignment_statuses", document)
        self.assertIn("value.lifecycle_event_entity_ids", document)
        self.assertIn("findings with tool provenance", document)
        self.assertIn("findings with source provenance", document)
        self.assertIn("value.source_repository_path", document)
        self.assertIn("action.dataset.openFinding=value.finding_id", document)
        self.assertIn("Evidence fabric linkage", document)
        self.assertIn("findingButton.dataset.openFinding", document)
        self.assertIn('id="deploymentTopology"', document)
        self.assertIn('id="sharedFateRegions"', document)
        self.assertIn('id="architectureHierarchy"', document)
        self.assertIn('data-open-diagram="declared-deployment-topology"', document)
        self.assertIn("function renderArchitectureModels", document)
        self.assertIn("Control model review questions", document)
        self.assertIn("Cascade observation context", document)
        self.assertIn('data-kind="unconfirmed_state"', document)
        self.assertIn('data-kind="review_gap"', document)
        self.assertIn('data-kind="containment_boundary"', document)
        self.assertIn('data-kind="cascade_component"', document)
        self.assertIn('data-kind="cascade_origin"', document)
        self.assertIn('includes("observed_runtime")', document)
        self.assertIn("discovered caller paths", document)
        self.assertIn("available_discovered_cascade_paths", document)
        self.assertIn("Projection omissions:", document)
        self.assertIn("Pinned review scope:", document)
        self.assertIn("Projection configuration", document)
        self.assertIn("projectionStatusLabel", document)
        self.assertIn("node budget", document)
        self.assertIn('id="diagramCopyRecipe"', document)
        self.assertIn('id="diagramRecipeText"', document)
        self.assertIn("function projectionCommand", document)
        self.assertIn("Projection command copied", document)
        self.assertIn("--propagation-include-finding", document)
        self.assertIn("Analysis state SHA-256", document)
        self.assertIn("total_active_components", document)
        self.assertIn("repeated paths shared", document)
        self.assertIn('id="detailPropagation"', document)
        self.assertIn('id="detailAssurance"', document)
        self.assertIn("openPropagationForFinding", document)
        self.assertIn("openAssuranceForFinding", document)
        self.assertIn("Finding outside bounded projection", document)
        self.assertIn("#diagrams/${encodeURIComponent(activeDiagram.id)}", document)
        self.assertIn("decodeHashPart", document)
        self.assertIn('data-view="traceability"', document)
        self.assertIn('data-view="sequences"', document)
        self.assertIn('data-view="diagrams"', document)
        self.assertIn("Export filtered CSV", document)
        self.assertIn('id="savedViewSelect"', document)
        self.assertIn('id="shareView"', document)
        self.assertIn("savedViewStorageKey", document)
        self.assertIn("function sharedFilterHash", document)
        self.assertIn('href="#mainContent"', document)
        self.assertIn('<caption class="sr-only">', document)
        self.assertIn("System context and analysis coverage", document)
        self.assertIn("Diagnostic readiness scorecard", document)
        self.assertIn('id="diagnosticQualification"', document)
        self.assertIn('id="diagnosticActions"', document)
        self.assertIn('id="reviewCalibration"', document)
        self.assertIn("function renderDiagnostics", document)
        self.assertIn('data-view="enhancements"', document)
        self.assertIn('id="enhancementMetrics"', document)
        self.assertIn('id="enhancementFreshness"', document)
        self.assertIn('id="enhancementTargets"', document)
        self.assertIn('id="enhancementScopePatch"', document)
        self.assertIn('id="enhancementCalibration"', document)
        self.assertIn('id="enhancementPrecision"', document)
        self.assertIn('id="enhancementHardening"', document)
        self.assertIn('id="enhancementPostHardening"', document)
        self.assertIn('id="enhancementResolution"', document)
        self.assertIn('id="enhancementOperations"', document)
        self.assertIn('id="enhancementReviewCampaign"', document)
        self.assertIn('id="enhancementEvidence"', document)
        self.assertIn('id="enhancementCapabilities"', document)
        self.assertIn("function renderEnhancementWorkbench", document)
        self.assertIn('id="inventorySnapshotBars"', document)
        self.assertIn('id="inventorySummaryReconciliation"', document)
        self.assertIn("Snapshot provenance", document)
        self.assertIn("bound to the same bytes", document)
        self.assertIn("by_snapshot_source", document)
        self.assertIn('id="sftaGapCount"', document)
        self.assertIn("bounded_interactive_view", document)
        self.assertIn('id="detailPrevious"', document)
        self.assertIn('id="detailNext"', document)
        self.assertIn('id="detailCopy"', document)
        self.assertIn("function moveDetailRecord", document)
        self.assertIn("function copyDetailLink", document)
        self.assertIn('id="sortFilter"', document)
        self.assertIn('id="resetFilters"', document)
        self.assertIn("function compareRecords", document)
        self.assertIn("function resetFailureModeView", document)
        self.assertIn("function renderAssuranceProgress", document)
        self.assertIn('id="renderStatus"', document)
        self.assertIn('dataset.reportRenderMode="progressive-on-demand"', document)
        self.assertIn("function ensureViewRendered", document)
        self.assertIn("function renderAllViews", document)
        self.assertIn('window.addEventListener("beforeprint",renderAllViews)', document)
        self.assertIn('mode:"progressive_on_demand"', document)
        self.assertNotIn("initHeader();renderOverview();renderCoverage();", document)
        self.assertNotIn("<script>bad()</script>", document)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn(r"\u003c/script\u003e", document)
        self.assertNotRegex(document, r"<script[^>]+src=")
        self.assertNotRegex(document, r"<link[^>]+rel=[\"']stylesheet")

        match = re.search(
            r'<script id="report-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        payload = json.loads(match.group(1))
        self.assertEqual(payload["project"]["name"], "Checkout <Service>")
        self.assertIn("Confirm <authorization>", payload["report"]["notes"])
        self.assertGreater(len(payload["records"]), 0)
        self.assertEqual(payload["interfaces"][0]["id"], "IF-API")
        self.assertTrue(payload["sequences"])
        self.assertTrue(payload["diagrams"])
        self.assertEqual(
            {
                "architecture-components",
                "declared-deployment-topology",
                "shared-fate-regions",
                "architecture-hierarchy",
            },
            {
                value["id"]
                for value in payload["diagrams"]
                if value.get("metadata", {}).get("category") == "architecture"
            },
        )
        self.assertEqual(
            payload["architecture"]["hierarchy"]["summary"]["nodes"],
            self.analysis["architecture_hierarchy"]["summary"]["nodes"],
        )
        self.assertEqual(
            payload["repository_inventory"]["summary_reconciliation"]["status"],
            "reconciled",
        )
        self.assertEqual(
            payload["report"]["diagram_configuration"]["failure_propagation"],
            {
                "record_limit": 2,
                "paths_per_component": 1,
                "depth": 1,
                "include_finding_ids": [included_id],
            },
        )
        propagation = next(
            value
            for value in payload["diagrams"]
            if value["metadata"].get("category") == "failure_propagation"
        )
        self.assertEqual(propagation["metadata"]["record_limit"], 2)
        self.assertEqual(propagation["metadata"]["cascade_paths_per_component"], 1)
        self.assertEqual(propagation["metadata"]["cascade_depth"], 1)
        self.assertEqual(
            propagation["metadata"]["requested_included_finding_ids"],
            [included_id],
        )
        self.assertEqual(
            propagation["metadata"]["projection_status"], "bounded_projection"
        )
        self.assertTrue(propagation["metadata"]["projection_reason_codes"])
        self.assertIn(
            f"failure:{included_id}",
            {node["id"] for node in propagation["nodes"]},
        )
        self.assertIn("planning_percent", payload["assurance"]["progress"])
        self.assertEqual(
            payload["enhancement_workbench"]["format"],
            "pysfmea-enhancement-workbench-7",
        )
        self.assertTrue(payload["enhancement_workbench"]["capability_register"])
        self.assertEqual(
            len(payload["enhancement_workbench"]["hardening_register"]), 76
        )
        self.assertEqual(
            len(payload["enhancement_workbench"]["post_hardening_register"]), 82
        )
        self.assertEqual(
            len(payload["enhancement_workbench"]["next_generation_register"]), 102
        )
        self.assertEqual(
            len(payload["enhancement_workbench"]["product_outcome_register"]), 95
        )
        self.assertIn("review_campaign", payload["enhancement_workbench"])
        self.assertIn("llm_governance_program", payload["enhancement_workbench"])
        self.assertEqual(
            payload["enhancement_workbench"]["assurance_automation_program"][
                "synthesized_test_designs"
            ]["property_tests"]["status"],
            "implemented",
        )
        self.assertIn("artifact_freshness", payload["enhancement_workbench"])
        self.assertIn("artifact_health", payload["enhancement_workbench"])
        self.assertIn("acceptance_targets", payload["enhancement_workbench"])
        self.assertEqual(
            payload["enhancement_workbench"]["activation_progress"]["status"],
            "not_started",
        )
        self.assertEqual(payload["activation"]["decision_history_total"], 0)
        self.assertIn('id="enhancementActivation"', document)
        self.assertIn('id="enhancementOutcomes"', document)
        self.assertEqual(payload["sfta"]["authoring"]["total_applies"], 0)
        self.assertIn('id="sftaAuthoring"', document)
        self.assertIn("sfta-authoring-seal", document)
        self.assertIn("configuration_review", payload)
        self.assertIn("config-authoring-init", document)
        self.assertIn("work_queue", payload["assurance"]["progress"])
        self.assertTrue(
            all("work" in value for value in payload["assurance"]["obligations"])
        )
        self.assertIn("pysfmea-assurance-work-queue-2", document)
        self.assertIn("work: ${work.state}", document)
        self.assertEqual(payload["report"]["binding"]["format"], HTML_REPORT_FORMAT)
        self.assertEqual(
            payload["report"]["binding"]["analysis_state_sha256"],
            analysis_state_sha256(self.analysis),
        )
        verification = verify_html_report_file(output, analysis=self.analysis)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["status"], "matched")
        self.assertEqual(verification["integrity_scope"], "document_and_payload")
        self.assertTrue(verification["checks"]["document_integrity"])
        self.assertTrue(verification["checks"]["payload_binding"])

        output.write_text(
            document.replace("--radius:16px", "--radius:17px", 1),
            encoding="utf-8",
        )
        changed_shell = verify_html_report_file(output, analysis=self.analysis)
        self.assertFalse(changed_shell["valid"])
        self.assertEqual(changed_shell["integrity_scope"], "invalid")
        self.assertFalse(changed_shell["checks"]["document_integrity"])
        self.assertIn("document_integrity", changed_shell["failed_checks"])
        self.assertTrue(changed_shell["checks"]["payload_integrity"])

        output.write_text(
            re.sub(
                r'\n<meta name="pysfmea-document-sha256" content="[0-9a-f]{64}">',
                "",
                document,
                count=1,
            ),
            encoding="utf-8",
        )
        downgraded = verify_html_report_file(output, analysis=self.analysis)
        self.assertFalse(downgraded["valid"])
        self.assertFalse(downgraded["checks"]["document_integrity"])

    def test_report_recomputes_or_withholds_untrusted_inventory_summary(self) -> None:
        inventory = self.analysis["repository_inventory"]
        actual_files = len(inventory["entries"])
        actual_opaque = inventory["summary"]["opaque_or_unresolved"]
        inventory["summary"]["files"] = actual_files + 999
        inventory["summary"]["opaque_or_unresolved"] = actual_opaque + 999
        inventory["summary"]["semantic_coverage_percent"] = -1

        payload = build_html_report_data(self.analysis)
        self.assertIn("qualification", payload["diagnostics"])
        self.assertIn("review_calibration", payload["diagnostics"]["workload"])
        projected = payload["repository_inventory"]
        self.assertEqual(projected["summary_reconciliation"]["status"], "recomputed")
        self.assertEqual(projected["summary"]["files"], actual_files)
        self.assertEqual(projected["summary"]["opaque_or_unresolved"], actual_opaque)
        self.assertIn(
            "coverage.inventory_summary_mismatch",
            {
                finding["rule_id"]
                for finding in payload["validation"]["project_findings"]
            },
        )

        inventory["entries"][0].pop("snapshot_source")
        unavailable = build_html_report_data(self.analysis)["repository_inventory"]
        self.assertEqual(unavailable["summary_reconciliation"]["status"], "unavailable")
        self.assertEqual(unavailable["summary"], {})

    def test_report_exposes_run_manifest_integrity(self) -> None:
        payload = build_html_report_data(self.analysis)
        self.assertTrue(payload["run_manifest_integrity"]["valid"])
        self.analysis["run_manifest"]["created_at"] = "2030-01-01T00:00:00+00:00"
        tampered = build_html_report_data(self.analysis)
        self.assertFalse(tampered["run_manifest_integrity"]["valid"])
        self.assertIn(
            "run_manifest.content_integrity",
            {
                finding["rule_id"]
                for finding in tampered["validation"]["project_findings"]
            },
        )

    def test_report_data_is_bounded_and_reports_truncation(self) -> None:
        payload = build_html_report_data(self.analysis, max_records=1)
        self.assertEqual(payload["report"]["embedded_records"], 1)
        self.assertEqual(
            payload["report"]["total_records"], len(self.analysis["items"])
        )
        self.assertEqual(
            payload["report"]["records_truncated"], len(self.analysis["items"]) > 1
        )
        with self.assertRaisesRegex(ValueError, "max_records"):
            build_html_report_data(self.analysis, max_records=0)

    def test_pinned_propagation_finding_is_retained_in_bounded_report(self) -> None:
        included_id = self.analysis["items"][-1]["id"]
        payload = build_html_report_data(
            self.analysis,
            max_records=1,
            propagation_record_limit=1,
            propagation_path_limit=0,
            propagation_depth=0,
            propagation_include_finding_ids=[included_id, included_id],
        )

        self.assertEqual([record["id"] for record in payload["records"]], [included_id])
        self.assertEqual(
            payload["report"]["diagram_configuration"]["failure_propagation"][
                "include_finding_ids"
            ],
            [included_id],
        )
        with self.assertRaisesRegex(ValueError, "report record limit"):
            build_html_report_data(
                self.analysis,
                max_records=1,
                propagation_include_finding_ids=[
                    self.analysis["items"][0]["id"],
                    included_id,
                ],
            )

    def test_large_registers_use_truthful_bounded_report_projections(self) -> None:
        payload = build_html_report_data(self.analysis)
        assurance = payload["assurance"]
        projection = assurance["report_projection"]
        self.assertLessEqual(
            len(assurance["obligations"]), MAX_REPORT_ASSURANCE_OBLIGATIONS
        )
        self.assertEqual(
            projection["obligations"]["embedded"],
            len(assurance["obligations"]),
        )
        self.assertGreaterEqual(
            projection["obligations"]["total"],
            projection["obligations"]["embedded"],
        )
        self.assertIn("portable review package", projection["complete_source"])

        gaps = [
            {"finding_id": f"SFMEA-{index}", "hazard_id": "HZ-1"}
            for index in range(MAX_REPORT_SFTA_GAPS_PER_CLASS + 3)
        ]
        sfta = _report_sfta_projection(
            {
                "schema_version": "1.0",
                "trees": [],
                "reconciliation": {
                    "summary": {"bottom_up_unmapped_findings": len(gaps)},
                    "finding_to_events": [],
                    "top_down_uncovered_events": [],
                    "bottom_up_unmapped_findings": gaps,
                    "hazard_link_mismatches": [],
                },
            }
        )
        embedded = sfta["reconciliation"]["bottom_up_unmapped_findings"]
        gap_projection = sfta["report_projection"]["collections"][
            "bottom_up_unmapped_findings"
        ]
        self.assertEqual(len(embedded), MAX_REPORT_SFTA_GAPS_PER_CLASS)
        self.assertEqual(gap_projection["total"], len(gaps))
        self.assertTrue(gap_projection["truncated"])
        self.assertTrue(sfta["report_projection"]["truncated"])

    def test_cli_creates_default_html_report(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = main(["report", str(analysis_path), "--title", "Review report"])
        self.assertEqual(result, 0)
        report_path = self.root / "analysis-report.html"
        self.assertTrue(report_path.is_file())
        self.assertIn("Created self-contained SFMEA report", output.getvalue())
        self.assertRegex(output.getvalue(), r"\([\d,]+ records; \d+\.\d MiB\)")

        self.assertIn(
            "<title>Review report</title>", report_path.read_text(encoding="utf-8")
        )

        json_report = self.root / "analysis-json-report.html"
        json_output = io.StringIO()
        json_error = io.StringIO()
        with contextlib.redirect_stdout(json_output):
            with contextlib.redirect_stderr(json_error):
                result = main(
                    [
                        "report",
                        str(analysis_path),
                        "--output",
                        str(json_report),
                        "--json",
                    ]
                )
        self.assertEqual(result, 0)
        self.assertEqual(json_error.getvalue(), "")
        generation_receipt = json.loads(json_output.getvalue())
        self.assertTrue(generation_receipt["valid"])
        self.assertEqual(generation_receipt["status"], "matched")
        self.assertTrue(generation_receipt["binding_requested"])
        self.assertTrue(generation_receipt["binding_checked"])
        self.assertEqual(
            generation_receipt["verifier"],
            {"name": "PySFMEA", "version": __version__},
        )
        self.assertEqual(Path(generation_receipt["path"]), json_report)
        self.assertEqual(generation_receipt["publication"]["status"], "published")
        self.assertEqual(generation_receipt["publication"]["phase"], "complete")
        self.assertFalse(generation_receipt["publication"]["destination_existed"])
        self.assertFalse(
            generation_receipt["publication"]["prior_destination_preserved"]
        )
        generation_validator = Draft202012Validator(
            schema_document("html-report-verification")
        )
        generation_validator.validate(generation_receipt)
        contradictory_receipt = json.loads(json.dumps(generation_receipt))
        contradictory_receipt["publication"]["status"] = "not_published"
        contradictory_receipt["publication"]["phase"] = "generation"
        self.assertFalse(generation_validator.is_valid(contradictory_receipt))
        contradictory_receipt = json.loads(json.dumps(generation_receipt))
        contradictory_receipt["publication"]["prior_destination_preserved"] = True
        self.assertFalse(generation_validator.is_valid(contradictory_receipt))

        rejected_report = self.root / "rejected-report.html"
        rejected_report.write_text("trusted prior report", encoding="utf-8")
        rejected_output = io.StringIO()
        rejected_error = io.StringIO()
        with patch(
            "pysfmea.cli.verify_html_report_file",
            side_effect=RuntimeError("sensitive injected verifier detail"),
        ):
            with contextlib.redirect_stdout(rejected_output):
                with contextlib.redirect_stderr(rejected_error):
                    result = main(
                        [
                            "report",
                            str(analysis_path),
                            "--output",
                            str(rejected_report),
                            "--json",
                        ]
                    )
        self.assertEqual(result, 1)
        self.assertEqual(rejected_error.getvalue(), "")
        rejected_receipt = json.loads(rejected_output.getvalue())
        self.assertFalse(rejected_receipt["valid"])
        self.assertEqual(
            rejected_receipt["errors"][0]["code"],
            "report.post_generation_verification_failed",
        )
        self.assertNotIn("sensitive injected", rejected_output.getvalue())
        self.assertEqual(rejected_receipt["publication"]["status"], "not_published")
        self.assertEqual(rejected_receipt["publication"]["phase"], "verification")
        self.assertTrue(rejected_receipt["publication"]["destination_existed"])
        self.assertTrue(rejected_receipt["publication"]["prior_destination_preserved"])
        self.assertEqual(
            rejected_report.read_text(encoding="utf-8"),
            "trusted prior report",
        )
        self.assertFalse(list(self.root.glob(".rejected-report.html.*.tmp")))
        Draft202012Validator(schema_document("html-report-verification")).validate(
            rejected_receipt
        )

        verification_output = io.StringIO()
        with contextlib.redirect_stdout(verification_output):
            result = main(
                [
                    "report-verify",
                    str(report_path),
                    "--analysis",
                    str(analysis_path),
                    "--json",
                ]
            )
        self.assertEqual(result, 0)
        verification = json.loads(verification_output.getvalue())
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["checks"]["analysis_state"])
        self.assertEqual(verification["integrity_scope"], "document_and_payload")
        verification_schema = schema_document("html-report-verification")
        self.assertLessEqual(set(verification_schema["required"]), set(verification))
        self.assertEqual(
            set(verification_schema["properties"]["checks"]["required"]),
            set(verification["checks"]),
        )

        human_output = io.StringIO()
        with contextlib.redirect_stdout(human_output):
            result = main(["report-verify", str(report_path)])
        self.assertEqual(result, 0)
        self.assertIn("analysis binding=not checked", human_output.getvalue())
        self.assertIn("Unchecked checks:", human_output.getvalue())
        self.assertIn("do not authenticate", human_output.getvalue())

        tampered_document = report_path.read_text(encoding="utf-8").replace(
            "--radius:16px", "--radius:17px", 1
        )
        report_path.write_text(tampered_document, encoding="utf-8")
        invalid_output = io.StringIO()
        with contextlib.redirect_stdout(invalid_output):
            result = main(["report-verify", str(report_path), "--json"])
        self.assertEqual(result, 1)
        invalid_verification = json.loads(invalid_output.getvalue())
        self.assertFalse(invalid_verification["valid"])
        self.assertEqual(invalid_verification["status"], "invalid")
        self.assertEqual(invalid_verification["integrity_scope"], "invalid")
        self.assertIn("document_integrity", invalid_verification["failed_checks"])

        missing_output = io.StringIO()
        with contextlib.redirect_stdout(missing_output):
            result = main(
                ["report-verify", str(self.root / "missing-report.html"), "--json"]
            )
        self.assertEqual(result, 1)
        missing_verification = json.loads(missing_output.getvalue())
        self.assertFalse(missing_verification["valid"])
        self.assertFalse(missing_verification["binding_requested"])
        self.assertFalse(missing_verification["binding_checked"])
        self.assertEqual(
            missing_verification["errors"][0]["code"],
            "report.verification_failed",
        )

        oversized_report = self.root / "oversized-report.html"
        oversized_report.write_bytes(b"x" * 11)
        oversized_output = io.StringIO()
        with patch("pysfmea.html_report.MAX_HTML_REPORT_VERIFY_BYTES", 10):
            with contextlib.redirect_stdout(oversized_output):
                result = main(["report-verify", str(oversized_report), "--json"])
        self.assertEqual(result, 1)
        oversized_verification = json.loads(oversized_output.getvalue())
        self.assertFalse(oversized_verification["valid"])
        self.assertIn(
            "10-byte verification limit",
            oversized_verification["errors"][0]["message"],
        )

        input_error_output = io.StringIO()
        with contextlib.redirect_stdout(input_error_output):
            result = main(
                [
                    "report-verify",
                    str(report_path),
                    "--analysis",
                    str(self.root / "missing-analysis.json"),
                    "--json",
                ]
            )
        self.assertEqual(result, 2)
        input_error = json.loads(input_error_output.getvalue())
        self.assertTrue(input_error["binding_requested"])
        self.assertFalse(input_error["binding_checked"])
        self.assertEqual(input_error["errors"][0]["code"], "analysis.load_failed")

    def test_report_profiles_enforce_bounded_projection(self) -> None:
        compact = build_html_report_data(self.analysis, profile="compact")
        management = build_html_report_data(self.analysis, profile="management")

        self.assertEqual(compact["report"]["profile"], "compact")
        self.assertEqual(management["report"]["profile"], "management")
        with self.assertRaisesRegex(ValueError, "profile must be"):
            build_html_report_data(self.analysis, profile="unknown")

    def test_report_notes_are_bounded_regular_utf8_files(self) -> None:
        notes = self.root / "notes.md"
        notes.write_text("# Review\n\nBounded notes.\n", encoding="utf-8")
        self.assertEqual(
            _read_bounded_report_notes(notes),
            "# Review\n\nBounded notes.\n",
        )

        notes_directory = self.root / "notes-directory"
        notes_directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            _read_bounded_report_notes(notes_directory)

        invalid_utf8 = self.root / "invalid-notes.md"
        invalid_utf8.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            _read_bounded_report_notes(invalid_utf8)

        oversized = self.root / "oversized-notes.md"
        oversized.write_bytes(b"x" * 11)
        with patch("pysfmea.html_report.MAX_NOTES_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "exceeds 10 bytes"):
                _read_bounded_report_notes(oversized)

        linked_notes = self.root / "linked-notes.md"
        try:
            linked_notes.symlink_to(notes)
        except OSError:
            linked_notes = None
        if linked_notes is not None:
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                _read_bounded_report_notes(linked_notes)

    def test_json_report_publication_is_transactional_and_structured(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        verification_schema = schema_document("html-report-verification")

        def run_json_report(*arguments: str) -> tuple[int, dict[str, object], str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    result = main(["report", *arguments, "--json"])
            receipt = json.loads(stdout.getvalue())
            Draft202012Validator(verification_schema).validate(receipt)
            return result, receipt, stderr.getvalue()

        result, receipt, stderr = run_json_report(
            str(analysis_path), "--output", str(analysis_path)
        )
        self.assertEqual(result, 2)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.invalid_destination")
        self.assertEqual(receipt["publication"]["phase"], "input_validation")
        self.assertTrue(receipt["publication"]["prior_destination_preserved"])
        preserved_analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        self.assertEqual(preserved_analysis["project"]["name"], "Checkout <Service>")

        directory_output = self.root / "report-directory"
        directory_output.mkdir()
        result, receipt, stderr = run_json_report(
            str(analysis_path), "--output", str(directory_output)
        )
        self.assertEqual(result, 2)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.invalid_destination")
        self.assertIn("regular file", receipt["errors"][0]["message"])
        self.assertTrue(directory_output.is_dir())
        human_error = io.StringIO()
        with contextlib.redirect_stderr(human_error):
            result = main(
                ["report", str(analysis_path), "--output", str(directory_output)]
            )
        self.assertEqual(result, 2)
        self.assertIn("regular file", human_error.getvalue())

        mocked_link_output = self.root / "mocked-link-report.html"
        mocked_link_output.write_text("trusted mocked link", encoding="utf-8")
        with patch("pysfmea.cli.Path.is_symlink", return_value=True):
            result, receipt, stderr = run_json_report(
                str(analysis_path), "--output", str(mocked_link_output)
            )
        self.assertEqual(result, 2)
        self.assertEqual(stderr, "")
        self.assertIn("symbolic link", receipt["errors"][0]["message"])
        self.assertEqual(
            mocked_link_output.read_text(encoding="utf-8"),
            "trusted mocked link",
        )

        symlink_target = self.root / "trusted-symlink-target.html"
        symlink_target.write_text("trusted symlink target", encoding="utf-8")
        symlink_output = self.root / "report-symlink.html"
        try:
            symlink_output.symlink_to(symlink_target)
        except OSError:
            symlink_output = None
        if symlink_output is not None:
            result, receipt, stderr = run_json_report(
                str(analysis_path), "--output", str(symlink_output)
            )
            self.assertEqual(result, 2)
            self.assertEqual(stderr, "")
            self.assertEqual(receipt["errors"][0]["code"], "report.invalid_destination")
            self.assertIn("symbolic link", receipt["errors"][0]["message"])
            self.assertTrue(symlink_output.is_symlink())
            self.assertEqual(
                symlink_target.read_text(encoding="utf-8"),
                "trusted symlink target",
            )

        race_target = self.root / "race-target.html"
        race_target.write_text("trusted race target", encoding="utf-8")
        race_output = self.root / "race-report.html"
        race_state = {"linked": False}
        published_destinations: list[Path] = []

        def verify_then_insert_link(
            staged: str | Path, *, analysis: dict[str, object]
        ) -> dict[str, object]:
            verification = verify_html_report_file(staged, analysis=analysis)
            try:
                race_output.symlink_to(race_target)
            except OSError:
                return verification
            race_state["linked"] = True
            return verification

        def capture_atomic_replace(source: str | Path, destination: str | Path) -> None:
            published_destinations.append(Path(destination))
            os.replace(source, destination)

        with patch(
            "pysfmea.cli.verify_html_report_file",
            side_effect=verify_then_insert_link,
        ):
            with patch(
                "pysfmea.cli.atomic_replace",
                side_effect=capture_atomic_replace,
            ):
                result, receipt, stderr = run_json_report(
                    str(analysis_path), "--output", str(race_output)
                )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["publication"]["status"], "published")
        self.assertEqual(published_destinations, [race_output.absolute()])
        if race_state["linked"]:
            self.assertFalse(race_output.is_symlink())
            self.assertIn("<!doctype html>", race_output.read_text(encoding="utf-8"))
            self.assertEqual(
                race_target.read_text(encoding="utf-8"),
                "trusted race target",
            )

        missing_output = self.root / "missing-input-report.html"
        result, receipt, stderr = run_json_report(
            str(self.root / "missing-analysis.json"),
            "--output",
            str(missing_output),
        )
        self.assertEqual(result, 2)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.analysis_load_failed")
        self.assertEqual(receipt["publication"]["phase"], "analysis_load")
        self.assertFalse(receipt["publication"]["prior_destination_preserved"])
        self.assertFalse(missing_output.exists())

        missing_notes_output = self.root / "missing-notes-report.html"
        missing_notes_output.write_text("trusted notes report", encoding="utf-8")
        result, receipt, stderr = run_json_report(
            str(analysis_path),
            "--notes",
            str(self.root / "missing-notes.md"),
            "--output",
            str(missing_notes_output),
        )
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.generation_failed")
        self.assertEqual(receipt["publication"]["phase"], "generation")
        self.assertTrue(receipt["publication"]["prior_destination_preserved"])
        self.assertEqual(
            missing_notes_output.read_text(encoding="utf-8"),
            "trusted notes report",
        )

        generation_output = self.root / "generation-report.html"
        generation_output.write_text("trusted generation report", encoding="utf-8")
        with patch(
            "pysfmea.cli.export_html_report",
            side_effect=RuntimeError("sensitive generation detail"),
        ):
            result, receipt, stderr = run_json_report(
                str(analysis_path), "--output", str(generation_output)
            )
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.generation_failed")
        self.assertEqual(receipt["publication"]["phase"], "generation")
        self.assertTrue(receipt["publication"]["prior_destination_preserved"])
        self.assertNotIn("sensitive generation", json.dumps(receipt))
        self.assertEqual(
            generation_output.read_text(encoding="utf-8"),
            "trusted generation report",
        )
        self.assertFalse(list(self.root.glob(".generation-report.html.*.tmp")))

        publication_output = self.root / "publication-report.html"
        publication_output.write_text("trusted publication report", encoding="utf-8")
        with patch(
            "pysfmea.cli.atomic_replace",
            side_effect=OSError("sensitive publication detail"),
        ):
            result, receipt, stderr = run_json_report(
                str(analysis_path), "--output", str(publication_output)
            )
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["errors"][0]["code"], "report.publication_failed")
        self.assertEqual(receipt["publication"]["phase"], "publication")
        self.assertTrue(receipt["publication"]["prior_destination_preserved"])
        self.assertNotIn("sensitive publication", json.dumps(receipt))
        self.assertEqual(
            publication_output.read_text(encoding="utf-8"),
            "trusted publication report",
        )
        self.assertFalse(list(self.root.glob(".publication-report.html.*.tmp")))

    def test_embedded_javascript_parses_when_node_is_available(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        output = export_html_report(self.analysis, self.root / "report.html")
        document = output.read_text(encoding="utf-8")
        scripts = re.findall(r"<script(?: [^>]*)?>(.*?)</script>", document, re.DOTALL)
        script = scripts[-1]
        javascript = self.root / "report.js"
        javascript.write_text(script, encoding="utf-8")
        result = subprocess.run(
            [node, "--check", str(javascript)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

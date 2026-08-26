from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.cross_reference import (
    CROSS_REFERENCE_FORMAT,
    CROSS_REFERENCE_VERIFICATION_FORMAT,
    build_cross_reference_index,
    export_cross_reference_index,
    verify_cross_reference_file,
)
from pysfmea.diagrams import build_diagram_models
from pysfmea.graphify import load_graphify_reconciliation
from pysfmea.integrity import canonical_json_sha256
from pysfmea.report import export_review_package, verify_review_package
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import save_analysis
from pysfmea.system_context import build_system_context


class CrossReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "app.py").write_text(
            "def caller():\n    return callee()\n\ndef callee():\n    return 1\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        by_name = {value["qualname"]: value for value in self.analysis["components"]}
        self.caller = by_name["caller"]
        self.callee = by_name["callee"]
        graph = self.root / "graph.json"
        graph.write_text(
            json.dumps(
                {
                    "nodes": [
                        {
                            "id": "caller",
                            "label": "caller()",
                            "source_file": "app.py",
                            "source_location": "L1",
                        },
                        {
                            "id": "callee",
                            "label": "callee()",
                            "source_file": "app.py",
                            "source_location": "L4",
                        },
                    ],
                    "edges": [
                        {
                            "source": "caller",
                            "target": "callee",
                            "relation": "calls",
                            "confidence": "EXTRACTED",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.analysis["graphify_reconciliation"] = load_graphify_reconciliation(
            self.analysis, graph
        )
        self.analysis["runtime_evidence"] = {
            "imports": [{"id": "RT-IMPORT-1", "source": "trace.json"}],
            "spans": [],
            "edges": [
                {
                    "source_component_id": self.caller["id"],
                    "target_component_id": self.callee["id"],
                    "trace_id": "trace-1",
                    "operation": "caller to callee",
                }
            ],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fuses_native_graphify_and_runtime_relationships(self) -> None:
        index = build_cross_reference_index(self.analysis)

        self.assertEqual(index["format"], CROSS_REFERENCE_FORMAT)
        fusion = next(
            value
            for value in index["component_relationship_fusions"]
            if value["source_component_id"] == self.caller["id"]
            and value["target_component_id"] == self.callee["id"]
        )
        self.assertEqual(fusion["classification"], "observed_multi_source")
        self.assertEqual(
            fusion["channels"],
            ["graphify_static", "native_ast", "runtime_observed"],
        )
        self.assertTrue(fusion["runtime_observed"])
        self.assertEqual(index["summary"]["multi_source_fusions"], 1)
        self.assertEqual(
            index["content_sha256"],
            build_cross_reference_index(self.analysis)["content_sha256"],
        )
        content = dict(index)
        supplied_digest = content.pop("content_sha256")
        self.assertEqual(supplied_digest, canonical_json_sha256(content))

    def test_projects_finding_guidance_and_verification_chain(self) -> None:
        index = build_cross_reference_index(self.analysis)
        finding = next(
            value
            for value in self.analysis["items"]
            if value["component_id"] == self.caller["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(chain["component_id"], self.caller["id"])
        self.assertTrue(chain["citation_ids"])
        self.assertTrue(chain["obligation_ids"])
        self.assertTrue(chain["dimensions"]["guidance"])
        self.assertTrue(chain["dimensions"]["verification"])
        self.assertFalse(chain["dimensions"]["evidence"])
        self.assertTrue(chain["outbound_fusion_ids"])
        self.assertTrue(chain["dimensions"]["component_relationships"])

    def test_cross_links_quality_gates_change_and_review_governance(self) -> None:
        index = build_cross_reference_index(self.analysis)
        finding = next(
            value
            for value in self.analysis["items"]
            if value["component_id"] == self.caller["id"]
        )
        profile = next(
            value
            for value in index["review_governance_profiles"]
            if value["finding_id"] == finding["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(profile["state"], "awaiting_finding_review")
        self.assertEqual(profile["next_action_id"], "review_finding")
        self.assertEqual(profile["source_change"], "new")
        self.assertEqual(profile["diagnostic_counts"], {"error": 1})
        self.assertFalse(profile["blocking_diagnostic_entity_ids"])
        self.assertTrue(profile["diagnostic_entity_ids"])
        diagnostic = next(
            value
            for value in index["entities"]
            if value["id"] == profile["diagnostic_entity_ids"][0]
        )
        self.assertEqual(diagnostic["kind"], "quality_gate_diagnostic")
        self.assertEqual(diagnostic["metadata"]["rule_id"], "review.unreviewed")
        self.assertEqual(diagnostic["metadata"]["scope"], "finding")
        self.assertEqual(chain["review_governance_profile_id"], profile["id"])
        self.assertEqual(chain["review_governance_state"], profile["state"])
        self.assertEqual(
            chain["quality_diagnostic_entity_ids"],
            profile["diagnostic_entity_ids"],
        )
        self.assertTrue(chain["dimensions"]["quality_governance"])
        global_ids = index["quality_gate_projection"]["global_diagnostic_entity_ids"]
        self.assertTrue(global_ids)
        self.assertTrue(set(global_ids).isdisjoint(profile["diagnostic_entity_ids"]))
        self.assertEqual(
            index["summary"]["quality_gate_diagnostics"],
            len(
                [
                    value
                    for value in index["entities"]
                    if value["kind"] == "quality_gate_diagnostic"
                ]
            ),
        )
        diagram = build_diagram_models(self.analysis, kind="cross_reference")[0]
        diagram_kinds = {value["kind"] for value in diagram["nodes"]}
        self.assertIn("review_governance_profile", diagram_kinds)
        self.assertIn("quality_gate_diagnostic", diagram_kinds)

        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_accepted_incomplete_finding_is_blocked_by_local_quality_gate(self) -> None:
        finding = self.analysis["items"][0]
        finding["review"]["disposition"] = "accepted"

        index = build_cross_reference_index(self.analysis)
        profile = next(
            value
            for value in index["review_governance_profiles"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(profile["state"], "blocked_by_validation")
        self.assertEqual(profile["next_action_id"], "resolve_quality_gate_diagnostics")
        self.assertTrue(profile["blocking_diagnostic_entity_ids"])
        self.assertGreater(profile["diagnostic_counts"]["error"], 0)
        self.assertTrue(
            any(
                value["kind"].startswith("quality_gate_finding_")
                and finding["id"] in " ".join(value["subject_ids"])
                for value in index["review_leads"]
            )
        )

    def test_verifier_rejects_review_governance_tampering(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["review_governance_profiles"][0]["next_action_id"] = "none"
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)

        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["review_governance_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_duplicate_quality_diagnostics_keep_distinct_verified_identity(
        self,
    ) -> None:
        diagnostic = {
            "rule_id": "synthetic.repeated",
            "level": "warning",
            "message": "Repeated bounded diagnostic.",
            "item_id": "",
            "component": "",
            "field": "context",
        }
        index = build_cross_reference_index(
            self.analysis,
            validation_report={"findings": [diagnostic, dict(diagnostic)]},
        )
        output = self.root / "duplicate-diagnostics.json"
        output.write_text(json.dumps(index), encoding="utf-8")

        diagnostic_entities = [
            value
            for value in index["entities"]
            if value["kind"] == "quality_gate_diagnostic"
        ]
        self.assertEqual(len(diagnostic_entities), 2)
        self.assertEqual(
            sorted(value["metadata"]["occurrence"] for value in diagnostic_entities),
            [1, 2],
        )
        verdict = verify_cross_reference_file(output)
        self.assertTrue(verdict["valid"])
        self.assertTrue(verdict["checks"]["review_governance_integrity"])

    def test_cross_links_adapter_runs_ledger_manifest_and_findings(self) -> None:
        index = build_cross_reference_index(self.analysis)
        finding = next(
            value
            for value in self.analysis["items"]
            if value["component_id"] == self.caller["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )
        provenance = index["adapter_provenance"]

        self.assertTrue(chain["adapter_run_entity_ids"])
        self.assertTrue(chain["adapter_provenance_relationship_ids"])
        self.assertTrue(chain["dimensions"]["tool_provenance"])
        self.assertIn("python.failure_rule_analyzer", chain["adapter_statuses"])
        self.assertEqual(
            chain["adapter_statuses"]["python.failure_rule_analyzer"],
            "completed",
        )
        self.assertTrue(
            any(
                value["adapter_id"] == "python.failure_rule_analyzer"
                and finding["id"] in value["linked_contribution_entity_ids"]
                for value in provenance["adapter_run_profiles"]
            )
        )
        entity_kinds = {value["id"]: value["kind"] for value in index["entities"]}
        self.assertEqual(
            entity_kinds[provenance["run_manifest_entity_id"]], "run_manifest"
        )
        self.assertEqual(
            entity_kinds[provenance["adapter_ledger_entity_id"]], "adapter_ledger"
        )
        self.assertEqual(
            index["summary"]["findings_with_tool_provenance"],
            len(index["finding_chains"]),
        )
        diagram = build_diagram_models(self.analysis, kind="cross_reference")[0]
        self.assertTrue(
            any(value["kind"] == "adapter_run" for value in diagram["nodes"])
        )

    def test_verifier_rejects_adapter_provenance_tampering(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        profile = tampered["adapter_provenance"]["adapter_run_profiles"][0]
        profile["unlinked_contribution_entity_ids"].append("FORGED-CONTRIBUTION")
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)

        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["adapter_provenance_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_cross_links_repository_inventory_sources_and_dependencies(self) -> None:
        (self.root / "requirements.txt").write_text(
            "httpx>=0.28,<1\n", encoding="utf-8"
        )
        (self.root / "opaque.asset").write_bytes(b"opaque")
        analysis = scan_repository(self.root)
        caller = next(
            value for value in analysis["components"] if value["qualname"] == "caller"
        )
        finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == caller["id"]
        )

        index = build_cross_reference_index(analysis)
        provenance = index["repository_provenance"]
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )
        entities = {value["id"]: value for value in index["entities"]}
        artifact = entities[chain["source_repository_artifact_entity_id"]]

        self.assertEqual(artifact["kind"], "repository_artifact")
        self.assertEqual(artifact["raw_id"], "app.py")
        self.assertEqual(chain["source_repository_path"], "app.py")
        self.assertEqual(chain["source_repository_status"], "analyzed")
        self.assertEqual(chain["source_analysis_depth"], "python_ast")
        self.assertRegex(chain["source_snapshot_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(chain["source_provenance_relationship_ids"])
        self.assertTrue(chain["dimensions"]["source_provenance"])
        self.assertFalse(provenance["unaccounted_component_ids"])
        self.assertFalse(provenance["unaccounted_finding_ids"])
        environment_finding_id = next(
            value["id"]
            for value in analysis["items"]
            if value["scanner"]["rule_id"] == "environment.dependency_drift"
        )
        environment_chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == environment_finding_id
        )
        self.assertGreaterEqual(
            len(environment_chain["source_repository_artifact_entity_ids"]), 1
        )
        self.assertTrue(environment_chain["dimensions"]["source_provenance"])
        self.assertTrue(provenance["opaque_repository_artifact_entity_ids"])
        self.assertTrue(provenance["dependency_entity_ids"])
        self.assertTrue(
            any(
                value["kind"] == "repository_artifacts_without_semantic_analysis"
                for value in index["review_leads"]
            )
        )
        dependency_profile = next(
            value
            for value in index["adapter_provenance"]["adapter_run_profiles"]
            if value["adapter_id"] == "python.dependency_inventory"
        )
        self.assertTrue(
            any(
                value.startswith("dependency:requirements.txt:")
                for value in dependency_profile["linked_contribution_entity_ids"]
            )
        )
        repository_profile = next(
            value
            for value in index["adapter_provenance"]["adapter_run_profiles"]
            if value["adapter_id"] == "python.repository_discoverer"
        )
        self.assertIn("app.py", repository_profile["linked_contribution_entity_ids"])
        self.assertEqual(
            index["summary"]["findings_with_repository_provenance"],
            index["summary"]["finding_chains"],
        )
        diagram = build_diagram_models(analysis, kind="cross_reference")[0]
        self.assertTrue(
            any(value["kind"] == "repository_artifact" for value in diagram["nodes"])
        )

    def test_verifier_rejects_repository_provenance_tampering(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["repository_provenance"][
            "opaque_repository_artifact_entity_ids"
        ].append("repository_artifact:forged")
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)

        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["repository_provenance_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_configuration_derived_findings_bind_to_manifest_input(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "project": {"name": "configured-source"},
                "common_causes": [
                    {
                        "id": "CC-SHARED",
                        "description": "Shared configuration corrupts behavior.",
                        "component_patterns": ["app.py:*"],
                        "hazards": [],
                        "requirements": [],
                        "causes": ["Invalid shared configuration"],
                        "controls": ["Independent configuration validation"],
                    }
                ],
            },
        )
        finding = next(
            value
            for value in analysis["items"]
            if value["scanner"]["rule_id"] == "common_cause.CC-SHARED"
        )

        index = build_cross_reference_index(analysis)
        provenance = index["repository_provenance"]
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )
        config_entity = next(
            value
            for value in index["entities"]
            if value["id"] == chain["source_configuration_input_entity_id"]
        )

        self.assertEqual(config_entity["kind"], "configuration_input")
        self.assertEqual(chain["source_repository_status"], "configured")
        self.assertEqual(chain["source_analysis_depth"], "project_configuration")
        self.assertRegex(chain["source_snapshot_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(chain["dimensions"]["source_provenance"])
        self.assertIn(finding["id"], provenance["configured_finding_ids"])
        self.assertNotIn(finding["id"], provenance["unaccounted_finding_ids"])
        self.assertEqual(
            index["summary"]["findings_with_source_provenance"],
            index["summary"]["finding_chains"],
        )

    def test_cross_links_machine_claims_summaries_and_lexical_conflicts(self) -> None:
        from jsonschema import Draft202012Validator

        finding = next(
            value
            for value in self.analysis["items"]
            if value["component_id"] == self.caller["id"]
        )
        finding["review"]["failure_mode"] = "remote service is available"
        citation_id = self.analysis["guidance"]["citations"][0]["id"]
        self.analysis["suggestions"] = [
            {
                "id": "SUG-CROSS-REFERENCE",
                "component_id": self.caller["id"],
                "component_reference": "app.py:caller",
                "origin": "machine_suggestion",
                "status": "proposed",
                "content": {
                    "failure_mode": "remote service is unavailable",
                    "trigger": "dependency outage",
                    "local_effect": "request fails",
                    "next_higher_effect": "workflow stops",
                },
                "evidence_ids": [
                    self.caller["id"],
                    finding["id"],
                    "UNKNOWN-EVIDENCE",
                ],
                "proposed_citation_ids": [citation_id, "UNKNOWN-CITATION"],
                "confidence": "medium",
                "provenance": {
                    "provider": "test-provider",
                    "model": "test-model",
                    "prompt_version": "test-prompt",
                    "baseline_id": self.analysis["project"]["baseline"]["id"],
                    "response_hash": "a" * 64,
                },
                "reviewer": "",
                "materialized_item_id": "",
            }
        ]
        self.analysis["generated_summaries"] = [
            {
                "id": "SUM-CROSS-REFERENCE",
                "group_by": "project",
                "key": "",
                "summary": "A bounded machine narrative for review.",
                "evidence_ids": [finding["id"], "UNKNOWN-SUMMARY-EVIDENCE"],
                "stale": True,
                "provider": "test-provider",
                "model": "test-model",
                "prompt_version": "test-prompt",
                "baseline_id": self.analysis["project"]["baseline"]["id"],
                "response_hash": "b" * 64,
            }
        ]

        index = build_cross_reference_index(self.analysis)
        machine = index["machine_assistance_provenance"]
        relationship_kinds = {
            value["kind"]
            for value in index["relationships"]
            if value["id"] in machine["relationship_ids"]
        }
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(index["summary"]["machine_suggestions"], 1)
        self.assertEqual(index["summary"]["machine_summaries"], 1)
        self.assertGreater(index["summary"]["machine_claim_relationships"], 0)
        self.assertIn("lexically_contradicts_claim", relationship_kinds)
        self.assertIn("grounded_in_supplied_evidence", relationship_kinds)
        self.assertIn("summarizes_supplied_evidence", relationship_kinds)
        self.assertEqual(
            set(chain["machine_assistance_entity_ids"]),
            {
                "machine_suggestion:SUG-CROSS-REFERENCE",
                "machine_summary:SUM-CROSS-REFERENCE",
            },
        )
        self.assertTrue(chain["dimensions"]["machine_assistance"])
        self.assertEqual(
            machine["unresolved_evidence_references"],
            [
                "SUG-CROSS-REFERENCE:UNKNOWN-EVIDENCE",
                "SUM-CROSS-REFERENCE:UNKNOWN-SUMMARY-EVIDENCE",
            ],
        )
        self.assertEqual(
            machine["unresolved_citation_references"],
            ["SUG-CROSS-REFERENCE:UNKNOWN-CITATION"],
        )
        lead_kinds = {value["kind"] for value in index["review_leads"]}
        self.assertIn("machine_claim_contradictions", lead_kinds)
        self.assertIn("stale_machine_summaries", lead_kinds)
        self.assertIn("unresolved_machine_assistance_references", lead_kinds)
        diagram = build_diagram_models(
            self.analysis, kind="cross_reference", cross_reference_index=index
        )[0]
        self.assertTrue(
            any(value["kind"] == "machine_suggestion" for value in diagram["nodes"])
        )
        self.assertTrue(
            any(value["kind"] == "machine_summary" for value in diagram["nodes"])
        )
        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_verifier_rejects_machine_assistance_profile_tampering(self) -> None:
        finding = self.analysis["items"][0]
        self.analysis["suggestions"] = [
            {
                "id": "SUG-TAMPER",
                "component_id": finding["component_id"],
                "component_reference": "app.py:caller",
                "origin": "machine_suggestion",
                "status": "proposed",
                "content": {"failure_mode": "A generated failure claim."},
                "evidence_ids": [finding["component_id"]],
                "proposed_citation_ids": [],
                "confidence": "low",
                "provenance": {},
                "reviewer": "",
                "materialized_item_id": "",
            }
        ]
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        standalone = verify_cross_reference_file(output)
        self.assertTrue(standalone["checks"]["system_context_integrity"])
        self.assertTrue(standalone["checks"]["lifecycle_provenance_integrity"])
        valid = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertTrue(valid["checks"]["machine_assistance_integrity"])

        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["machine_assistance_provenance"]["suggestion_profiles"][0][
            "evidence_entity_ids"
        ] = []
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["machine_assistance_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_cross_links_methodology_sources_citations_and_findings(self) -> None:
        from jsonschema import Draft202012Validator

        index = build_cross_reference_index(self.analysis)
        provenance = index["guidance_provenance"]
        cited_chain = next(
            value for value in index["finding_chains"] if value["citation_ids"]
        )
        cited_profile = next(
            value
            for value in provenance["citation_profiles"]
            if value["citation_id"] == cited_chain["citation_ids"][0]
        )
        source_profile = next(
            value
            for value in provenance["source_profiles"]
            if value["id"] == cited_profile["source_entity_id"]
        )
        relationship_kinds = {
            value["kind"]
            for value in index["relationships"]
            if value["id"] in provenance["relationship_ids"]
        }

        self.assertTrue(provenance["source_profiles"])
        self.assertTrue(provenance["review_check_profiles"])
        self.assertRegex(provenance["methodology_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(cited_chain["guidance_lineage_status"], "complete")
        self.assertTrue(cited_chain["dimensions"]["guidance_provenance"])
        self.assertIn(
            cited_profile["source_entity_id"],
            cited_chain["guidance_source_entity_ids"],
        )
        self.assertIn(cited_profile["id"], source_profile["citation_entity_ids"])
        self.assertIn("declares_methodology", relationship_kinds)
        self.assertIn("uses_methodology_source", relationship_kinds)
        self.assertIn("defines_review_check", relationship_kinds)
        self.assertIn("defines_guidance_citation", relationship_kinds)
        self.assertIn("supported_by_guidance", relationship_kinds)
        self.assertEqual(
            index["summary"]["guidance_citations_with_source_lineage"],
            index["summary"]["guidance_citations"],
        )
        self.assertEqual(index["summary"]["unresolved_guidance_source_references"], 0)

        diagram = build_diagram_models(
            self.analysis, kind="cross_reference", cross_reference_index=index
        )[0]
        self.assertTrue(
            any(value["kind"] == "guidance_source" for value in diagram["nodes"])
        )
        self.assertTrue(
            any(
                value["kind"] == "defines_guidance_citation"
                for value in diagram["edges"]
            )
        )
        Draft202012Validator(schema_document("cross-reference")).validate(index)

        output = self.root / "guidance-fabric.json"
        output.write_text(json.dumps(index), encoding="utf-8")
        verified = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["checks"]["guidance_provenance_integrity"])

    def test_verifier_rejects_rehashed_guidance_lineage_tampering(self) -> None:
        output = self.root / "guidance-fabric.json"
        export_cross_reference_index(self.analysis, output)
        original = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(
            verify_cross_reference_file(output)["checks"][
                "guidance_provenance_integrity"
            ]
        )

        tampered = json.loads(json.dumps(original))
        source_profile = tampered["guidance_provenance"]["source_profiles"][0]
        source_profile["source_record"]["title"] = "Rewritten guidance title"
        source_profile["source_record_sha256"] = canonical_json_sha256(
            source_profile["source_record"]
        )
        source_entity = next(
            value
            for value in tampered["entities"]
            if value["id"] == source_profile["id"]
        )
        source_entity["metadata"]["source_record_sha256"] = source_profile[
            "source_record_sha256"
        ]
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["guidance_provenance_integrity"])
        self.assertTrue(rejected["checks"]["content_integrity"])

        tampered = json.loads(json.dumps(original))
        chain = next(
            value for value in tampered["finding_chains"] if value["citation_ids"]
        )
        chain["guidance_source_entity_ids"] = []
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")
        rejected_chain = verify_cross_reference_file(output)
        self.assertFalse(rejected_chain["checks"]["finding_chain_integrity"])

    def test_cross_references_every_analysis_output_and_surfaces_unknowns(self) -> None:
        index = build_cross_reference_index(self.analysis)
        coverage = index["analysis_projection_coverage"]
        profiles = {value["section"]: value for value in coverage["section_profiles"]}

        self.assertEqual(set(profiles), set(self.analysis))
        self.assertEqual(coverage["coverage_percent"], 100.0)
        self.assertEqual(coverage["material_coverage_percent"], 100.0)
        self.assertEqual(coverage["record_coverage_percent"], 100.0)
        self.assertGreater(coverage["semantic_record_count"], 0)
        self.assertEqual(
            coverage["semantically_projected_record_count"],
            coverage["semantic_record_count"],
        )
        self.assertEqual(coverage["unresolved_record_count"], 0)
        self.assertEqual(coverage["record_profiles_omitted_by_bound"], 0)
        self.assertEqual(coverage["unmapped_section_names"], [])
        self.assertEqual(coverage["registered_without_projection_section_names"], [])
        self.assertEqual(
            profiles["schema_version"]["coverage_status"], "provenance_only"
        )
        self.assertEqual(
            profiles["runtime_evidence"]["coverage_status"],
            "semantically_projected",
        )
        self.assertEqual(
            profiles["graphify_reconciliation"]["coverage_status"],
            "semantically_projected",
        )
        self.assertEqual(profiles["suggestions"]["coverage_status"], "empty")
        section_relationships = [
            value
            for value in index["relationships"]
            if value["kind"] == "contains_analysis_section"
        ]
        self.assertEqual(len(section_relationships), len(self.analysis))
        self.assertEqual(
            index["summary"]["analysis_projection_relationships"],
            len(coverage["relationship_ids"]),
        )
        self.assertEqual(
            index["summary"]["analysis_record_projection_coverage_percent"],
            100.0,
        )
        self.assertFalse(
            any(
                value["kind"] == "unmapped_analysis_outputs"
                for value in index["review_leads"]
            )
        )

        diagram = build_diagram_models(
            self.analysis, kind="cross_reference", cross_reference_index=index
        )[0]
        diagram_kinds = {value["kind"] for value in diagram["nodes"]}
        self.assertIn("analysis_scope", diagram_kinds)
        self.assertIn("analysis_section", diagram_kinds)
        self.assertEqual(
            diagram["metadata"]["analysis_record_projection_coverage_percent"],
            100.0,
        )
        self.assertEqual(diagram["metadata"]["unresolved_analysis_records"], 0)

        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

        extended = json.loads(json.dumps(self.analysis))
        extended["experimental_scanner_output"] = {
            "records": [{"id": "EXPERIMENTAL-1"}]
        }
        extended_index = build_cross_reference_index(extended)
        extended_coverage = extended_index["analysis_projection_coverage"]
        self.assertEqual(
            extended_coverage["unmapped_section_names"],
            ["experimental_scanner_output"],
        )
        self.assertLess(extended_coverage["coverage_percent"], 100.0)
        self.assertLess(extended_coverage["material_coverage_percent"], 100.0)
        self.assertIn(
            "unmapped_analysis_outputs",
            {value["kind"] for value in extended_index["review_leads"]},
        )

        unresolved = json.loads(json.dumps(self.analysis))
        unresolved["resilience_semantics"]["effects"].append(
            {
                "component_reference": "missing.py:unknown_component",
                "direct_effects": ["persistence_write"],
                "transitive_effects": ["persistence_write"],
                "retry_factor": 1,
                "unprotected_retry_side_effect": False,
            }
        )
        unresolved_index = build_cross_reference_index(unresolved)
        unresolved_coverage = unresolved_index["analysis_projection_coverage"]
        self.assertEqual(unresolved_coverage["unresolved_record_count"], 1)
        self.assertLess(unresolved_coverage["record_coverage_percent"], 100.0)
        self.assertIn(
            "unresolved_analysis_record_projections",
            {value["kind"] for value in unresolved_index["review_leads"]},
        )
        unresolved_output = self.root / "unresolved-record-fabric.json"
        unresolved_output.write_text(json.dumps(unresolved_index), encoding="utf-8")
        unresolved_verdict = verify_cross_reference_file(unresolved_output)
        self.assertTrue(unresolved_verdict["valid"])
        self.assertTrue(unresolved_verdict["checks"]["analysis_projection_integrity"])

    def test_verifier_rejects_rehashed_analysis_projection_tampering(self) -> None:
        output = self.root / "projection-fabric.json"
        export_cross_reference_index(self.analysis, output)
        valid = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertTrue(valid["checks"]["analysis_projection_integrity"])

        tampered = json.loads(output.read_text(encoding="utf-8"))
        profile = next(
            value
            for value in tampered["analysis_projection_coverage"]["section_profiles"]
            if value["section"] == "components"
        )
        profile["projected_entity_count"] += 1
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output)
        self.assertFalse(rejected["valid"])
        self.assertTrue(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["analysis_projection_integrity"])

    def test_verifier_rejects_rehashed_record_witness_tampering(self) -> None:
        output = self.root / "record-projection-fabric.json"
        export_cross_reference_index(self.analysis, output)
        exported = output.read_text(encoding="utf-8")
        self.assertEqual(exported.count("\n"), 1)
        original = json.loads(exported)
        record_profile = next(
            value
            for value in original["analysis_projection_coverage"]["record_profiles"]
            if value["projected_entity_count"]
        )
        witness_id = next(
            relation_id
            for relation_id in record_profile["projection_relationship_ids"]
            if next(
                value
                for value in original["relationships"]
                if value["id"] == relation_id
            )["kind"]
            == "witnesses_projected_entity"
        )
        witness = next(
            value for value in original["relationships"] if value["id"] == witness_id
        )
        witness["metadata"]["projected_entity_id"] = "component:rewritten"
        content = dict(original)
        content.pop("content_sha256")
        original["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(original), encoding="utf-8")

        rejected = verify_cross_reference_file(output)

        self.assertFalse(rejected["valid"])
        self.assertTrue(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["analysis_projection_integrity"])

    def test_record_projection_bound_is_explicit_and_verifiable(self) -> None:
        with mock.patch("pysfmea.cross_reference.MAX_ANALYSIS_PROJECTION_RECORDS", 1):
            index = build_cross_reference_index(self.analysis)
            coverage = index["analysis_projection_coverage"]

            self.assertEqual(len(coverage["record_profiles"]), 1)
            self.assertEqual(
                coverage["record_profiles_omitted_by_bound"],
                coverage["semantic_record_count"] - 1,
            )
            self.assertEqual(
                coverage["unresolved_record_count"],
                coverage["semantic_record_count"] - 1,
            )
            self.assertLess(coverage["record_coverage_percent"], 100.0)
            self.assertIn(
                "unresolved_analysis_record_projections",
                {value["kind"] for value in index["review_leads"]},
            )
            output = self.root / "bounded-record-fabric.json"
            output.write_text(json.dumps(index), encoding="utf-8")
            verdict = verify_cross_reference_file(output)
            self.assertTrue(verdict["valid"])
            self.assertTrue(verdict["checks"]["analysis_projection_integrity"])

    def test_cross_references_system_context_and_lifecycle_history(self) -> None:
        self.analysis["system_context"] = build_system_context(
            {
                "project": {
                    "purpose": "Process governed workflows",
                    "boundary": "The scanned Python repository",
                    "operating_context": "Hosted service",
                    "operational_modes": ["Normal", "Maintenance"],
                    "system_states": ["Ready"],
                    "safe_states": ["Read only"],
                    "degraded_states": ["Queue requests"],
                }
            }
        )
        matched = self.analysis["items"][0]
        unmatched = self.analysis["items"][1]
        matched["review"].update(
            {
                "operational_mode": "  NORMAL  ",
                "operational_state": "Ready",
                "required_safe_state": "Read only",
                "degraded_behavior": "Queue requests",
                "recovery_behavior": "Drain the queue",
            }
        )
        matched["review_history"] = [
            {
                "event": "review_update",
                "at": "2026-08-13T12:00:00Z",
                "reviewer": "Jordan",
                "changes": {"operational_mode": {"before": "", "after": "  NORMAL  "}},
            }
        ]
        unmatched["review"]["operational_mode"] = "Emergency"
        self.analysis["history"] = [
            {
                "event": "finding_selected_for_review",
                "at": "2026-08-13T11:00:00Z",
                "item_id": matched["id"],
            },
            {
                "event": "orphan_subject_recorded",
                "at": "2026-08-13T11:30:00Z",
                "suggestion_id": "SUG-MISSING",
            },
        ]

        index = build_cross_reference_index(self.analysis)
        context = index["system_context_provenance"]
        lifecycle = index["lifecycle_provenance"]
        matched_chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == matched["id"]
        )
        unmatched_chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == unmatched["id"]
        )

        matched_profiles = [
            value
            for value in context["finding_claim_profiles"]
            if value["finding_id"] == matched["id"]
        ]
        self.assertEqual(
            next(
                value
                for value in matched_profiles
                if value["review_field"] == "operational_mode"
            )["alignment_status"],
            "matched",
        )
        self.assertEqual(
            next(
                value
                for value in matched_profiles
                if value["review_field"] == "recovery_behavior"
            )["alignment_status"],
            "not_cataloged",
        )
        self.assertIn("matched", matched_chain["system_context_alignment_statuses"])
        self.assertIn(
            "outside_catalog", unmatched_chain["system_context_alignment_statuses"]
        )
        self.assertTrue(matched_chain["dimensions"]["system_context"])
        self.assertTrue(matched_chain["dimensions"]["lifecycle_history"])
        self.assertTrue(matched_chain["lifecycle_event_entity_ids"])
        self.assertEqual(index["summary"]["analysis_lifecycle_events"], 2)
        self.assertEqual(index["summary"]["finding_review_events"], 1)
        self.assertEqual(
            lifecycle["unresolved_subject_references"][0].split(":")[-1],
            "SUG-MISSING",
        )
        lead_kinds = {value["kind"] for value in index["review_leads"]}
        self.assertIn("finding_context_claims_outside_resolved_catalog", lead_kinds)
        self.assertIn("finding_context_claims_without_catalog_field", lead_kinds)
        self.assertIn("unresolved_lifecycle_subject_references", lead_kinds)

        diagram = build_diagram_models(
            self.analysis, kind="cross_reference", cross_reference_index=index
        )[0]
        diagram_kinds = {value["kind"] for value in diagram["nodes"]}
        self.assertIn("finding_context_claim", diagram_kinds)
        self.assertIn("system_context_value", diagram_kinds)
        self.assertIn("lifecycle_event", diagram_kinds)
        self.assertIn("lifecycle_actor", diagram_kinds)

        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_verifier_rejects_context_and_lifecycle_tampering(self) -> None:
        self.analysis["system_context"] = build_system_context(
            {
                "project": {
                    "purpose": "Test",
                    "boundary": "Repository",
                    "operating_context": "Service",
                    "operational_modes": ["Normal"],
                }
            }
        )
        finding = self.analysis["items"][0]
        finding["review"]["operational_mode"] = "Normal"
        finding["review_history"] = [
            {
                "event": "review_update",
                "at": "2026-08-13T12:00:00Z",
                "reviewer": "Jordan",
                "changes": {"operational_mode": {"before": "", "after": "Normal"}},
            }
        ]
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        valid = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertTrue(valid["checks"]["system_context_integrity"])
        self.assertTrue(valid["checks"]["lifecycle_provenance_integrity"])

        context_tampered = json.loads(output.read_text(encoding="utf-8"))
        context_tampered["system_context_provenance"]["finding_claim_profiles"][0][
            "normalized_value"
        ] = "tampered"
        content = dict(context_tampered)
        content.pop("content_sha256")
        context_tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(context_tampered), encoding="utf-8")
        rejected_context = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertFalse(rejected_context["checks"]["system_context_integrity"])

        export_cross_reference_index(self.analysis, output)
        lifecycle_tampered = json.loads(output.read_text(encoding="utf-8"))
        lifecycle_tampered["lifecycle_provenance"]["finding_review_event_profiles"][0][
            "event_sha256"
        ] = "0" * 64
        content = dict(lifecycle_tampered)
        content.pop("content_sha256")
        lifecycle_tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(lifecycle_tampered), encoding="utf-8")
        rejected_lifecycle = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertFalse(rejected_lifecycle["checks"]["lifecycle_provenance_integrity"])

    def test_projects_test_candidates_and_coverage_without_promoting_evidence(
        self,
    ) -> None:
        (self.root / "test_app.py").write_text(
            "from app import caller\n\n\ndef test_caller():\n    assert caller() == 1\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        caller = next(
            value for value in analysis["components"] if value["qualname"] == "caller"
        )
        caller["coverage"] = {
            "line_percent": 100.0,
            "covered_lines": 2,
            "missing_lines": 0,
            "branch_percent": None,
            "covered_branches": 0,
            "missing_branches": 0,
        }
        finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == caller["id"]
        )

        index = build_cross_reference_index(analysis)
        profile = next(
            value
            for value in index["verification_readiness_profiles"]
            if value["finding_id"] == finding["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(profile["evidence_posture"], "candidate_tests_and_coverage")
        self.assertTrue(profile["evidence_signals"]["candidate_test_links"])
        self.assertTrue(profile["evidence_signals"]["coverage_observation"])
        self.assertFalse(profile["evidence_signals"]["execution_recorded"])
        self.assertFalse(profile["evidence_signals"]["terminal_verification"])
        self.assertTrue(profile["test_candidate_entity_ids"])
        self.assertTrue(profile["coverage_entity_ids"])
        self.assertEqual(chain["verification_readiness_profile_id"], profile["id"])
        self.assertTrue(chain["dimensions"]["verification_readiness"])
        self.assertEqual(
            chain["verification_evidence_posture"],
            "candidate_tests_and_coverage",
        )
        self.assertTrue(
            any(
                value["kind"] == "test_candidate"
                for value in index["entities"]
                if value["id"] in profile["test_candidate_entity_ids"]
            )
        )
        diagram = build_diagram_models(analysis, kind="cross_reference")[0]
        diagram_kinds = {value["kind"] for value in diagram["nodes"]}
        self.assertIn("verification_readiness_profile", diagram_kinds)
        self.assertIn("test_candidate", diagram_kinds)
        self.assertIn("coverage_observation", diagram_kinds)

        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_accepted_finding_readiness_gaps_are_prioritized(self) -> None:
        finding = self.analysis["items"][0]
        finding["review"]["disposition"] = "accepted"

        index = build_cross_reference_index(self.analysis)
        profile = next(
            value
            for value in index["verification_readiness_profiles"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(profile["lifecycle_state"], "definition_required")
        self.assertEqual(profile["next_action_id"], "define_assurance_contract")
        self.assertIn("accepted_finding_without_owner", profile["readiness_gaps"])
        self.assertIn("accepted_finding_without_reviewer", profile["readiness_gaps"])
        self.assertIn(
            "accepted_finding_without_registered_implementation",
            profile["readiness_gaps"],
        )
        lead_kinds = {value["kind"] for value in index["review_leads"]}
        self.assertIn(
            "verification_readiness_gap_accepted_finding_without_owner",
            lead_kinds,
        )
        self.assertGreater(
            index["summary"]["verification_readiness_gaps"][
                "accepted_finding_without_owner"
            ],
            0,
        )

    def test_verified_posture_requires_registered_execution_and_evidence(self) -> None:
        finding = self.analysis["items"][0]
        finding["review"].update(
            {
                "disposition": "accepted",
                "owner": "Verification Owner",
                "reviewer": "Finding Reviewer",
            }
        )
        obligation = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["finding_id"] == finding["id"]
        )
        obligation["assurance_status"] = "verified"
        obligation["evidence_status"] = "sufficient"
        obligation["evidence_artifact_ids"] = ["EVIDENCE-1"]
        obligation["automation"].update(
            {
                "implementation_status": "implemented",
                "implemented_test_path": "tests/test_app.py",
                "test_sha256": "a" * 64,
                "implementation_origin": "reviewed_manual_test",
            }
        )
        self.analysis["assurance"]["evidence_artifacts"].append(
            {"id": "EVIDENCE-1", "path": "evidence/junit.xml", "kind": "junit"}
        )
        self.analysis["assurance"]["executions"].append(
            {
                "id": "EXEC-1",
                "obligation_id": obligation["id"],
                "status": "passed",
                "reviews": [{"reviewer": "Independent Reviewer"}],
            }
        )

        index = build_cross_reference_index(self.analysis)
        profile = next(
            value
            for value in index["verification_readiness_profiles"]
            if value["finding_id"] == finding["id"]
        )

        self.assertEqual(profile["lifecycle_state"], "resolved")
        self.assertEqual(profile["next_action_id"], "none")
        self.assertEqual(
            profile["evidence_posture"], "verified_with_sufficient_evidence"
        )
        self.assertTrue(profile["implemented_test_entity_ids"])
        self.assertEqual(profile["execution_ids"], ["EXEC-1"])
        self.assertEqual(profile["evidence_artifact_ids"], ["EVIDENCE-1"])
        self.assertTrue(profile["evidence_signals"]["independent_execution_review"])
        self.assertTrue(profile["evidence_signals"]["terminal_verification"])
        self.assertFalse(profile["readiness_gaps"])
        self.assertTrue(
            verify_cross_reference_file(
                export_cross_reference_index(
                    self.analysis, self.root / "verified.json"
                ),
                analysis=self.analysis,
            )["valid"]
        )

    def test_verifier_rejects_verification_readiness_tampering(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["verification_readiness_profiles"][0]["evidence_posture"] = (
            "verified_with_sufficient_evidence"
        )
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)

        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["verification_readiness_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_cross_links_typed_exception_flow_with_disposition_metadata(self) -> None:
        (self.root / "exceptions.py").write_text(
            "class DomainError(Exception):\n"
            "    pass\n\n"
            "class ValidationError(DomainError):\n"
            "    pass\n\n"
            "def leaf():\n"
            "    raise ValidationError('invalid')\n\n"
            "def caller():\n"
            "    try:\n"
            "        leaf()\n"
            "    except DomainError:\n"
            "        pass\n"
            "    finally:\n"
            "        return None\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        components = {value["qualname"]: value for value in analysis["components"]}
        index = build_cross_reference_index(analysis)

        edge_entity = next(
            value
            for value in index["entities"]
            if value["kind"] == "exception_propagation_edge"
            and value["metadata"]["exception_type"] == "ValidationError"
        )
        self.assertEqual(
            edge_entity["metadata"]["disposition"], "caught_and_suppresses"
        )
        finalizer_entity = next(
            value
            for value in index["entities"]
            if value["kind"] == "exception_finalizer"
        )
        self.assertEqual(finalizer_entity["metadata"]["terminal_kind"], "return")
        self.assertTrue(finalizer_entity["metadata"]["unconditional_terminal"])
        handler_entity = next(
            value for value in index["entities"] if value["kind"] == "exception_handler"
        )
        self.assertEqual(handler_entity["metadata"]["outcome_kinds"], ["fallthrough"])
        self.assertEqual(handler_entity["metadata"]["outcome_certainty"], "uniform")
        self.assertFalse(handler_entity["metadata"]["may_reraise_original"])
        component_links = {
            (value["source"], value["kind"])
            for value in index["relationships"]
            if value["target"] == edge_entity["id"]
        }
        self.assertIn(
            (
                f"component:{components['leaf']['id']}",
                "has_exception_propagation_outgoing_edge",
            ),
            component_links,
        )
        self.assertTrue(
            any(
                value["source"] == f"component:{components['caller']['id']}"
                and value["target"] == finalizer_entity["id"]
                and value["kind"] == "has_exception_propagation_finalizer"
                for value in index["relationships"]
            )
        )
        self.assertIn(
            (
                f"component:{components['caller']['id']}",
                "has_exception_propagation_incoming_edge",
            ),
            component_links,
        )
        caller_profile = next(
            value
            for value in index["semantic_profiles"]
            if value["component_id"] == components["caller"]["id"]
        )
        self.assertTrue(caller_profile["dimensions"]["exception_propagation"])
        output = export_cross_reference_index(
            analysis, self.root / "typed-exception-fabric.json"
        )
        self.assertTrue(verify_cross_reference_file(output, analysis=analysis)["valid"])

    def test_dependency_finding_uses_resolved_artifact_path_in_source_chain(
        self,
    ) -> None:
        (self.root / "pyproject.toml").write_text(
            "[project]\n"
            "name = 'sample'\n"
            "version = '1.0.0'\n"
            "dependencies = ['httpx>=1']\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        dependency_finding = next(
            value
            for value in analysis["items"]
            if value["scanner"]["rule_id"] == "environment.dependency_drift"
        )
        index = build_cross_reference_index(analysis)
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == dependency_finding["id"]
        )

        self.assertEqual(chain["source_repository_path"], "pyproject.toml")
        self.assertEqual(
            chain["source_repository_artifact_entity_ids"],
            ["repository_artifact:pyproject.toml"],
        )
        output = export_cross_reference_index(
            analysis, self.root / "dependency-fabric.json"
        )
        self.assertTrue(verify_cross_reference_file(output, analysis=analysis)["valid"])

    def test_cross_links_cascades_timing_retries_and_breaker_models(self) -> None:
        (self.root / "resilience.py").write_text(
            "def downstream():\n"
            "    return client.get('https://service', timeout=5)\n\n"
            "@retry\n"
            "def upstream():\n"
            "    return downstream()\n\n"
            "class CircuitBreaker:\n"
            "    def allow_request(self):\n"
            "        if self.state == 'OPEN':\n"
            "            return False\n"
            "        return True\n\n"
            "    def record_failure(self):\n"
            "        self.failure_count += 1\n"
            "        if self.failure_count >= self.threshold:\n"
            "            self.state = 'OPEN'\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        components = {value["qualname"]: value for value in analysis["components"]}
        index = build_cross_reference_index(analysis)
        downstream = components["downstream"]
        downstream_finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == downstream["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == downstream_finding["id"]
        )

        self.assertTrue(chain["dimensions"]["cascade_analysis"])
        self.assertTrue(chain["dimensions"]["timing_and_resilience"])
        self.assertIn(components["upstream"]["id"], chain["cascade_component_ids"])
        self.assertTrue(chain["timing_relationship_ids"])
        self.assertTrue(chain["resilience_entity_ids"])
        kinds = {
            value["kind"]
            for value in index["entities"]
            if value["id"] in chain["resilience_entity_ids"]
        }
        self.assertIn("resilience_operation", kinds)
        upstream_finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == components["upstream"]["id"]
        )
        upstream_chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == upstream_finding["id"]
        )
        self.assertTrue(
            any(
                value["kind"] == "retry_path"
                and value["id"] in upstream_chain["resilience_entity_ids"]
                for value in index["entities"]
            )
        )

        breaker = components["CircuitBreaker.allow_request"]
        breaker_finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == breaker["id"]
        )
        breaker_chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == breaker_finding["id"]
        )
        self.assertTrue(
            any(
                value["kind"] == "circuit_breaker_model"
                and value["id"] in breaker_chain["resilience_entity_ids"]
                for value in index["entities"]
            )
        )
        diagram = build_diagram_models(analysis, kind="cross_reference")[0]
        self.assertTrue(
            any(
                value["kind"] in {"resilience_operation", "circuit_breaker_model"}
                for value in diagram["nodes"]
            )
        )
        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_cross_links_semantic_analyzers_and_compound_exposures(self) -> None:
        (self.root / "semantic.py").write_text(
            "import asyncio\n\n"
            "def require_scope(user_id, scope):\n"
            "    return bool(user_id and scope)\n\n"
            "def worker(tenant_id, state):\n"
            "    if state.status == 'running':\n"
            "        state.status = 'done'\n"
            "    return tenant_id\n\n"
            "async def endpoint(tenant_id, user_id, state):\n"
            "    require_scope(user_id, 'records:write')\n"
            "    if state.status == 'new':\n"
            "        state.status = 'running'\n"
            "    task = asyncio.create_task(worker(tenant_id, state))\n"
            "    await asyncio.gather(task)\n"
            "    return state.status\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        endpoint = next(
            value for value in analysis["components"] if value["qualname"] == "endpoint"
        )
        finding = next(
            value
            for value in analysis["items"]
            if value["component_id"] == endpoint["id"]
        )

        index = build_cross_reference_index(analysis)
        profile = next(
            value
            for value in index["semantic_profiles"]
            if value["component_id"] == endpoint["id"]
        )
        chain = next(
            value
            for value in index["finding_chains"]
            if value["finding_id"] == finding["id"]
        )

        self.assertTrue(profile["dimensions"]["data_flow"])
        self.assertTrue(profile["dimensions"]["authorization_scope"])
        self.assertTrue(profile["dimensions"]["concurrency"])
        self.assertTrue(profile["dimensions"]["state_machine"])
        self.assertEqual(chain["semantic_profile_id"], profile["id"])
        self.assertTrue(chain["dimensions"]["semantic_exposure"])
        self.assertIn(
            "authorization_context_crosses_data_flow",
            chain["compound_exposure_kinds"],
        )
        self.assertIn("concurrent_state_transition", chain["compound_exposure_kinds"])
        self.assertGreater(index["summary"]["semantic_profiles_with_records"], 0)
        self.assertGreater(index["summary"]["compound_exposure_chains"], 0)
        self.assertTrue(
            any(
                value["kind"]
                == "compound_semantic_exposure_authorization_context_crosses_data_flow"
                for value in index["review_leads"]
            )
        )
        entity_kinds = {
            value["kind"]
            for value in index["entities"]
            if value["id"] in chain["semantic_entity_ids"]
        }
        self.assertTrue(
            {
                "semantic_profile",
                "data_flow_edge",
                "authorization_context",
                "concurrency_operation",
                "state_transition",
            }
            <= entity_kinds
        )
        diagram = build_diagram_models(analysis, kind="cross_reference")[0]
        self.assertTrue(
            any(value["kind"] == "semantic_profile" for value in diagram["nodes"])
        )

        from jsonschema import Draft202012Validator

        Draft202012Validator(schema_document("cross-reference")).validate(index)

    def test_verifier_rejects_semantic_profile_reference_tampering(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["semantic_profiles"][0]["relationship_ids"].append("XREL-UNKNOWN")
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")

        rejected = verify_cross_reference_file(output, analysis=self.analysis)

        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["semantic_profile_integrity"])
        self.assertFalse(rejected["checks"]["exact_regeneration"])

    def test_aggregates_repetitive_sfta_reconciliation_leads(self) -> None:
        finding_ids = [value["id"] for value in self.analysis["items"][:2]]
        index = build_cross_reference_index(
            self.analysis,
            sfta_model={
                "trees": [],
                "reconciliation": {
                    "bottom_up_unmapped_findings": [
                        {"finding_id": finding_ids[0]},
                        {"finding_id": finding_ids[1]},
                    ]
                },
            },
        )
        leads = [
            value
            for value in index["review_leads"]
            if value["kind"] == "sfta_bottom_up_unmapped_findings"
        ]

        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["affected_count"], 2)
        self.assertEqual(
            leads[0]["subject_ids"],
            sorted(f"finding:{finding_id}" for finding_id in finding_ids),
        )

    def test_diagram_and_cli_export_are_available(self) -> None:
        diagram = build_diagram_models(self.analysis, kind="cross_reference")[0]
        self.assertEqual(diagram["id"], "cross-reference-evidence-fabric")
        self.assertTrue(any(value["kind"] == "finding" for value in diagram["nodes"]))

        analysis_path = self.root / "analysis.json"
        output = self.root / "fabric.json"
        save_analysis(analysis_path, self.analysis)
        self.assertEqual(
            main(["cross-reference", str(analysis_path), "-o", str(output)]),
            0,
        )
        exported = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exported["format"], CROSS_REFERENCE_FORMAT)
        self.assertEqual(
            exported["analysis_state_sha256"],
            build_cross_reference_index(self.analysis)["analysis_state_sha256"],
        )

    def test_verifier_detects_tampering_and_exact_analysis_drift(self) -> None:
        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)

        verdict = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertEqual(verdict["format"], CROSS_REFERENCE_VERIFICATION_FORMAT)
        self.assertTrue(verdict["valid"])
        self.assertEqual(verdict["status"], "matched")
        self.assertTrue(verdict["checks"]["exact_regeneration"])

        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["summary"]["relationships"] += 1
        output.write_text(json.dumps(tampered), encoding="utf-8")
        rejected = verify_cross_reference_file(output, analysis=self.analysis)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["summary_reconciliation"])

        tampered["summary"]["entities"] = "not-a-count"
        content = dict(tampered)
        content.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(content)
        output.write_text(json.dumps(tampered), encoding="utf-8")
        malformed_count = verify_cross_reference_file(output)
        self.assertFalse(malformed_count["valid"])
        self.assertEqual(malformed_count["entity_count"], 0)

    def test_cli_verifier_emits_schema_valid_verdicts(self) -> None:
        from jsonschema import Draft202012Validator

        analysis_path = self.root / "analysis.json"
        fabric_path = self.root / "fabric.json"
        save_analysis(analysis_path, self.analysis)
        export_cross_reference_index(self.analysis, fabric_path)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "cross-reference-verify",
                    str(fabric_path),
                    "--analysis",
                    str(analysis_path),
                    "--json",
                ]
            )
        verdict = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(verdict["valid"])
        Draft202012Validator(schema_document("cross-reference-verification")).validate(
            verdict
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "cross-reference-verify",
                    str(fabric_path),
                    "--analysis",
                    str(self.root / "missing-analysis.json"),
                    "--json",
                ]
            )
        rejected = json.loads(stdout.getvalue())
        self.assertEqual(status, 2)
        self.assertFalse(rejected["valid"])
        self.assertEqual(rejected["errors"][0]["code"], "analysis.load_failed")
        Draft202012Validator(schema_document("cross-reference-verification")).validate(
            rejected
        )

    def test_review_package_rejects_semantically_drifted_fabric(self) -> None:
        package = export_review_package(self.analysis, self.root / "review-package")
        verified = verify_review_package(package)
        self.assertTrue(verified["cross_reference"]["valid"])

        fabric_path = package / "cross-reference.json"
        fabric = json.loads(fabric_path.read_text(encoding="utf-8"))
        fabric["limitations"].append("Synthetic semantic drift for verification test.")
        fabric_without_digest = dict(fabric)
        fabric_without_digest.pop("content_sha256")
        fabric["content_sha256"] = canonical_json_sha256(fabric_without_digest)
        fabric_path.write_text(
            json.dumps(fabric, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw = fabric_path.read_bytes()
        entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "cross-reference.json"
        )
        entry["bytes"] = len(raw)
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        rejected = verify_review_package(package)
        self.assertFalse(rejected["valid"])
        self.assertTrue(rejected["cross_reference"]["checks"]["content_integrity"])
        self.assertFalse(rejected["cross_reference"]["checks"]["exact_regeneration"])
        self.assertTrue(
            any(
                finding["rule_id"] == "package.cross_reference_projection_invalid"
                for finding in rejected["findings"]
            )
        )

    def test_public_schemas_validate_artifact_and_verdict(self) -> None:
        from jsonschema import Draft202012Validator

        output = self.root / "fabric.json"
        export_cross_reference_index(self.analysis, output)
        fabric = json.loads(output.read_text(encoding="utf-8"))
        verdict = verify_cross_reference_file(output, analysis=self.analysis)

        Draft202012Validator(schema_document("cross-reference")).validate(fabric)
        Draft202012Validator(schema_document("cross-reference-verification")).validate(
            verdict
        )

    def test_public_schema_accepts_nested_repository_artifact_references(self) -> None:
        from jsonschema import Draft202012Validator

        nested = self.root / "nested"
        nested.mkdir()
        (nested / "worker.py").write_text(
            "def work():\n    return 1\n", encoding="utf-8"
        )
        analysis = scan_repository(self.root)
        fabric = build_cross_reference_index(analysis)

        self.assertTrue(
            any(
                value["id"] == "repository_artifact:nested/worker.py"
                for value in fabric["entities"]
            )
        )
        Draft202012Validator(schema_document("cross-reference")).validate(fabric)

    def test_static_control_flow_decisions_are_exact_semantic_records(self) -> None:
        (self.root / "pruned.py").write_text(
            "def choose():\n    if False:\n        return missing()\n    return 1\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        fabric = build_cross_reference_index(analysis)
        decision = next(
            value for value in analysis["static_control_flow_model"]["decisions"]
            if value["component_reference"] == "pruned.py:choose"
        )
        entity = next(
            value for value in fabric["entities"]
            if value["id"] == f"static_control_flow_decision:{decision['id']}"
        )
        self.assertEqual(entity["kind"], "static_control_flow_decision")
        self.assertTrue(
            any(
                value["channel"] == "static_control_flow"
                and value["target"] == entity["id"]
                for value in fabric["relationships"]
            )
        )
        coverage = next(
            value
            for value in fabric["analysis_projection_coverage"]["section_profiles"]
            if value["section"] == "static_control_flow_model"
        )
        self.assertEqual(coverage["coverage_status"], "semantically_projected")
        self.assertEqual(coverage["source_record_count"], 1)
        self.assertEqual(coverage["semantically_projected_record_count"], 1)
        diagram = build_diagram_models(analysis, kind="cross_reference")[0]
        self.assertTrue(
            any(
                value["kind"] == "static_control_flow_decision"
                for value in diagram["nodes"]
            )
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.enhancements import (
    ENHANCEMENT_SPECS,
    ENHANCEMENT_WORKBENCH_FORMAT,
    HARDENING_SPECS,
    NEXT_GENERATION_TITLES,
    POST_HARDENING_TITLES,
    PRODUCT_OUTCOME_TITLES,
    enhancement_scope_preview,
    enhancement_workbench,
    enhancement_workbench_markdown,
    evidence_preflight,
    export_enhancement_workbench,
    verify_enhancement_workbench_file,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis


class EnhancementWorkbenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "app.py").write_text(
            """
import asyncio
from fastapi import APIRouter

router = APIRouter(prefix='/events')

@router.post('/publish')
async def publish_event(queue, repository):
    await queue.publish({'state': 'ready'})
    await repository.commit()
    task = asyncio.create_task(queue.flush())
    return await task
""".lstrip(),
            encoding="utf-8",
        )
        (self.root / "client.ts").write_text(
            "export const BASE_URL = '/events';\n"
            "export const publish = () => fetch(`${BASE_URL}/publish`, "
            "{method: 'POST'});\n",
            encoding="utf-8",
        )
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_app.py").write_text(
            "def test_publish_event():\n    assert True\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_workbench_accounts_for_complete_backlog_and_is_deterministic(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "scan": {
                    "test_evidence_include": ["tests/**"],
                    "boundary_evidence_include": ["client.ts"],
                }
            },
        )

        first = enhancement_workbench(analysis)
        second = enhancement_workbench(analysis)

        self.assertEqual(first["format"], ENHANCEMENT_WORKBENCH_FORMAT)
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        self.assertEqual(first["summary"]["enhancements"], len(ENHANCEMENT_SPECS))
        self.assertEqual(first["summary"]["hardening_items"], 76)
        self.assertEqual(first["summary"]["post_hardening_items"], 82)
        self.assertEqual(first["summary"]["next_generation_items"], 102)
        self.assertEqual(first["summary"]["product_outcome_items"], 95)
        self.assertEqual(len(HARDENING_SPECS), 76)
        self.assertEqual(len(POST_HARDENING_TITLES), 82)
        self.assertEqual(len(NEXT_GENERATION_TITLES), 102)
        self.assertEqual(len(PRODUCT_OUTCOME_TITLES), 95)
        self.assertEqual(
            {value["id"] for value in first["hardening_register"]},
            {value.id for value in HARDENING_SPECS},
        )
        self.assertEqual(
            first["artifact_freshness"]["status"],
            "current",
        )
        self.assertEqual(first["artifact_health"]["overall_status"], "incomplete")
        self.assertEqual(len(first["post_hardening_register"]), 82)
        self.assertEqual(len(first["next_generation_register"]), 102)
        self.assertEqual(len(first["product_outcome_register"]), 95)
        self.assertEqual(
            first["summary"]["product_outcome_maturity"],
            {"planned": 0, "partial": 0, "implemented": 95, "validated": 0},
        )
        outcomes = {value["id"]: value for value in first["product_outcome_register"]}
        self.assertEqual(outcomes["E001"]["product_maturity"], "implemented")
        self.assertIn(
            "src/pysfmea/evidence_onboarding.py",
            outcomes["E001"]["implementation_evidence"],
        )
        self.assertEqual(outcomes["E002"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E008"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E009"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E010"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E012"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E016"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"][
                "interprocedural_data_flow"
            ]["resolved_call_edges"],
            analysis["interprocedural_data_flow"]["summary"]["resolved_call_edges"],
        )
        self.assertEqual(outcomes["E017"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["alias_object_flow"][
                "embedded_bindings"
            ],
            analysis["alias_object_flow"]["summary"]["embedded_bindings"],
        )
        self.assertEqual(outcomes["E019"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["concurrency_model"][
                "operations_embedded"
            ],
            analysis["concurrency_model"]["summary"]["operations_embedded"],
        )
        self.assertEqual(outcomes["E020"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["exception_propagation"][
                "propagation_edges_embedded"
            ],
            analysis["exception_propagation"]["summary"]["propagation_edges_embedded"],
        )
        self.assertEqual(outcomes["E021"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["state_machine_model"][
                "transitions_embedded"
            ],
            analysis["state_machine_model"]["summary"]["transitions_embedded"],
        )
        for identifier in ("E022", "E023", "E024", "E025", "E026", "E027"):
            self.assertEqual(outcomes[identifier]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["resilience_semantics"][
                "operations_embedded"
            ],
            analysis["resilience_semantics"]["summary"]["operations_embedded"],
        )
        self.assertEqual(outcomes["E029"]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"][
                "authorization_scope_flow"
            ]["flow_edges_embedded"],
            analysis["authorization_scope_flow"]["summary"]["flow_edges_embedded"],
        )
        self.assertEqual(outcomes["E031"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E032"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E033"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E034"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E064"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E091"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E093"]["product_maturity"], "implemented")
        self.assertEqual(outcomes["E095"]["product_maturity"], "implemented")
        for identifier in ("E071", "E075", "E080", "E081", "E084", "E087"):
            self.assertEqual(outcomes[identifier]["product_maturity"], "implemented")
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["contract_semantics"][
                "operations_embedded"
            ],
            analysis["contract_semantics"]["summary"]["operations_embedded"],
        )
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["deployment_topology"][
                "nodes_embedded"
            ],
            analysis["deployment_topology"]["summary"]["nodes_embedded"],
        )
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"]["shared_fate_analysis"][
                "regions"
            ],
            analysis["shared_fate_analysis"]["summary"]["regions"],
        )
        self.assertEqual(
            first["analysis_fidelity_program"]["observations"][
                "architecture_hierarchy"
            ]["nodes"],
            analysis["architecture_hierarchy"]["summary"]["nodes"],
        )
        self.assertEqual(outcomes["E042"]["product_maturity"], "implemented")
        self.assertTrue(outcomes["E042"]["implementation_evidence"])
        self.assertEqual(outcomes["E046"]["product_maturity"], "implemented")
        self.assertIn(
            "src/pysfmea/assurance_synthesis.py",
            outcomes["E046"]["implementation_evidence"],
        )
        self.assertEqual(outcomes["E050"]["product_maturity"], "implemented")
        self.assertFalse(
            any(
                value["resolution_state"] == "resolved_product_capability"
                for value in outcomes.values()
            )
        )
        self.assertEqual(first["capability_attestations"]["product_projection_gaps"], 0)
        self.assertEqual(first["resolution_attestations"]["product_projection_gaps"], 0)
        self.assertEqual(
            first["product_outcome_attestations"]["product_projection_gaps"], 0
        )
        self.assertEqual(
            first["product_outcome_scorecard"]["format"],
            "pysfmea-product-outcome-scorecard-1",
        )
        self.assertRegex(
            first["artifact_freshness"]["analysis_state_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(first["acceptance_targets"]["targets"][0]["target"], 70.0)
        self.assertTrue(first["precision_risks"]["insufficiently_calibrated_rules"])
        self.assertEqual(
            {value["id"] for value in first["capability_register"]},
            {value.id for value in ENHANCEMENT_SPECS},
        )
        self.assertTrue(first["review_clusters"])
        self.assertTrue(first["evidence_portfolio"])
        self.assertTrue(first["surface_models"]["events"])
        self.assertTrue(first["surface_models"]["concurrency"])
        self.assertTrue(first["review_campaign"]["calibration_samples"])
        self.assertTrue(first["review_campaign"]["batches"])
        self.assertEqual(
            first["finding_consolidation_program"]["status"], "implemented"
        )
        self.assertTrue(
            first["finding_consolidation_program"]["preservation_contract"][
                "member_evidence_and_citations_preserved"
            ]
        )
        self.assertEqual(
            first["evidence_onboarding"]["format"],
            "pysfmea-evidence-onboarding-1",
        )
        self.assertEqual(
            first["precision_program"]["suppression_policy"]["automatic_rule_tuning"],
            False,
        )
        self.assertEqual(
            first["llm_governance_program"]["format"],
            "pysfmea-llm-governance-program-1",
        )
        self.assertEqual(
            first["evidence_acquisition"]["mode"],
            "plan_only_no_repository_execution",
        )
        self.assertTrue(
            all("argv" in value for value in first["evidence_acquisition"]["steps"])
        )
        self.assertEqual(
            first["interface_disposition_queue"]["authority"],
            "review_queue_only_no_automatic_compatibility_or_defect_decision",
        )
        Draft202012Validator(schema_document("enhancement-workbench")).validate(first)

    def test_workbench_exports_json_and_markdown(self) -> None:
        analysis = scan_repository(self.root)
        json_path = self.root / "workbench.json"
        markdown_path = self.root / "workbench.md"

        export_enhancement_workbench(analysis, json_path)
        export_enhancement_workbench(analysis, markdown_path, output_format="markdown")

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["format"], ENHANCEMENT_WORKBENCH_FORMAT)
        markdown = markdown_path.read_text(encoding="utf-8")
        self.assertEqual(markdown, enhancement_workbench_markdown(payload))
        self.assertIn("Evidence acquisition", markdown)
        self.assertIn("Hardening resolution register", markdown)
        self.assertIn("Post-hardening resolution register", markdown)
        self.assertIn("Real-run resolution register", markdown)
        with self.assertRaisesRegex(ValueError, "json or markdown"):
            export_enhancement_workbench(
                analysis, self.root / "invalid.txt", output_format="xml"
            )

    def test_workbench_exposes_stale_runtime_evidence_without_credit(self) -> None:
        analysis = scan_repository(self.root)
        analysis["runtime_evidence"] = {
            "imports": [{"id": "TRACE-OLD", "baseline_id": "BASELINE-OLD"}],
            "spans": [],
            "edges": [],
        }

        workbench = enhancement_workbench(analysis)

        self.assertEqual(workbench["artifact_freshness"]["status"], "stale")
        self.assertEqual(
            workbench["artifact_freshness"]["runtime_imports"]["status"], "stale"
        )
        runtime_item = next(
            value for value in workbench["hardening_register"] if value["id"] == "H04"
        )
        self.assertEqual(
            runtime_item["resolution_state"],
            "project_evidence_required",
        )

    def test_workbench_does_not_score_an_excluded_web_boundary(self) -> None:
        analysis = scan_repository(
            self.root,
            config={"scan": {"exclude": ["client.ts"]}},
        )

        workbench = enhancement_workbench(analysis)

        scope_step = next(
            value
            for value in workbench["evidence_acquisition"]["steps"]
            if value["id"] == "review_evidence_scope"
        )
        self.assertEqual(scope_step["execution_boundary"], "read_only_planning")
        self.assertTrue(scope_step["configuration_suggestions"])
        self.assertEqual(workbench["scope_patch"]["status"], "review_required")
        self.assertIn(
            'boundary_evidence_include = ["client.ts"]',
            workbench["scope_patch"]["toml_preview"],
        )
        cross_stack = next(
            value
            for value in workbench["acceptance_targets"]["targets"]
            if value["id"] == "cross-stack"
        )
        self.assertEqual(cross_stack["status"], "unmeasured")
        self.assertIsNone(cross_stack["current"])

    def test_scope_preview_is_bounded_metadata_only_and_schema_valid(self) -> None:
        analysis = scan_repository(
            self.root,
            config={"scan": {"exclude": ["client.ts", "tests/**"]}},
        )

        preview = enhancement_scope_preview(analysis, self.root)

        self.assertEqual(preview["format"], "pysfmea-enhancement-scope-preview-1")
        self.assertEqual(preview["summary"]["matched_files"], 2)
        self.assertFalse(preview["summary"]["truncated"])
        self.assertEqual(
            {value["classification"] for value in preview["files"]},
            {"test_evidence_candidate", "web_boundary_candidate"},
        )
        self.assertTrue(all("sha256" not in value for value in preview["files"]))
        Draft202012Validator(schema_document("enhancement-scope-preview")).validate(
            preview
        )

        analysis_path = self.root / "scope-analysis.json"
        output_path = self.root / "scope-preview.json"
        save_analysis(analysis_path, analysis)
        expected_cli_preview = enhancement_scope_preview(analysis, self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main(
                [
                    "enhance-scope-preview",
                    str(analysis_path),
                    str(self.root),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(output_path.read_text(encoding="utf-8"))["content_sha256"],
            expected_cli_preview["content_sha256"],
        )

    def test_evidence_preflight_is_read_only_bound_and_schema_valid(self) -> None:
        analysis = scan_repository(self.root)
        result = evidence_preflight(analysis, self.root)

        self.assertEqual(result["format"], "pysfmea-evidence-preflight-1")
        self.assertGreaterEqual(result["summary"]["test_files"], 1)
        self.assertEqual(result["summary"]["coverage_status"], "missing")
        self.assertTrue(
            next(
                value
                for value in result["ordered_actions"]
                if value["id"] == "regenerate_coverage"
            )["required"]
        )
        Draft202012Validator(schema_document("evidence-preflight")).validate(result)

        analysis_path = self.root / "preflight-analysis.json"
        output_path = self.root / "evidence-preflight.json"
        save_analysis(analysis_path, analysis)
        expected_cli_result = evidence_preflight(analysis, self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main(
                [
                    "enhance-evidence-preflight",
                    str(analysis_path),
                    str(self.root),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(output_path.read_text(encoding="utf-8"))["content_sha256"],
            expected_cli_result["content_sha256"],
        )

    def test_cli_exports_workbench(self) -> None:
        analysis_path = self.root / "analysis.json"
        output_path = self.root / "enhancement-workbench.json"
        save_analysis(analysis_path, scan_repository(self.root))

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = main(
                [
                    "enhance",
                    str(analysis_path),
                    "-o",
                    str(output_path),
                ]
            )

        self.assertEqual(result, 0)
        self.assertIn("Exported enhancement workbench", captured.getvalue())
        self.assertEqual(
            json.loads(output_path.read_text(encoding="utf-8"))["format"],
            ENHANCEMENT_WORKBENCH_FORMAT,
        )

        verification = verify_enhancement_workbench_file(
            output_path,
            analysis=load_analysis(analysis_path),
        )
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["status"], "matched")
        Draft202012Validator(
            schema_document("enhancement-workbench-verification")
        ).validate(verification)

        verify_output = io.StringIO()
        with contextlib.redirect_stdout(verify_output):
            exit_code = main(
                [
                    "enhance-verify",
                    str(output_path),
                    "--analysis",
                    str(analysis_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(json.loads(verify_output.getvalue())["valid"])

        receipt_path = self.root / "enhancement-workbench-verification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            receipt_exit = main(
                [
                    "enhance-verify",
                    str(output_path),
                    "--analysis",
                    str(analysis_path),
                    "--output",
                    str(receipt_path),
                ]
            )
        self.assertEqual(receipt_exit, 0)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(receipt["valid"])
        Draft202012Validator(
            schema_document("enhancement-workbench-verification")
        ).validate(receipt)

        tampered = json.loads(output_path.read_text(encoding="utf-8"))
        tampered["summary"]["active_findings"] += 1
        output_path.write_text(json.dumps(tampered), encoding="utf-8")
        rejected = verify_enhancement_workbench_file(output_path)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])

    def test_verifier_rejects_rehashed_projection_based_capability_overclaim(
        self,
    ) -> None:
        analysis = scan_repository(self.root)
        output_path = self.root / "enhancement-workbench.json"
        export_enhancement_workbench(analysis, output_path)
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        deployment_model = next(
            value
            for value in payload["product_outcome_register"]
            if value["id"] == "E071"
        )
        deployment_model["product_maturity"] = "validated"
        deployment_model["resolution_state"] = "validated_product_capability"
        payload["summary"]["product_outcome_maturity"] = {
            "planned": 0,
            "partial": 0,
            "implemented": 94,
            "validated": 1,
        }
        payload.pop("content_sha256")
        payload["content_sha256"] = canonical_json_sha256(payload)
        output_path.write_text(json.dumps(payload), encoding="utf-8")

        rejected = verify_enhancement_workbench_file(output_path)

        self.assertFalse(rejected["valid"])
        self.assertTrue(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["product_outcome_semantics"])


if __name__ == "__main__":
    unittest.main()

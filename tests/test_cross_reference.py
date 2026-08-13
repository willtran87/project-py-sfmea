from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

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


class CrossReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
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


if __name__ == "__main__":
    unittest.main()

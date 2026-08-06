from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.config import write_config_template
from pysfmea.diagrams import interface_flow_diagram
from pysfmea.discovery import (
    OpenAICompatibleProvider,
    deterministic_summary,
    discover_suggestions,
    evaluate_candidates,
    evidence_packets,
    generate_summary,
    review_suggestion,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.publication import (
    PUBLICATION_FAILURE_CATALOG_ALGORITHM,
    PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
    PUBLICATION_FAILURE_CATALOG_FORMAT,
    PUBLICATION_FAILURE_CATALOG_SHA256,
    PUBLICATION_FAILURES,
)
from pysfmea.readiness import repository_readiness
from pysfmea.report import (
    REVIEW_PACKAGE_SCHEMA_FILES,
    _verify_analysis_structure,
    _verify_review_views,
    analysis_state_sha256,
    export_inventory,
    export_review_archive,
    export_review_package,
    verify_review_package,
)
from pysfmea.runtime import import_runtime_trace
from pysfmea.scanner import scan_repository
from pysfmea.schemas import REVIEW_PACKAGE_VERIFICATION_FORMAT, schema_document
from pysfmea.signing import sign_review_package, verify_review_signature
from pysfmea.store import load_analysis, merge_rescan, save_analysis
from pysfmea.version import __version__
from pysfmea.visuals import (
    coverage_metrics,
    export_coverage,
    export_sequence,
    export_traceability,
    sequence_model,
    traceability_model,
)


class StaticProvider:
    name = "test-provider"
    model = "test-model"

    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        component_id = payload["component"]["evidence_id"]
        return {
            "suggestions": [
                {
                    "failure_class": "security",
                    "guideword": "Bypass",
                    "failure_mode": "The authorization boundary permits an unauthorized operation.",
                    "trigger": "A crafted request reaches the entrypoint.",
                    "causes": ["Authorization is evaluated after the protected operation."],
                    "local_effect": "The operation executes without a valid authorization decision.",
                    "next_higher_effect": "The service exposes a protected capability.",
                    "possible_end_effects": ["Protected data or operations may be exposed."],
                    "prevention_controls": [],
                    "detection_controls": [],
                    "recommended_actions": ["Enforce authorization before side effects."],
                    "evidence_ids": [component_id],
                    "citation_ids": ["NIST-SP-800-218-PW.7"],
                    "uncertainties": ["The external identity contract was not supplied."],
                    "questions": ["Where is authorization enforced?"],
                    "confidence": "medium",
                }
            ]
        }


class UnsafeProvider(StaticProvider):
    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        result = super().generate(payload, task=task)
        result["suggestions"][0]["severity"] = 10
        return result


class UnknownCitationProvider(StaticProvider):
    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        result = super().generate(payload, task=task)
        result["suggestions"][0]["citation_ids"] = ["NASA-INVENTED-CLAUSE"]
        return result


class ExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def validate(value):\n    return bool(value)\n\n"
            "def charge(value):\n    return value * 2\n\n"
            "def checkout(value):\n    validate(value)\n    return charge(value)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "requirements": [
                    {
                        "id": "REQ-1",
                        "text": "Process valid requests.",
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
                "component_mappings": [
                    {
                        "pattern": "service.py:checkout",
                        "requirements": ["REQ-1"],
                        "hazards": ["HZ-1"],
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sequence_traceability_and_coverage_exports(self) -> None:
        model = sequence_model(self.analysis, "service.py:checkout")
        labels = [value["label"] for value in model["interactions"]]
        self.assertEqual(labels[:2], ["validate", "charge"])
        sequence_path = export_sequence(
            self.analysis, self.root / "sequence.md", "service.py:checkout"
        )
        self.assertIn("sequenceDiagram", sequence_path.read_text(encoding="utf-8"))
        trace = traceability_model(self.analysis)
        self.assertTrue(any(edge["kind"] == "may_contribute_to" for edge in trace["edges"]))
        self.assertTrue(any(edge["kind"] == "mitigates" for edge in trace["edges"]))
        self.assertIn(
            "flowchart LR",
            export_traceability(self.analysis, self.root / "trace.md").read_text(
                encoding="utf-8"
            ),
        )
        bounded = sequence_model(
            self.analysis, "service.py:checkout", max_interactions=1
        )
        self.assertEqual(len(bounded["interactions"]), 1)
        self.assertTrue(bounded["truncated"])
        self.assertIn("max_interactions", bounded["truncation_reasons"])

    def test_sequence_retains_control_flow_await_and_interface_candidates(self) -> None:
        (self.root / "flow.py").write_text(
            "import httpx\n\n"
            "def normalize(value):\n    return value\n\n"
            "async def orchestrate(client, enabled):\n"
            "    if enabled:\n"
            "        await client.send()\n"
            "    else:\n"
            "        httpx.get('https://example.invalid')\n"
            "    try:\n"
            "        return normalize(enabled)\n"
            "    except ValueError:\n"
            "        return normalize(False)\n\n"
            "class Alpha:\n"
            "    def dispatch(self):\n"
            "        return 1\n\n"
            "class Beta:\n"
            "    def dispatch(self):\n"
            "        return 2\n\n"
            "def ambiguous():\n"
            "    return dispatch()\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        component = next(
            value
            for value in analysis["components"]
            if value.get("qualname") == "orchestrate"
        )
        candidates = {
            value["reference"]: value
            for value in component["external_call_candidates"]
        }
        self.assertEqual(candidates["httpx.get"]["confidence"], "high")
        self.assertEqual(candidates["client.send"]["confidence"], "medium")

        model = sequence_model(analysis, "flow.py:orchestrate")
        send = next(
            value for value in model["interactions"] if value["label"] == "client.send"
        )
        normalized = [
            value for value in model["interactions"] if value["label"] == "normalize"
        ]
        self.assertTrue(send["awaited"])
        self.assertIn("if@7:body", send["control_context"])
        self.assertEqual(send["evidence"], "static_external_candidate")
        self.assertEqual(len(normalized), 2)
        self.assertTrue(
            any("handler-1" in " ".join(value["control_context"]) for value in normalized)
        )

        sequence_path = export_sequence(
            analysis, self.root / "flow-sequence.md", "flow.py:orchestrate"
        )
        document = sequence_path.read_text(encoding="utf-8")
        self.assertIn("[static candidate]", document)
        self.assertIn("[await]", document)
        interface_diagram = interface_flow_diagram(analysis)
        self.assertEqual(
            interface_diagram["metadata"]["external_candidates_total"], 2
        )
        self.assertEqual(
            {
                edge["evidence"]
                for edge in interface_diagram["edges"]
                if edge["kind"] == "external_interface_candidate"
            },
            {"static_candidate"},
        )
        ambiguous = sequence_model(analysis, "flow.py:ambiguous")
        ambiguous_calls = [
            value
            for value in ambiguous["interactions"]
            if value["label"] == "dispatch"
        ]
        self.assertEqual(len(ambiguous_calls), 2)
        self.assertEqual(
            {value["confidence"] for value in ambiguous_calls}, {"low"}
        )
        self.assertEqual(
            {value["resolution"] for value in ambiguous_calls},
            {"ambiguous_static_internal_call"},
        )

        normalize = next(
            value for value in analysis["components"] if value.get("qualname") == "normalize"
        )
        analysis["runtime_evidence"] = {
            "imports": [],
            "spans": [],
            "edges": [
                {
                    "trace_id": "T",
                    "source_component_id": component["id"],
                    "target_component_id": normalize["id"],
                    "source_name": "orchestrate",
                    "target_name": "normalize",
                    "operation": "normalize",
                    "start_time": "10",
                    "end_time": "20",
                    "timing_status": "observed",
                    "duration_ns": 10,
                },
                {
                    "trace_id": "T",
                    "source_component_id": normalize["id"],
                    "target_component_id": component["id"],
                    "source_name": "normalize",
                    "target_name": "orchestrate",
                    "operation": "dynamic callback",
                    "timing_status": "unavailable",
                },
            ],
        }
        reconciled = sequence_model(analysis, "flow.py:orchestrate")
        self.assertEqual(reconciled["reconciliation"]["corroborated_relations"], 1)
        self.assertEqual(reconciled["reconciliation"]["runtime_only_relations"], 1)
        self.assertEqual(
            reconciled["reconciliation"]["runtime_timing_statuses"],
            {"observed": 1, "unavailable": 1},
        )
        self.assertTrue(
            all(
                value.get("observation_status") == "runtime_corroborated"
                for value in reconciled["interactions"]
                if value["label"] == "normalize" and value["evidence"] == "static_ast"
            )
        )
        self.assertTrue(
            any(
                value.get("static_alignment") == "runtime_only"
                for value in reconciled["interactions"]
            )
        )

    def test_type_evidence_resolves_receivers_and_nested_call_order(self) -> None:
        (self.root / "typed_flow.py").write_text(
            "from httpx import AsyncClient\n\n"
            "class LocalClient:\n"
            "    def fetch(self):\n"
            "        return 1\n\n"
            "def normalize(value):\n"
            "    return value\n\n"
            "def wrap(value):\n"
            "    return value\n\n"
            "async def external(client: AsyncClient):\n"
            "    return await client.get('https://example.invalid')\n\n"
            "def local(client: LocalClient):\n"
            "    return client.fetch()\n\n"
            "def constructed():\n"
            "    client = LocalClient()\n"
            "    return client.fetch()\n\n"
            "def nested():\n"
            "    return wrap(normalize(True))\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        components = {
            value["qualname"]: value
            for value in analysis["components"]
            if value.get("source", {}).get("path") == "typed_flow.py"
        }
        external = components["external"]
        self.assertEqual(external["symbol_types"]["client"], "httpx.AsyncClient")
        self.assertEqual(
            external["external_call_candidates"][0]["basis"],
            "typed_receiver_known_external_api",
        )
        self.assertEqual(
            external["call_sites"][0]["resolution"], "parameter_annotation"
        )
        local_model = sequence_model(analysis, "typed_flow.py:local")
        self.assertEqual(local_model["interactions"][0]["label"], "fetch")
        self.assertEqual(local_model["interactions"][0]["confidence"], "high")
        constructed_model = sequence_model(analysis, "typed_flow.py:constructed")
        self.assertTrue(
            any(value["label"] == "fetch" for value in constructed_model["interactions"])
        )
        nested = components["nested"]
        self.assertEqual(nested["ordered_calls"], ["normalize", "wrap"])

    def test_repository_readiness_guides_pre_scan_setup(self) -> None:
        missing = repository_readiness(self.root)
        self.assertFalse(missing["ready"])
        self.assertTrue(
            any(check["id"] == "configuration.file" for check in missing["checks"])
        )
        write_config_template(self.root / "sfmea.toml")
        unchanged_template = repository_readiness(self.root)
        self.assertFalse(unchanged_template["ready"])
        self.assertTrue(
            any(
                check["id"] == "configuration.example_template"
                for check in unchanged_template["checks"]
            )
        )
        config_path = self.root / "sfmea.toml"
        configured = (
            config_path.read_text(encoding="utf-8")
            .replace("Example Python System", "Checkout Service")
            .replace("Example unacceptable system condition", "Incorrect checkout")
            .replace("Example reviewer", "Jordan Lee")
            .replace("src/example/", "")
        )
        config_path.write_text(configured, encoding="utf-8")
        ready = repository_readiness(self.root)
        self.assertTrue(ready["ready"])
        self.assertGreater(ready["counts"]["pass"], 0)

    def test_traceability_namespaces_catalog_ids(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "hazards": [{"id": "SHARED", "description": "Hazard"}],
                "requirements": [
                    {"id": "SHARED", "text": "Requirement", "hazards": ["SHARED"]}
                ],
            },
        )
        model = traceability_model(analysis)
        shared = [node for node in model["nodes"] if node.get("reference_id") == "SHARED"]
        self.assertEqual({node["kind"] for node in shared}, {"requirement", "hazard"})
        self.assertEqual(len({node["id"] for node in shared}), 2)
        metrics = coverage_metrics(self.analysis)
        self.assertEqual(metrics["requirements"]["coverage_percent"], 100.0)
        self.assertEqual(
            metrics["repository_artifacts"]["reconciliation_status"], "reconciled"
        )
        self.assertEqual(
            metrics["repository_artifacts"]["files"],
            len(self.analysis["repository_inventory"]["entries"]),
        )
        self.assertIn(
            "SFMEA analysis coverage",
            export_coverage(self.analysis, self.root / "coverage.md").read_text(
                encoding="utf-8"
            ),
        )
        self.analysis["repository_inventory"]["summary"]["files"] += 999
        recomputed = coverage_metrics(self.analysis)["repository_artifacts"]
        self.assertEqual(recomputed["reconciliation_status"], "recomputed")
        self.assertEqual(
            recomputed["files"],
            len(self.analysis["repository_inventory"]["entries"]),
        )

    def test_runtime_trace_import_adds_observed_sequence_edges(self) -> None:
        trace_path = self.root / "trace.json"
        trace_path.write_text(
            json.dumps(
                {
                    "spans": [
                        {"trace_id": "T1", "span_id": "S1", "name": "checkout"},
                        {
                            "trace_id": "T1",
                            "span_id": "S2",
                            "parent_span_id": "S1",
                            "name": "charge",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        record = import_runtime_trace(self.analysis, trace_path, label="checkout test")
        self.assertEqual(record["mapped_span_count"], 2)
        model = sequence_model(self.analysis, "service.py:checkout")
        self.assertTrue(
            any(value["evidence"] == "observed_runtime" for value in model["interactions"])
        )
        history_count = len(self.analysis["history"])
        duplicate = import_runtime_trace(self.analysis, trace_path, label="duplicate")
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(len(self.analysis["runtime_evidence"]["imports"]), 1)
        self.assertEqual(len(self.analysis["history"]), history_count)
        self.assertEqual(self.analysis["summary"]["runtime_mapped_spans"], 2)

    def test_runtime_trace_import_is_bounded_link_safe_and_transactional(self) -> None:
        trace_path = self.root / "bounded-trace.json"
        payload = {
            "spans": [
                {"trace_id": "T1", "span_id": "S1", "name": "checkout"},
                {
                    "trace_id": "T1",
                    "span_id": "S2",
                    "parent_span_id": "S1",
                    "name": "charge",
                },
            ]
        }
        trace_bytes = json.dumps(payload).encode("utf-8")
        trace_path.write_bytes(trace_bytes)
        original_analysis = copy.deepcopy(self.analysis)

        with patch("pysfmea.runtime.MAX_RUNTIME_TRACE_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "10-byte import limit"):
                import_runtime_trace(self.analysis, trace_path)
        self.assertEqual(self.analysis, original_analysis)

        trace_path.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 JSON"):
            import_runtime_trace(self.analysis, trace_path)
        trace_path.write_text("1", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "root must be an object or array"):
            import_runtime_trace(self.analysis, trace_path)
        trace_path.write_bytes(trace_bytes)

        trace_text = trace_bytes.decode("utf-8")
        trace_path.write_text(
            '{"spans":[],"spans":' + trace_text.split('"spans":', 1)[1],
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            import_runtime_trace(self.analysis, trace_path)
        for value in ("NaN", "1e9999"):
            with self.subTest(non_finite=value):
                trace_path.write_text(
                    '{"numeric_probe":' + value + "," + trace_text[1:],
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "non-finite number"):
                    import_runtime_trace(self.analysis, trace_path)
        trace_path.write_bytes(trace_bytes)
        with patch("pysfmea.runtime.MAX_RUNTIME_JSON_NODES", 2):
            with self.assertRaisesRegex(ValueError, "2-node JSON structure limit"):
                import_runtime_trace(self.analysis, trace_path)
        with patch(
            "pysfmea.json_ingestion._same_file_identity", side_effect=[True, False]
        ):
            with self.assertRaisesRegex(ValueError, "changed during bounded consumption"):
                import_runtime_trace(self.analysis, trace_path)
        with patch("pysfmea.json_ingestion.stat.S_ISLNK", return_value=True):
            with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
                import_runtime_trace(self.analysis, trace_path)
        with self.assertRaisesRegex(ValueError, "500 printable"):
            import_runtime_trace(self.analysis, trace_path, label="x" * 501)
        with patch("pysfmea.runtime.MAX_SPANS_PER_IMPORT", 1):
            with self.assertRaisesRegex(ValueError, "exceeds 1 spans"):
                import_runtime_trace(self.analysis, trace_path)
        self.assertEqual(self.analysis, original_analysis)

        trace_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no recognizable spans"):
            import_runtime_trace(self.analysis, trace_path)
        self.assertEqual(self.analysis, original_analysis)

        trace_path.write_text(
            json.dumps(
                {
                    "spans": [
                        {
                            "trace_id": "T1",
                            "span_id": "S1",
                            "name": "checkout",
                            "attributes": {"a": {"b": {"c": {"d": 1}}}},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with patch("pysfmea.runtime.MAX_RUNTIME_ATTRIBUTE_DEPTH", 2):
            with self.assertRaisesRegex(ValueError, "nesting exceeds 2 levels"):
                import_runtime_trace(self.analysis, trace_path)
        self.assertEqual(self.analysis, original_analysis)

        trace_path.write_bytes(trace_bytes)
        with patch(
            "pysfmea.runtime.refresh_summary",
            side_effect=RuntimeError("summary refresh failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "summary refresh failed"):
                import_runtime_trace(self.analysis, trace_path)
        self.assertEqual(self.analysis, original_analysis)

    def test_review_package_bounds_analysis_structure_before_projection(self) -> None:
        node_verdict = _verify_analysis_structure(
            {"values": [1, 2, 3]}, max_depth=10, max_nodes=4
        )
        self.assertFalse(node_verdict["valid"])
        self.assertFalse(node_verdict["checks"]["node_limit"])
        self.assertEqual(node_verdict["node_count"], 5)

        malformed_core_values = {
            "items": ["bad"],
            "components": {},
            "context": [],
            "assurance": [],
            "runtime_evidence": [],
            "project": [],
            "repository_inventory": [],
            "adapter_runs": [],
            "system_context": [],
        }
        for field, value in malformed_core_values.items():
            with self.subTest(field=field):
                malformed = copy.deepcopy(self.analysis)
                malformed[field] = value
                contract_verdict = _verify_analysis_structure(malformed)
                self.assertFalse(contract_verdict["valid"])
                self.assertFalse(contract_verdict["checks"]["core_contract"])
                self.assertTrue(
                    any(
                        error["code"] == "analysis_structure.core_contract"
                        for error in contract_verdict["errors"]
                    )
                )
        malformed_nested_values = {
            "context.analysis": ("context", "analysis"),
            "context.risk": ("context", "risk"),
            "context.quality": ("context", "quality"),
            "methodology.basis": ("methodology", "basis"),
            "run_manifest.adapters": ("run_manifest", "adapters"),
        }
        for label, (parent, field) in malformed_nested_values.items():
            with self.subTest(path=label):
                malformed = copy.deepcopy(self.analysis)
                malformed[parent][field] = ["bad"]
                contract_verdict = _verify_analysis_structure(malformed)
                self.assertFalse(contract_verdict["valid"])
                self.assertFalse(contract_verdict["checks"]["core_contract"])
        malformed_leaf_values = {
            "linked_hazards": (
                ("items", 0, "review", "linked_hazards"),
                [{}],
            ),
            "finding_citation_id": (
                ("items", 0, "scanner", "citations", 0, "citation_id"),
                [],
            ),
            "fault_tree_hazard": (
                ("context", "fault_trees"),
                [
                    {
                        "id": "T",
                        "hazard": {},
                        "top_event_id": "E",
                        "top_event": "Invalid tree",
                        "events": [],
                        "gates": [],
                    }
                ],
            ),
            "quality_level": (
                ("context", "quality", "unreviewed_level"),
                [],
            ),
            "risk_categories": (
                ("context", "risk", "severity_categories"),
                [{}],
            ),
            "guidance_citation_id": (
                ("guidance", "citations", 0, "id"),
                [],
            ),
        }
        for label, (path, value) in malformed_leaf_values.items():
            with self.subTest(leaf=label):
                malformed = copy.deepcopy(self.analysis)
                cursor: Any = malformed
                for segment in path[:-1]:
                    cursor = cursor[segment]
                cursor[path[-1]] = value
                contract_verdict = _verify_analysis_structure(malformed)
                self.assertFalse(contract_verdict["valid"])
                self.assertFalse(contract_verdict["checks"]["core_contract"])

        destination = export_review_package(
            self.analysis, self.root / "bounded-review-package"
        )
        analysis_path = destination / "analysis.json"
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        nested: dict[str, Any] = {}
        analysis["adversarial_extension"] = nested
        for _index in range(105):
            child: dict[str, Any] = {}
            nested["child"] = child
            nested = child
        analysis_path.write_text(
            json.dumps(analysis, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        analysis_raw = analysis_path.read_bytes()
        analysis_entry = next(
            value for value in manifest["files"] if value["path"] == "analysis.json"
        )
        analysis_entry["bytes"] = len(analysis_raw)
        analysis_entry["sha256"] = hashlib.sha256(analysis_raw).hexdigest()
        manifest["analysis_state_sha256"] = analysis_state_sha256(analysis)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        verified = verify_review_package(destination)
        self.assertFalse(verified["valid"])
        self.assertFalse(verified["analysis_structure"]["valid"])
        self.assertFalse(
            verified["analysis_structure"]["checks"]["depth_limit"]
        )
        self.assertGreater(verified["analysis_structure"]["max_depth"], 100)
        self.assertIn(
            "package.analysis_structure_limit",
            {value["rule_id"] for value in verified["findings"]},
        )
        self.assertNotIn(
            "package.checksum_mismatch",
            {value["rule_id"] for value in verified["findings"]},
        )
        Draft202012Validator(
            schema_document("review-package-verification")
        ).validate(verified)

        export_review_package(self.analysis, destination, overwrite=True)
        analysis_path = destination / "analysis.json"
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        analysis["items"] = ["malformed-item"]
        analysis_path.write_text(
            json.dumps(analysis, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        analysis_raw = analysis_path.read_bytes()
        analysis_entry = next(
            value for value in manifest["files"] if value["path"] == "analysis.json"
        )
        analysis_entry["bytes"] = len(analysis_raw)
        analysis_entry["sha256"] = hashlib.sha256(analysis_raw).hexdigest()
        manifest["analysis_state_sha256"] = analysis_state_sha256(analysis)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        malformed_verified = verify_review_package(destination)
        self.assertFalse(malformed_verified["valid"])
        self.assertFalse(
            malformed_verified["analysis_structure"]["checks"]["core_contract"]
        )
        malformed_rules = {
            value["rule_id"] for value in malformed_verified["findings"]
        }
        self.assertIn("package.analysis_contract_invalid", malformed_rules)
        self.assertNotIn("package.checksum_mismatch", malformed_rules)
        Draft202012Validator(
            schema_document("review-package-verification")
        ).validate(malformed_verified)

        with patch(
            "pysfmea.report._verify_review_package",
            side_effect=RuntimeError("sensitive internal detail"),
        ):
            aborted = verify_review_package(destination)
        self.assertFalse(aborted["valid"])
        self.assertEqual(
            aborted["findings"][0]["rule_id"],
            "package.semantic_verification_aborted",
        )
        self.assertIn("RuntimeError", aborted["findings"][0]["message"])
        self.assertNotIn("sensitive internal detail", aborted["findings"][0]["message"])
        Draft202012Validator(
            schema_document("review-package-verification")
        ).validate(aborted)

    def test_review_package_is_complete_and_manifested(self) -> None:
        destination = self.root / "review-package"
        original_analysis = copy.deepcopy(self.analysis)
        result = export_review_package(
            self.analysis,
            destination,
            source_analysis=self.root / "analysis.json",
        )
        self.assertEqual(self.analysis, original_analysis)
        manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["analysis_state_sha256"]), 64)
        names = {value["path"] for value in manifest["files"]}
        self.assertTrue(
            {
                "analysis.json",
                "worksheet.csv",
                "worksheet.md",
                "inventory.md",
                "architecture.md",
                "traceability.md",
                "coverage.md",
                "audit.csv",
                "validation.json",
                "summary.json",
                "README.md",
            }.issubset(names)
        )
        self.assertTrue(REVIEW_PACKAGE_SCHEMA_FILES.issubset(names))
        self.assertEqual(manifest["schema_catalog"]["schema_count"], 18)
        self.assertEqual(
            manifest["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "package_provenance_projection_v1",
                "review_views_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertIn("assurance-work.json", names)
        Draft202012Validator(schema_document("review-package-manifest")).validate(
            manifest
        )
        with self.assertRaisesRegex(ValueError, "not empty"):
            export_review_package(self.analysis, destination)
        unexpected = destination / "reviewer-notes.txt"
        unexpected.write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unrecognized files"):
            export_review_package(self.analysis, destination, overwrite=True)
        self.assertEqual(unexpected.read_text(encoding="utf-8"), "preserve me")
        unexpected.unlink()
        refreshed = export_review_package(self.analysis, destination, overwrite=True)
        self.assertTrue((refreshed / "manifest.json").is_file())
        self.assertFalse(
            any(path.name.startswith(f".{destination.name}.tmp-") for path in self.root.iterdir())
        )

        manifest_path = refreshed / "manifest.json"
        newline_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for filename in ("architecture.md", "README.md"):
            path = refreshed / filename
            raw = path.read_bytes()
            normalized = raw.replace(b"\r\n", b"\n")
            alternate = (
                normalized.replace(b"\n", b"\r\n")
                if raw == normalized
                else normalized
            )
            path.write_bytes(alternate)
            entry = next(
                value
                for value in newline_manifest["files"]
                if value["path"] == filename
            )
            entry["bytes"] = len(alternate)
            entry["sha256"] = hashlib.sha256(alternate).hexdigest()
        manifest_path.write_text(
            json.dumps(newline_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        newline_verification = verify_review_package(refreshed)
        self.assertTrue(newline_verification["valid"])
        self.assertTrue(newline_verification["review_views"]["valid"])
        self.assertTrue(newline_verification["package_provenance"]["valid"])
        export_review_package(self.analysis, destination, overwrite=True)

        historical_profiles = (
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                },
                32,
            ),
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                },
                34,
            ),
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                },
                36,
            ),
            (
                {
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                },
                37,
            ),
            (
                {
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                    "workflow-status",
                },
                38,
            ),
            (
                {
                    "assurance-work-queue",
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                    "workflow-status",
                },
                39,
            ),
        )
        for index, (retained_names, expected_files) in enumerate(
            historical_profiles, start=1
        ):
            compatible = export_review_package(
                self.analysis,
                self.root / f"compatible-package-{index}",
                source_analysis=self.root / "analysis.json",
            )
            catalog_path = compatible / "schema-catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            catalog["schemas"] = [
                entry
                for entry in catalog["schemas"]
                if entry["name"] in retained_names
            ]
            retained_files = {
                "schema-catalog.json",
                *(entry["filename"] for entry in catalog["schemas"]),
            }
            for filename in REVIEW_PACKAGE_SCHEMA_FILES - retained_files:
                (compatible / filename).unlink()
            catalog_path.write_text(
                json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            manifest_path = compatible / "manifest.json"
            compatible_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            compatible_manifest["files"] = [
                entry
                for entry in compatible_manifest["files"]
                if entry["path"] not in REVIEW_PACKAGE_SCHEMA_FILES
                or entry["path"] in retained_files
            ]
            catalog_raw = catalog_path.read_bytes()
            catalog_entry = next(
                entry
                for entry in compatible_manifest["files"]
                if entry["path"] == "schema-catalog.json"
            )
            catalog_entry["bytes"] = len(catalog_raw)
            catalog_entry["sha256"] = hashlib.sha256(catalog_raw).hexdigest()
            compatible_manifest["schema_catalog"].update(
                {
                    "canonical_sha256": canonical_json_sha256(catalog),
                    "schema_count": len(retained_names),
                }
            )
            manifest_path.write_text(
                json.dumps(compatible_manifest, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            compatible_verification = verify_review_package(compatible)
            self.assertTrue(compatible_verification["valid"])
            self.assertEqual(
                compatible_verification["checked_files"], expected_files
            )

        pre_diagnostics_analysis = copy.deepcopy(self.analysis)
        pre_diagnostics_analysis["generator"]["version"] = "0.49.0"
        pre_diagnostics = export_review_package(
            pre_diagnostics_analysis,
            self.root / "pre-diagnostics-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_diagnostics_manifest_path = pre_diagnostics / "manifest.json"
        pre_diagnostics_manifest = json.loads(
            pre_diagnostics_manifest_path.read_text(encoding="utf-8")
        )
        pre_diagnostics_manifest["exporter"]["version"] = "0.49.0"
        pre_diagnostics_manifest["capabilities"].remove(
            "analysis_diagnostics_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove(
            "guidance_traceability_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove(
            "evidence_catalog_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove(
            "interchange_artifacts_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove(
            "review_views_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_diagnostics_manifest["capabilities"].remove("sfta_projection_v1")
        pre_diagnostics_manifest_path.write_text(
            json.dumps(pre_diagnostics_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_diagnostics_verification = verify_review_package(pre_diagnostics)
        self.assertTrue(pre_diagnostics_verification["valid"])
        self.assertEqual(
            pre_diagnostics_verification["capabilities"],
            ["assurance_register_projection", "assurance_work_queue_projection"],
        )
        self.assertEqual(pre_diagnostics_verification["analysis_diagnostics"], {})
        self.assertEqual(pre_diagnostics_verification["guidance_traceability"], {})

        pre_guidance_analysis = copy.deepcopy(self.analysis)
        pre_guidance_analysis["generator"]["version"] = "0.51.0"
        pre_guidance = export_review_package(
            pre_guidance_analysis,
            self.root / "pre-guidance-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_guidance_manifest_path = pre_guidance / "manifest.json"
        pre_guidance_manifest = json.loads(
            pre_guidance_manifest_path.read_text(encoding="utf-8")
        )
        pre_guidance_manifest["exporter"]["version"] = "0.51.0"
        pre_guidance_manifest["capabilities"].remove(
            "guidance_traceability_projection_v1"
        )
        pre_guidance_manifest["capabilities"].remove(
            "evidence_catalog_projection_v1"
        )
        pre_guidance_manifest["capabilities"].remove(
            "interchange_artifacts_projection_v1"
        )
        pre_guidance_manifest["capabilities"].remove(
            "review_views_projection_v1"
        )
        pre_guidance_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_guidance_manifest["capabilities"].remove("sfta_projection_v1")
        pre_guidance_manifest_path.write_text(
            json.dumps(pre_guidance_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_guidance_verification = verify_review_package(pre_guidance)
        self.assertTrue(pre_guidance_verification["valid"])
        self.assertEqual(
            pre_guidance_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
            ],
        )
        self.assertEqual(pre_guidance_verification["guidance_traceability"], {})

        pre_sfta_analysis = copy.deepcopy(self.analysis)
        pre_sfta_analysis["generator"]["version"] = "0.52.0"
        pre_sfta = export_review_package(
            pre_sfta_analysis,
            self.root / "pre-sfta-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_sfta_manifest_path = pre_sfta / "manifest.json"
        pre_sfta_manifest = json.loads(
            pre_sfta_manifest_path.read_text(encoding="utf-8")
        )
        pre_sfta_manifest["exporter"]["version"] = "0.52.0"
        pre_sfta_manifest["capabilities"].remove("sfta_projection_v1")
        pre_sfta_manifest["capabilities"].remove("evidence_catalog_projection_v1")
        pre_sfta_manifest["capabilities"].remove(
            "interchange_artifacts_projection_v1"
        )
        pre_sfta_manifest["capabilities"].remove("review_views_projection_v1")
        pre_sfta_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_sfta_manifest_path.write_text(
            json.dumps(pre_sfta_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_sfta_verification = verify_review_package(pre_sfta)
        self.assertTrue(pre_sfta_verification["valid"])
        self.assertEqual(
            pre_sfta_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "guidance_traceability_projection_v1",
            ],
        )
        self.assertEqual(pre_sfta_verification["sfta_projection"], {})

        pre_evidence_analysis = copy.deepcopy(self.analysis)
        pre_evidence_analysis["generator"]["version"] = "0.53.0"
        pre_evidence = export_review_package(
            pre_evidence_analysis,
            self.root / "pre-evidence-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_evidence_manifest_path = pre_evidence / "manifest.json"
        pre_evidence_manifest = json.loads(
            pre_evidence_manifest_path.read_text(encoding="utf-8")
        )
        pre_evidence_manifest["exporter"]["version"] = "0.53.0"
        pre_evidence_manifest["capabilities"].remove(
            "evidence_catalog_projection_v1"
        )
        pre_evidence_manifest["capabilities"].remove(
            "interchange_artifacts_projection_v1"
        )
        pre_evidence_manifest["capabilities"].remove(
            "review_views_projection_v1"
        )
        pre_evidence_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_evidence_manifest_path.write_text(
            json.dumps(pre_evidence_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_evidence_verification = verify_review_package(pre_evidence)
        self.assertTrue(pre_evidence_verification["valid"])
        self.assertEqual(
            pre_evidence_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "guidance_traceability_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertEqual(pre_evidence_verification["evidence_catalog"], {})

        pre_interchange_analysis = copy.deepcopy(self.analysis)
        pre_interchange_analysis["generator"]["version"] = "0.54.0"
        pre_interchange = export_review_package(
            pre_interchange_analysis,
            self.root / "pre-interchange-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_interchange_manifest_path = pre_interchange / "manifest.json"
        pre_interchange_manifest = json.loads(
            pre_interchange_manifest_path.read_text(encoding="utf-8")
        )
        pre_interchange_manifest["exporter"]["version"] = "0.54.0"
        pre_interchange_manifest["capabilities"].remove(
            "interchange_artifacts_projection_v1"
        )
        pre_interchange_manifest["capabilities"].remove(
            "review_views_projection_v1"
        )
        pre_interchange_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_interchange_manifest_path.write_text(
            json.dumps(pre_interchange_manifest, indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        pre_interchange_verification = verify_review_package(pre_interchange)
        self.assertTrue(pre_interchange_verification["valid"])
        self.assertEqual(
            pre_interchange_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertEqual(
            pre_interchange_verification["interchange_artifacts"], {}
        )

        pre_review_views_analysis = copy.deepcopy(self.analysis)
        pre_review_views_analysis["generator"]["version"] = "0.55.0"
        pre_review_views = export_review_package(
            pre_review_views_analysis,
            self.root / "pre-review-views-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_review_views_manifest_path = pre_review_views / "manifest.json"
        pre_review_views_manifest = json.loads(
            pre_review_views_manifest_path.read_text(encoding="utf-8")
        )
        pre_review_views_manifest["exporter"]["version"] = "0.55.0"
        pre_review_views_manifest["capabilities"].remove(
            "review_views_projection_v1"
        )
        pre_review_views_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_review_sarif_path = pre_review_views / "findings.sarif"
        pre_review_sarif = json.loads(
            pre_review_sarif_path.read_text(encoding="utf-8")
        )
        pre_review_sarif["runs"][0]["tool"]["driver"]["semanticVersion"] = (
            "0.55.0"
        )
        pre_review_sarif["runs"][0]["tool"]["driver"]["informationUri"] = (
            "https://github.com/Will-A-W/project-py-sfmea"
        )
        pre_review_sarif_path.write_text(
            json.dumps(pre_review_sarif, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_review_cyclonedx_path = pre_review_views / "components.cdx.json"
        pre_review_cyclonedx = json.loads(
            pre_review_cyclonedx_path.read_text(encoding="utf-8")
        )
        pre_review_cyclonedx["metadata"]["tools"]["components"][0][
            "version"
        ] = "0.55.0"
        pre_review_cyclonedx_path.write_text(
            json.dumps(pre_review_cyclonedx, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        for filename, path in (
            ("findings.sarif", pre_review_sarif_path),
            ("components.cdx.json", pre_review_cyclonedx_path),
        ):
            raw = path.read_bytes()
            entry = next(
                value
                for value in pre_review_views_manifest["files"]
                if value["path"] == filename
            )
            entry["bytes"] = len(raw)
            entry["sha256"] = hashlib.sha256(raw).hexdigest()
        pre_review_views_manifest_path.write_text(
            json.dumps(pre_review_views_manifest, indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        pre_review_views_verification = verify_review_package(pre_review_views)
        self.assertTrue(pre_review_views_verification["valid"])
        self.assertEqual(
            pre_review_views_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertEqual(pre_review_views_verification["review_views"], {})
        self.assertTrue(
            pre_review_views_verification["interchange_artifacts"]["valid"]
        )

        pre_provenance_analysis = copy.deepcopy(self.analysis)
        pre_provenance_analysis["generator"]["version"] = "0.56.1"
        pre_provenance = export_review_package(
            pre_provenance_analysis,
            self.root / "pre-provenance-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_provenance_manifest_path = pre_provenance / "manifest.json"
        pre_provenance_manifest = json.loads(
            pre_provenance_manifest_path.read_text(encoding="utf-8")
        )
        pre_provenance_manifest["exporter"]["version"] = "0.56.1"
        pre_provenance_manifest["capabilities"].remove(
            "package_provenance_projection_v1"
        )
        pre_provenance_sarif_path = pre_provenance / "findings.sarif"
        pre_provenance_sarif = json.loads(
            pre_provenance_sarif_path.read_text(encoding="utf-8")
        )
        pre_provenance_sarif["runs"][0]["tool"]["driver"][
            "semanticVersion"
        ] = "0.56.1"
        pre_provenance_sarif_path.write_text(
            json.dumps(pre_provenance_sarif, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_provenance_cyclonedx_path = pre_provenance / "components.cdx.json"
        pre_provenance_cyclonedx = json.loads(
            pre_provenance_cyclonedx_path.read_text(encoding="utf-8")
        )
        pre_provenance_cyclonedx["metadata"]["tools"]["components"][0][
            "version"
        ] = "0.56.1"
        pre_provenance_cyclonedx_path.write_text(
            json.dumps(pre_provenance_cyclonedx, indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        pre_provenance_inventory_path = pre_provenance / "inventory.md"
        export_inventory(
            pre_provenance_analysis,
            pre_provenance_inventory_path,
            include_repository_accounting=False,
        )
        pre_provenance_coverage_path = pre_provenance / "coverage.md"
        export_coverage(
            pre_provenance_analysis,
            pre_provenance_coverage_path,
            format="markdown",
            include_repository_accounting=False,
        )
        for filename, path in (
            ("findings.sarif", pre_provenance_sarif_path),
            ("components.cdx.json", pre_provenance_cyclonedx_path),
            ("inventory.md", pre_provenance_inventory_path),
            ("coverage.md", pre_provenance_coverage_path),
        ):
            raw = path.read_bytes()
            entry = next(
                value
                for value in pre_provenance_manifest["files"]
                if value["path"] == filename
            )
            entry["bytes"] = len(raw)
            entry["sha256"] = hashlib.sha256(raw).hexdigest()
        pre_provenance_manifest_path.write_text(
            json.dumps(pre_provenance_manifest, indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        pre_provenance_verification = verify_review_package(pre_provenance)
        self.assertTrue(pre_provenance_verification["valid"])
        self.assertEqual(
            pre_provenance_verification["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "review_views_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertEqual(pre_provenance_verification["package_provenance"], {})

        legacy = export_review_package(
            self.analysis,
            self.root / "legacy-package",
            source_analysis=self.root / "analysis.json",
        )
        legacy_manifest_path = legacy / "manifest.json"
        legacy_manifest = json.loads(legacy_manifest_path.read_text(encoding="utf-8"))
        legacy_manifest.pop("schema_catalog")
        legacy_manifest.pop("capabilities")
        legacy_analysis_path = legacy / "analysis.json"
        legacy_analysis = json.loads(
            legacy_analysis_path.read_text(encoding="utf-8")
        )
        legacy_analysis["generator"]["version"] = "0.46.0"
        legacy_analysis_path.write_text(
            json.dumps(legacy_analysis, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        legacy_manifest["exporter"]["version"] = "0.46.0"
        legacy_manifest["analysis_generator"] = legacy_analysis["generator"]
        legacy_manifest["analysis_state_sha256"] = canonical_json_sha256(
            legacy_analysis
        )
        legacy_manifest["files"] = [
            value
            for value in legacy_manifest["files"]
            if value["path"] not in REVIEW_PACKAGE_SCHEMA_FILES
            and value["path"] != "assurance-work.json"
        ]
        legacy_analysis_raw = legacy_analysis_path.read_bytes()
        legacy_analysis_entry = next(
            value
            for value in legacy_manifest["files"]
            if value["path"] == "analysis.json"
        )
        legacy_analysis_entry["bytes"] = len(legacy_analysis_raw)
        legacy_analysis_entry["sha256"] = hashlib.sha256(
            legacy_analysis_raw
        ).hexdigest()
        legacy_manifest_path.write_text(
            json.dumps(legacy_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        for filename in REVIEW_PACKAGE_SCHEMA_FILES:
            (legacy / filename).unlink()
        (legacy / "assurance-work.json").unlink()
        legacy_verification = verify_review_package(legacy)
        self.assertTrue(legacy_verification["valid"])
        self.assertEqual(legacy_verification["checked_files"], 26)
        self.assertEqual(legacy_verification["schema_catalog"], {})
        self.assertEqual(legacy_verification["assurance_work_queue"], {})

        legacy_archive = self.root / "legacy-package.zip"
        with zipfile.ZipFile(
            legacy_archive, "w", compression=zipfile.ZIP_DEFLATED
        ) as bundle:
            for path in legacy.iterdir():
                bundle.write(path, path.name)
        legacy_archive_verification = verify_review_package(legacy_archive)
        self.assertTrue(legacy_archive_verification["valid"])
        self.assertEqual(legacy_archive_verification["checked_files"], 26)

        self.analysis["project"]["settings"]["config_file"] = str(
            self.root / "sfmea.toml"
        )
        self.analysis["runtime_evidence"]["imports"] = [
            {
                "source": str(self.root / "runtime" / "trace.json"),
                "mapped_span_count": 0,
                "unmapped_span_count": 0,
            }
        ]
        portable = export_review_package(
            self.analysis,
            self.root / "portable-package",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        snapshot = json.loads((portable / "analysis.json").read_text(encoding="utf-8"))
        portable_manifest = json.loads(
            (portable / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(snapshot["project"]["root"], ".")
        self.assertEqual(snapshot["project"]["settings"]["config_file"], "sfmea.toml")
        self.assertEqual(
            snapshot["runtime_evidence"]["imports"][0]["source"], "trace.json"
        )
        self.assertEqual(portable_manifest["source_analysis"], "analysis.json")
        self.assertTrue(portable_manifest["portable"])
        self.assertEqual(self.analysis["project"]["root"], str(self.root))

    def test_review_view_reconciliation_preserves_pre_05765_packages(self) -> None:
        destination = export_review_package(
            self.analysis, self.root / "legacy-review-views"
        )
        packaged_analysis = json.loads(
            (destination / "analysis.json").read_text(encoding="utf-8")
        )
        export_inventory(
            packaged_analysis,
            destination / "inventory.md",
            include_repository_accounting=False,
        )
        export_coverage(
            packaged_analysis,
            destination / "coverage.md",
            format="markdown",
            include_repository_accounting=False,
        )
        listed = {path.name for path in destination.iterdir() if path.is_file()}

        historical = _verify_review_views(
            destination, listed, packaged_analysis, "0.57.64"
        )
        self.assertTrue(historical["valid"])
        current = _verify_review_views(
            destination, listed, packaged_analysis, "0.57.65"
        )
        self.assertFalse(current["valid"])
        self.assertFalse(current["checks"]["system_views_projection"])

    def test_review_package_materializes_assurance_before_snapshot(self) -> None:
        for case, missing_value in (
            ("missing", None),
            ("malformed", []),
        ):
            with self.subTest(case=case):
                analysis = copy.deepcopy(self.analysis)
                if missing_value is None:
                    analysis.pop("assurance", None)
                else:
                    analysis["assurance"] = missing_value
                original = copy.deepcopy(analysis)
                destination = self.root / f"materialized-{case}-package"

                export_review_package(analysis, destination)

                self.assertEqual(analysis, original)
                packaged_analysis = json.loads(
                    (destination / "analysis.json").read_text(encoding="utf-8")
                )
                self.assertIsInstance(packaged_analysis["assurance"], dict)
                self.assertIsInstance(
                    packaged_analysis["assurance"]["obligations"], list
                )
                manifest = json.loads(
                    (destination / "manifest.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    manifest["analysis_state_sha256"],
                    analysis_state_sha256(packaged_analysis),
                )
                verified = verify_review_package(destination)
                self.assertTrue(verified["valid"])
                self.assertTrue(verified["assurance_register"]["valid"])
                self.assertTrue(verified["assurance_work_queue"]["valid"])

                archive = export_review_archive(
                    analysis,
                    self.root / f"materialized-{case}-package.zip",
                )
                self.assertEqual(analysis, original)
                archive_verified = verify_review_package(archive)
                self.assertTrue(archive_verified["valid"])
                self.assertEqual(archive_verified["container"], "zip")
                self.assertTrue(archive_verified["assurance_register"]["valid"])
                self.assertTrue(archive_verified["assurance_work_queue"]["valid"])

    def test_package_cli_infers_archive_from_zip_output_suffix(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        archive = self.root / "review-bundle.ZIP"
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            self.assertEqual(
                main(["package", str(analysis_path), "-o", str(archive)]),
                0,
            )

        self.assertTrue(archive.is_file())
        self.assertTrue(zipfile.is_zipfile(archive))
        self.assertIn("Created SFMEA review archive", output.getvalue())
        verified = verify_review_package(archive)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["container"], "zip")

        default_archive = analysis_path.with_name("analysis-review-package.zip")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["package", str(analysis_path), "--zip"]), 0)
        self.assertTrue(default_archive.is_file())
        self.assertTrue(verify_review_package(default_archive)["valid"])

    def test_package_cli_emits_schema_backed_json_receipt(self) -> None:
        analysis_path = self.root / "receipt-analysis.json"
        save_analysis(analysis_path, self.analysis)

        for container, destination in (
            ("directory", self.root / "receipt-package"),
            ("zip", self.root / "receipt-package.zip"),
        ):
            with self.subTest(container=container):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        main(
                            [
                                "package",
                                str(analysis_path),
                                "-o",
                                str(destination),
                                "--json",
                            ]
                        ),
                        0,
                    )

                receipt = json.loads(output.getvalue())
                Draft202012Validator(
                    schema_document("review-package-verification")
                ).validate(receipt)
                self.assertTrue(receipt["valid"])
                self.assertEqual(receipt["container"], container)
                self.assertEqual(receipt["checked_files"], 46)
                self.assertEqual(len(receipt["capabilities"]), 9)
                self.assertEqual(Path(receipt["package"]), destination.resolve())
                self.assertEqual(
                    receipt["publication"],
                    {"status": "published", "phase": "complete"},
                )
                self.assertEqual(
                    receipt["verifier"],
                    {"name": "PySFMEA", "version": __version__},
                )
                if container == "zip":
                    with zipfile.ZipFile(destination) as bundle:
                        manifest_raw = bundle.read("manifest.json")
                    self.assertEqual(
                        receipt["archive_sha256"],
                        hashlib.sha256(destination.read_bytes()).hexdigest(),
                    )
                else:
                    manifest_raw = (destination / "manifest.json").read_bytes()
                    self.assertNotIn("archive_sha256", receipt)
                self.assertEqual(
                    receipt["manifest_sha256"],
                    hashlib.sha256(manifest_raw).hexdigest(),
                )

        receipt_validator = Draft202012Validator(
            schema_document("review-package-verification")
        )
        contradictory_receipts = (
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "not_published",
                    "phase": "generation",
                },
            },
            {
                "valid": False,
                "checked_files": 40,
                "counts": {"error": 1, "warning": 0},
                "publication": {"status": "published", "phase": "complete"},
            },
            {
                "valid": False,
                "checked_files": 1,
                "counts": {"error": 1, "warning": 0},
                "publication": {
                    "status": "not_published",
                    "phase": "analysis_load",
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "post_publication_verification",
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "catalog_algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "catalog_canonicalization": (
                        PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
                    ),
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "catalog_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "catalog_format": PUBLICATION_FAILURE_CATALOG_FORMAT,
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "failure_rule_id": "package.publication.internal_failure",
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "failure_code": "internal_failure",
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "next_action": "collect_diagnostics",
                },
            },
            {
                "valid": True,
                "checked_files": 40,
                "publication": {
                    "status": "published",
                    "phase": "complete",
                    "retry_policy": "manual_diagnostics",
                },
            },
        )
        for contradiction in contradictory_receipts:
            with self.subTest(contradiction=contradiction):
                malformed_receipt = copy.deepcopy(receipt)
                malformed_receipt.update(contradiction)
                self.assertTrue(list(receipt_validator.iter_errors(malformed_receipt)))

        core_contradictions = (
            {"valid": True, "checked_files": 40, "error_count": 1},
            {"valid": True, "checked_files": 0, "error_count": 0},
            {"valid": False, "checked_files": 40, "error_count": 0},
        )
        for contradiction in core_contradictions:
            with self.subTest(core_contradiction=contradiction):
                malformed_receipt = copy.deepcopy(receipt)
                malformed_receipt.pop("publication")
                malformed_receipt["valid"] = contradiction["valid"]
                malformed_receipt["checked_files"] = contradiction["checked_files"]
                malformed_receipt["counts"]["error"] = contradiction["error_count"]
                self.assertTrue(list(receipt_validator.iter_errors(malformed_receipt)))

        identity_contradictions = (
            "verifier",
            "manifest_sha256",
            "archive_sha256",
        )
        for missing_field in identity_contradictions:
            with self.subTest(missing_identity=missing_field):
                malformed_receipt = copy.deepcopy(receipt)
                malformed_receipt.pop(missing_field)
                self.assertTrue(list(receipt_validator.iter_errors(malformed_receipt)))

        finding_contradictions = (
            {
                "valid": True,
                "error_count": 0,
                "warning_count": 0,
                "findings": [
                    {
                        "rule_id": "package.unreported_error",
                        "level": "error",
                        "message": "Injected error finding.",
                        "path": "manifest.json",
                    }
                ],
            },
            {
                "valid": False,
                "error_count": 1,
                "warning_count": 0,
                "findings": [],
            },
            {
                "valid": True,
                "error_count": 0,
                "warning_count": 1,
                "findings": [],
            },
            {
                "valid": True,
                "error_count": 0,
                "warning_count": 0,
                "findings": [
                    {
                        "rule_id": "package.unreported_warning",
                        "level": "warning",
                        "message": "Injected warning finding.",
                        "path": "manifest.json",
                    }
                ],
            },
        )
        for contradiction in finding_contradictions:
            with self.subTest(finding_contradiction=contradiction):
                malformed_receipt = copy.deepcopy(receipt)
                malformed_receipt.pop("publication")
                malformed_receipt["valid"] = contradiction["valid"]
                malformed_receipt["counts"] = {
                    "error": contradiction["error_count"],
                    "warning": contradiction["warning_count"],
                }
                malformed_receipt["findings"] = contradiction["findings"]
                self.assertTrue(list(receipt_validator.iter_errors(malformed_receipt)))

        rejected_destination = self.root / "rejected-receipt-package"

        def reject_receipt(path: str | Path) -> dict[str, Any]:
            receipt = copy.deepcopy(verify_review_package(path))
            receipt["valid"] = False
            receipt["counts"]["error"] += 1
            receipt["findings"].append(
                {
                    "rule_id": "package.post_publication_receipt_invalid",
                    "level": "error",
                    "message": "Injected post-publication receipt failure.",
                    "path": "manifest.json",
                }
            )
            return receipt

        rejected_output = io.StringIO()
        with patch(
            "pysfmea.cli.verify_review_package",
            side_effect=reject_receipt,
        ):
            with contextlib.redirect_stdout(rejected_output):
                self.assertEqual(
                    main(
                        [
                            "package",
                            str(analysis_path),
                            "-o",
                            str(rejected_destination),
                            "--json",
                        ]
                    ),
                    1,
                )
        rejected_receipt = json.loads(rejected_output.getvalue())
        Draft202012Validator(
            schema_document("review-package-verification")
        ).validate(rejected_receipt)
        self.assertFalse(rejected_receipt["valid"])
        self.assertEqual(
            rejected_receipt["publication"],
            {
                "status": "published",
                "phase": "post_publication_verification",
            },
        )
        self.assertEqual(
            rejected_receipt["findings"][-1]["rule_id"],
            "package.post_publication_receipt_invalid",
        )

        malformed_analysis = self.root / "malformed-analysis.json"
        malformed_analysis.write_text("{not-json", encoding="utf-8")
        failure_cases = (
            (
                "missing-analysis",
                [
                    "package",
                    str(self.root / "missing-analysis.json"),
                    "-o",
                    str(self.root / "missing-analysis-package.zip"),
                    "--json",
                ],
                "zip",
                "analysis_load",
                "package.publication.analysis_missing",
            ),
            (
                "malformed-analysis",
                [
                    "package",
                    str(malformed_analysis),
                    "-o",
                    str(self.root / "malformed-analysis-package.zip"),
                    "--json",
                ],
                "zip",
                "analysis_load",
                "package.publication.analysis_invalid",
            ),
            (
                "destination-conflict",
                [
                    "package",
                    str(analysis_path),
                    "-o",
                    str(self.root / "receipt-package"),
                    "--json",
                ],
                "directory",
                "generation",
                "package.publication.generation_rejected",
            ),
        )
        for case, argv, container, phase, rule_id in failure_cases:
            with self.subTest(case=case):
                failure_output = io.StringIO()
                failure_error = io.StringIO()
                with contextlib.redirect_stdout(failure_output):
                    with contextlib.redirect_stderr(failure_error):
                        self.assertEqual(main(argv), 2)
                self.assertEqual(failure_error.getvalue(), "")
                failure = json.loads(failure_output.getvalue())
                Draft202012Validator(
                    schema_document("review-package-verification")
                ).validate(failure)
                self.assertFalse(failure["valid"])
                self.assertEqual(failure["container"], container)
                self.assertEqual(failure["checked_files"], 0)
                self.assertEqual(
                    failure["findings"][0]["rule_id"],
                    rule_id,
                )
                self.assertNotIn(str(self.root), failure["findings"][0]["message"])
                self.assertEqual(
                    failure["verifier"],
                    {"name": "PySFMEA", "version": __version__},
                )
                self.assertEqual(
                    failure["publication"],
                    {
                        "status": "not_published",
                        "phase": phase,
                        "catalog_format": PUBLICATION_FAILURE_CATALOG_FORMAT,
                        "catalog_algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
                        "catalog_canonicalization": (
                            PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
                        ),
                        "catalog_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
                        "failure_code": rule_id.rsplit(".", 1)[-1],
                        "failure_rule_id": rule_id,
                        "next_action": PUBLICATION_FAILURES[
                            rule_id.rsplit(".", 1)[-1]
                        ].next_action,
                        "retry_policy": PUBLICATION_FAILURES[
                            rule_id.rsplit(".", 1)[-1]
                        ].retry_policy,
                    },
                )
                mismatched_failure = copy.deepcopy(failure)
                mismatched_failure["publication"]["failure_code"] = (
                    "internal_failure"
                )
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_failure))
                )
                mismatched_rule = copy.deepcopy(failure)
                mismatched_rule["publication"]["failure_rule_id"] = (
                    "package.publication.internal_failure"
                )
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_rule))
                )
                mismatched_catalog = copy.deepcopy(failure)
                mismatched_catalog["publication"]["catalog_format"] = (
                    "pysfmea-publication-failure-catalog-0"
                )
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_catalog))
                )
                mismatched_algorithm = copy.deepcopy(failure)
                mismatched_algorithm["publication"]["catalog_algorithm"] = "sha1"
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_algorithm))
                )
                mismatched_canonicalization = copy.deepcopy(failure)
                mismatched_canonicalization["publication"][
                    "catalog_canonicalization"
                ] = "unspecified"
                self.assertTrue(
                    list(
                        receipt_validator.iter_errors(
                            mismatched_canonicalization
                        )
                    )
                )
                mismatched_digest = copy.deepcopy(failure)
                mismatched_digest["publication"]["catalog_sha256"] = "0" * 64
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_digest))
                )
                for required_identity in (
                    "catalog_format",
                    "catalog_algorithm",
                    "catalog_canonicalization",
                    "catalog_sha256",
                    "failure_rule_id",
                ):
                    with self.subTest(
                        case=case, missing_identity=required_identity
                    ):
                        missing_identity = copy.deepcopy(failure)
                        missing_identity["publication"].pop(required_identity)
                        self.assertTrue(
                            list(receipt_validator.iter_errors(missing_identity))
                        )
                mismatched_action = copy.deepcopy(failure)
                mismatched_action["publication"]["next_action"] = (
                    "collect_diagnostics"
                )
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_action))
                )
                mismatched_retry = copy.deepcopy(failure)
                mismatched_retry["publication"]["retry_policy"] = (
                    "manual_diagnostics"
                )
                self.assertTrue(
                    list(receipt_validator.iter_errors(mismatched_retry))
                )

        runtime_output = io.StringIO()
        with patch(
            "pysfmea.cli.export_review_package",
            side_effect=RuntimeError("sensitive internal detail"),
        ):
            with contextlib.redirect_stdout(runtime_output):
                self.assertEqual(
                    main(
                        [
                            "package",
                            str(analysis_path),
                            "-o",
                            str(self.root / "runtime-failure-package"),
                            "--json",
                        ]
                    ),
                    2,
                )
        runtime_failure = json.loads(runtime_output.getvalue())
        Draft202012Validator(
            schema_document("review-package-verification")
        ).validate(runtime_failure)
        self.assertEqual(
            runtime_failure["findings"][0]["rule_id"],
            "package.publication.internal_failure",
        )
        self.assertNotIn(
            "sensitive internal detail",
            runtime_failure["findings"][0]["message"],
        )
        self.assertEqual(
            runtime_failure["publication"],
            {
                "status": "not_published",
                "phase": "generation",
                "catalog_format": PUBLICATION_FAILURE_CATALOG_FORMAT,
                "catalog_algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
                "catalog_canonicalization": (
                    PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
                ),
                "catalog_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
                "failure_code": "internal_failure",
                "failure_rule_id": "package.publication.internal_failure",
                "next_action": "collect_diagnostics",
                "retry_policy": "manual_diagnostics",
            },
        )

        permission_cases = (
            (
                "analysis-unreadable",
                "pysfmea.cli.load_analysis",
                self.root / "permission-analysis-package",
                "analysis_load",
                "package.publication.analysis_unreadable",
            ),
            (
                "destination-unavailable",
                "pysfmea.cli.export_review_package",
                self.root / "permission-destination-package",
                "generation",
                "package.publication.destination_unavailable",
            ),
        )
        for case, target, destination, phase, rule_id in permission_cases:
            with self.subTest(case=case):
                permission_output = io.StringIO()
                with patch(target, side_effect=PermissionError("sensitive local path")):
                    with contextlib.redirect_stdout(permission_output):
                        self.assertEqual(
                            main(
                                [
                                    "package",
                                    str(analysis_path),
                                    "-o",
                                    str(destination),
                                    "--json",
                                ]
                            ),
                            2,
                        )
                permission_failure = json.loads(permission_output.getvalue())
                Draft202012Validator(
                    schema_document("review-package-verification")
                ).validate(permission_failure)
                self.assertEqual(
                    permission_failure["findings"][0]["rule_id"], rule_id
                )
                self.assertNotIn(
                    "sensitive local path",
                    permission_failure["findings"][0]["message"],
                )
                self.assertEqual(
                    permission_failure["publication"],
                    {
                        "status": "not_published",
                        "phase": phase,
                        "catalog_format": PUBLICATION_FAILURE_CATALOG_FORMAT,
                        "catalog_algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
                        "catalog_canonicalization": (
                            PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
                        ),
                        "catalog_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
                        "failure_code": rule_id.rsplit(".", 1)[-1],
                        "failure_rule_id": rule_id,
                        "next_action": PUBLICATION_FAILURES[
                            rule_id.rsplit(".", 1)[-1]
                        ].next_action,
                        "retry_policy": PUBLICATION_FAILURES[
                            rule_id.rsplit(".", 1)[-1]
                        ].retry_policy,
                    },
                )
        self.assertTrue(verify_review_package(self.root / "receipt-package")["valid"])

    def test_review_package_withholds_failed_internal_verification(self) -> None:
        destination = export_review_package(
            self.analysis,
            self.root / "publish-gated-package",
        )
        before = {
            path.name: path.read_bytes()
            for path in destination.iterdir()
            if path.is_file()
        }
        original = copy.deepcopy(self.analysis)
        invalid_verdict = {
            "valid": False,
            "findings": [
                {"rule_id": "package.generated_projection_invalid"},
                {"rule_id": "package.generated_projection_invalid"},
            ],
        }

        with patch(
            "pysfmea.report.verify_review_package",
            return_value=invalid_verdict,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "package.generated_projection_invalid.*destination was not published",
            ):
                export_review_package(
                    self.analysis,
                    destination,
                    overwrite=True,
                )

        after = {
            path.name: path.read_bytes()
            for path in destination.iterdir()
            if path.is_file()
        }
        self.assertEqual(after, before)
        self.assertEqual(self.analysis, original)
        self.assertFalse(
            any(
                path.name.startswith(f".{destination.name}.tmp-")
                for path in destination.parent.iterdir()
            )
        )

        archive = export_review_archive(
            self.analysis,
            self.root / "publish-gated-package.zip",
        )
        archive_before = archive.read_bytes()
        with patch(
            "pysfmea.report.verify_review_package",
            side_effect=[{"valid": True}, invalid_verdict],
        ):
            with self.assertRaisesRegex(
                ValueError,
                "package.generated_projection_invalid.*destination was not published",
            ):
                export_review_archive(
                    self.analysis,
                    archive,
                    overwrite=True,
                )
        self.assertEqual(archive.read_bytes(), archive_before)
        self.assertFalse(
            any(
                path.name.startswith(f".{archive.stem}.tmp-")
                for path in archive.parent.iterdir()
            )
        )

    def test_review_package_verification_rejects_tampering_and_unsafe_content(self) -> None:
        destination = export_review_package(
            self.analysis,
            self.root / "verified-package",
            source_analysis=self.root / "analysis.json",
        )
        verified = verify_review_package(destination)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["checked_files"], 46)
        self.assertEqual(
            verified["verification_format"], REVIEW_PACKAGE_VERIFICATION_FORMAT
        )
        Draft202012Validator(schema_document("review-package-verification")).validate(
            verified
        )
        self.assertTrue(verified["schema_catalog"]["valid"])
        self.assertTrue(verified["analysis_structure"]["valid"])
        self.assertGreater(verified["analysis_structure"]["node_count"], 0)
        self.assertGreater(verified["analysis_structure"]["max_depth"], 0)
        self.assertEqual(
            verified["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "package_provenance_projection_v1",
                "review_views_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertTrue(all(verified["schema_catalog"]["checks"].values()))
        self.assertTrue(verified["analysis_diagnostics"]["valid"])
        self.assertEqual(verified["analysis_diagnostics"]["artifact_count"], 5)
        self.assertTrue(all(verified["analysis_diagnostics"]["checks"].values()))
        self.assertTrue(verified["guidance_traceability"]["valid"])
        self.assertEqual(verified["guidance_traceability"]["artifact_count"], 2)
        self.assertGreater(verified["guidance_traceability"]["citation_count"], 0)
        self.assertGreater(verified["guidance_traceability"]["finding_link_count"], 0)
        self.assertTrue(all(verified["guidance_traceability"]["checks"].values()))
        self.assertTrue(verified["sfta_projection"]["valid"])
        self.assertEqual(verified["sfta_projection"]["artifact_count"], 2)
        self.assertTrue(all(verified["sfta_projection"]["checks"].values()))
        self.assertTrue(verified["evidence_catalog"]["valid"])
        self.assertEqual(verified["evidence_catalog"]["artifact_count"], 1)
        self.assertTrue(all(verified["evidence_catalog"]["checks"].values()))
        self.assertTrue(verified["interchange_artifacts"]["valid"])
        self.assertEqual(verified["interchange_artifacts"]["artifact_count"], 2)
        self.assertTrue(all(verified["interchange_artifacts"]["checks"].values()))
        self.assertTrue(verified["review_views"]["valid"])
        self.assertEqual(verified["review_views"]["artifact_count"], 10)
        self.assertTrue(all(verified["review_views"]["checks"].values()))
        self.assertTrue(verified["package_provenance"]["valid"])
        self.assertEqual(verified["package_provenance"]["artifact_count"], 2)
        self.assertTrue(all(verified["package_provenance"]["checks"].values()))
        self.assertTrue(verified["assurance_work_queue"]["valid"])
        self.assertEqual(verified["assurance_work_queue"]["status"], "matched")
        self.assertTrue(
            all(verified["assurance_work_queue"]["checks"].values())
        )
        self.assertTrue(verified["assurance_register"]["valid"])
        self.assertTrue(all(verified["assurance_register"]["checks"].values()))
        self.assertEqual(
            verified["binding"]["analysis_state_sha256"],
            json.loads(
                (destination / "manifest.json").read_text(encoding="utf-8")
            )["analysis_state_sha256"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-package", str(destination), "--json"]), 0)
        human_output = io.StringIO()
        with contextlib.redirect_stdout(human_output):
            self.assertEqual(main(["verify-package", str(destination)]), 0)
        self.assertIn(
            "Schema catalog: valid=True, schemas=18", human_output.getvalue()
        )
        self.assertIn(
            "Analysis structure: valid=True, nodes=", human_output.getvalue()
        )
        self.assertIn(
            "Assurance work queue: valid=True, status=matched",
            human_output.getvalue(),
        )
        self.assertIn(
            "Assurance register: valid=True, obligations=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Analysis diagnostics: valid=True, artifacts=5",
            human_output.getvalue(),
        )
        self.assertIn(
            "Guidance traceability: valid=True, citations=",
            human_output.getvalue(),
        )
        self.assertIn(
            "SFTA projection: valid=True, trees=",
            human_output.getvalue(),
        )

        self.assertIn(
            "Evidence catalog: valid=True, executions=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Interchange artifacts: valid=True, SARIF-results=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Review views: valid=True, artifacts=10, findings=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Package provenance: valid=True, review-decisions=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Capabilities: analysis_diagnostics_projection_v1, "
            "assurance_register_projection, assurance_work_queue_projection, "
            "evidence_catalog_projection_v1, guidance_traceability_projection_v1, "
            "interchange_artifacts_projection_v1, package_provenance_projection_v1, "
            "review_views_projection_v1, sfta_projection_v1",
            human_output.getvalue(),
        )

        queue_path = destination / "assurance-work.json"
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        queue["notice"] += " Rewritten after packaging."
        queue_content = dict(queue)
        queue_content.pop("integrity")
        queue["integrity"]["content_sha256"] = canonical_json_sha256(
            queue_content
        )
        queue_path.write_text(
            json.dumps(queue, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        queue_raw = queue_path.read_bytes()
        queue_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "assurance-work.json"
        )
        queue_entry["bytes"] = len(queue_raw)
        queue_entry["sha256"] = hashlib.sha256(queue_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        queue_tampered = verify_review_package(destination)
        queue_rules = {value["rule_id"] for value in queue_tampered["findings"]}
        self.assertFalse(queue_tampered["valid"])
        self.assertIn("package.assurance_work_queue_invalid", queue_rules)
        self.assertNotIn("package.checksum_mismatch", queue_rules)
        self.assertTrue(
            queue_tampered["assurance_work_queue"]["checks"]["content_integrity"]
        )
        self.assertFalse(
            queue_tampered["assurance_work_queue"]["checks"]["semantic_projection"]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        register_path = destination / "assurance-register.json"
        register = json.loads(register_path.read_text(encoding="utf-8"))
        register["notice"] += " Rewritten after packaging."
        register_path.write_text(
            json.dumps(register, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        register_raw = register_path.read_bytes()
        register_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "assurance-register.json"
        )
        register_entry["bytes"] = len(register_raw)
        register_entry["sha256"] = hashlib.sha256(register_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        register_tampered = verify_review_package(destination)
        register_rules = {
            value["rule_id"] for value in register_tampered["findings"]
        }
        self.assertFalse(register_tampered["valid"])
        self.assertIn("package.assurance_register_invalid", register_rules)
        self.assertNotIn("package.checksum_mismatch", register_rules)
        self.assertFalse(
            register_tampered["assurance_register"]["checks"][
                "semantic_projection"
            ]
        )
        self.assertTrue(register_tampered["assurance_work_queue"]["valid"])

        export_review_package(self.analysis, destination, overwrite=True)

        validation_path = destination / "validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["counts"]["warning"] += 1
        validation_path.write_text(
            json.dumps(validation, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        validation_raw = validation_path.read_bytes()
        validation_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "validation.json"
        )
        validation_entry["bytes"] = len(validation_raw)
        validation_entry["sha256"] = hashlib.sha256(validation_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        diagnostics_tampered = verify_review_package(destination)
        diagnostics_rules = {
            value["rule_id"] for value in diagnostics_tampered["findings"]
        }
        self.assertFalse(diagnostics_tampered["valid"])
        self.assertIn("package.analysis_diagnostics_invalid", diagnostics_rules)
        self.assertNotIn("package.checksum_mismatch", diagnostics_rules)
        self.assertFalse(
            diagnostics_tampered["analysis_diagnostics"]["checks"]["validation"]
        )
        self.assertTrue(
            diagnostics_tampered["analysis_diagnostics"]["checks"]["summary"]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        citations_path = destination / "citations.json"
        citations = json.loads(citations_path.read_text(encoding="utf-8"))
        citations[0]["summary"] += " Rewritten after packaging."
        citations_path.write_text(
            json.dumps(citations, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        citations_raw = citations_path.read_bytes()
        citations_entry = next(
            value for value in manifest["files"] if value["path"] == "citations.json"
        )
        citations_entry["bytes"] = len(citations_raw)
        citations_entry["sha256"] = hashlib.sha256(citations_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        guidance_tampered = verify_review_package(destination)
        guidance_rules = {
            value["rule_id"] for value in guidance_tampered["findings"]
        }
        self.assertFalse(guidance_tampered["valid"])
        self.assertIn("package.guidance_traceability_invalid", guidance_rules)
        self.assertNotIn("package.checksum_mismatch", guidance_rules)
        self.assertTrue(
            guidance_tampered["guidance_traceability"]["checks"][
                "traceability_projection"
            ]
        )
        self.assertFalse(
            guidance_tampered["guidance_traceability"]["checks"][
                "citation_catalog_projection"
            ]
        )
        self.assertFalse(
            guidance_tampered["guidance_traceability"]["checks"][
                "cross_artifact_consistency"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        sfta_path = destination / "sfta.json"
        sfta = json.loads(sfta_path.read_text(encoding="utf-8"))
        sfta["notice"] += " Rewritten after packaging."
        sfta_path.write_text(
            json.dumps(sfta, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sfta_raw = sfta_path.read_bytes()
        sfta_entry = next(
            value for value in manifest["files"] if value["path"] == "sfta.json"
        )
        sfta_entry["bytes"] = len(sfta_raw)
        sfta_entry["sha256"] = hashlib.sha256(sfta_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        sfta_tampered = verify_review_package(destination)
        sfta_rules = {value["rule_id"] for value in sfta_tampered["findings"]}
        self.assertFalse(sfta_tampered["valid"])
        self.assertIn("package.sfta_projection_invalid", sfta_rules)
        self.assertNotIn("package.checksum_mismatch", sfta_rules)
        self.assertFalse(
            sfta_tampered["sfta_projection"]["checks"]["model_projection"]
        )
        self.assertTrue(
            sfta_tampered["sfta_projection"]["checks"]["gap_register_projection"]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        evidence_path = destination / "evidence-catalog.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["evidence_artifacts"].append(
            {
                "id": "forged-artifact",
                "path": "forged-evidence.json",
                "sha256": "0" * 64,
            }
        )
        evidence_path.write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        evidence_raw = evidence_path.read_bytes()
        evidence_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "evidence-catalog.json"
        )
        evidence_entry["bytes"] = len(evidence_raw)
        evidence_entry["sha256"] = hashlib.sha256(evidence_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        evidence_tampered = verify_review_package(destination)
        evidence_rules = {
            value["rule_id"] for value in evidence_tampered["findings"]
        }
        self.assertFalse(evidence_tampered["valid"])
        self.assertIn("package.evidence_catalog_invalid", evidence_rules)
        self.assertNotIn("package.checksum_mismatch", evidence_rules)
        self.assertTrue(
            evidence_tampered["evidence_catalog"]["checks"]["baseline_binding"]
        )
        self.assertTrue(
            evidence_tampered["evidence_catalog"]["checks"]["execution_inventory"]
        )
        self.assertFalse(
            evidence_tampered["evidence_catalog"]["checks"][
                "evidence_artifact_inventory"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        sarif_path = destination / "findings.sarif"
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        sarif["runs"][0]["results"][0]["message"]["text"] = (
            "Rewritten after packaging."
        )
        sarif_path.write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sarif_raw = sarif_path.read_bytes()
        sarif_entry = next(
            value for value in manifest["files"] if value["path"] == "findings.sarif"
        )
        sarif_entry["bytes"] = len(sarif_raw)
        sarif_entry["sha256"] = hashlib.sha256(sarif_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        sarif_tampered = verify_review_package(destination)
        sarif_rules = {value["rule_id"] for value in sarif_tampered["findings"]}
        self.assertFalse(sarif_tampered["valid"])
        self.assertIn("package.interchange_artifacts_invalid", sarif_rules)
        self.assertNotIn("package.checksum_mismatch", sarif_rules)
        self.assertFalse(
            sarif_tampered["interchange_artifacts"]["checks"]["sarif_projection"]
        )
        self.assertTrue(
            sarif_tampered["interchange_artifacts"]["checks"][
                "cyclonedx_projection"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        cyclonedx_path = destination / "components.cdx.json"
        cyclonedx = json.loads(cyclonedx_path.read_text(encoding="utf-8"))
        cyclonedx["metadata"]["component"]["version"] = "FORGED-BASELINE"
        cyclonedx_path.write_text(
            json.dumps(cyclonedx, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        cyclonedx_raw = cyclonedx_path.read_bytes()
        cyclonedx_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "components.cdx.json"
        )
        cyclonedx_entry["bytes"] = len(cyclonedx_raw)
        cyclonedx_entry["sha256"] = hashlib.sha256(cyclonedx_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        cyclonedx_tampered = verify_review_package(destination)
        cyclonedx_rules = {
            value["rule_id"] for value in cyclonedx_tampered["findings"]
        }
        self.assertFalse(cyclonedx_tampered["valid"])
        self.assertIn("package.interchange_artifacts_invalid", cyclonedx_rules)
        self.assertNotIn("package.checksum_mismatch", cyclonedx_rules)
        self.assertTrue(
            cyclonedx_tampered["interchange_artifacts"]["checks"][
                "sarif_projection"
            ]
        )
        self.assertFalse(
            cyclonedx_tampered["interchange_artifacts"]["checks"][
                "cyclonedx_projection"
            ]
        )
        self.assertFalse(
            cyclonedx_tampered["interchange_artifacts"]["checks"][
                "baseline_consistency"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        architecture_path = destination / "architecture.md"
        architecture_path.write_text(
            architecture_path.read_text(encoding="utf-8")
            + "\nForged architecture conclusion.\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        architecture_raw = architecture_path.read_bytes()
        architecture_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "architecture.md"
        )
        architecture_entry["bytes"] = len(architecture_raw)
        architecture_entry["sha256"] = hashlib.sha256(
            architecture_raw
        ).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        review_views_tampered = verify_review_package(destination)
        review_view_rules = {
            value["rule_id"] for value in review_views_tampered["findings"]
        }
        self.assertFalse(review_views_tampered["valid"])
        self.assertIn("package.review_views_invalid", review_view_rules)
        self.assertNotIn("package.checksum_mismatch", review_view_rules)
        self.assertFalse(
            review_views_tampered["review_views"]["checks"][
                "system_views_projection"
            ]
        )
        self.assertTrue(
            review_views_tampered["review_views"]["checks"][
                "worksheet_projection"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        run_manifest_path = destination / "run-manifest.json"
        run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        run_manifest["review_decisions"].append(
            {
                "finding_id": "FORGED-FINDING",
                "disposition": "accepted",
                "status": "closed",
                "reviewer": "Forged reviewer",
                "reviewed_at": "2026-08-04T12:00:00+00:00",
                "rationale": "Inserted after packaging.",
            }
        )
        run_manifest_content = dict(run_manifest)
        run_manifest_content.pop("manifest_sha256")
        run_manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                run_manifest_content,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        run_manifest_path.write_text(
            json.dumps(run_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_manifest_raw = run_manifest_path.read_bytes()
        run_manifest_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "run-manifest.json"
        )
        run_manifest_entry["bytes"] = len(run_manifest_raw)
        run_manifest_entry["sha256"] = hashlib.sha256(
            run_manifest_raw
        ).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        provenance_tampered = verify_review_package(destination)
        provenance_rules = {
            value["rule_id"] for value in provenance_tampered["findings"]
        }
        self.assertFalse(provenance_tampered["valid"])
        self.assertIn("package.provenance_projection_invalid", provenance_rules)
        self.assertNotIn("package.checksum_mismatch", provenance_rules)
        self.assertFalse(
            provenance_tampered["package_provenance"]["checks"][
                "run_manifest_projection"
            ]
        )
        self.assertTrue(
            provenance_tampered["package_provenance"]["checks"][
                "readme_projection"
            ]
        )
        self.assertTrue(
            provenance_tampered["package_provenance"]["checks"][
                "timestamp_consistency"
            ]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("capabilities")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        undeclared = verify_review_package(destination)
        self.assertFalse(undeclared["valid"])
        self.assertIn(
            "package.capabilities_missing",
            {value["rule_id"] for value in undeclared["findings"]},
        )
        self.assertTrue(undeclared["assurance_work_queue"]["valid"])

        export_review_package(self.analysis, destination, overwrite=True)

        schema_path = destination / "pysfmea-diagram.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["title"] = "Tampered schema title"
        schema_path.write_text(
            json.dumps(schema, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        schema_tampered = verify_review_package(destination)
        Draft202012Validator(schema_document("review-package-verification")).validate(
            schema_tampered
        )
        schema_rules = {value["rule_id"] for value in schema_tampered["findings"]}
        self.assertIn("package.checksum_mismatch", schema_rules)
        self.assertIn("package.schema.digest", schema_rules)

        export_review_package(self.analysis, destination, overwrite=True)

        summary_path = destination / "summary.json"
        summary_path.write_text(
            summary_path.read_text(encoding="utf-8") + "tampered\n",
            encoding="utf-8",
        )
        tampered = verify_review_package(destination)
        tampered_rules = {value["rule_id"] for value in tampered["findings"]}
        self.assertFalse(tampered["valid"])
        self.assertIn("package.checksum_mismatch", tampered_rules)
        self.assertIn("package.size_mismatch", tampered_rules)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-package", str(destination)]), 1)

        missing = verify_review_package(self.root / "missing-review-package.zip")
        self.assertFalse(missing["valid"])
        Draft202012Validator(schema_document("review-package-verification")).validate(
            missing
        )

        export_review_package(self.analysis, destination, overwrite=True)
        unexpected = destination / "reviewer-notes.txt"
        unexpected.write_text("not manifested\n", encoding="utf-8")
        extra = verify_review_package(destination)
        self.assertIn(
            "package.file_unexpected",
            {value["rule_id"] for value in extra["findings"]},
        )
        unexpected.unlink()

        unexpected_directory = destination / "nested-content"
        unexpected_directory.mkdir()
        nested_file = unexpected_directory / "do-not-traverse.txt"
        nested_file.write_text("unexpected\n", encoding="utf-8")
        nested = verify_review_package(destination)
        self.assertIn(
            "package.entry_type",
            {value["rule_id"] for value in nested["findings"]},
        )
        nested_file.unlink()
        unexpected_directory.rmdir()

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["bytes"] = 100_000_001
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        oversized = verify_review_package(destination)
        self.assertIn(
            "package.file_limit",
            {value["rule_id"] for value in oversized["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["files"][:6]:
            entry["bytes"] = 90_000_000
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        excessive_total = verify_review_package(destination)
        self.assertIn(
            "package.total_limit",
            {value["rule_id"] for value in excessive_total["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"].extend(
            dict(manifest["files"][0]) for _ in range(61)
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        excessive_entries = verify_review_package(destination)
        self.assertIn(
            "package.file_list_invalid",
            {value["rule_id"] for value in excessive_entries["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["path"] = "../escape.txt"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        unsafe = verify_review_package(destination)
        self.assertIn(
            "package.path_unsafe",
            {value["rule_id"] for value in unsafe["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        analysis_path = destination / "analysis.json"
        snapshot = json.loads(analysis_path.read_text(encoding="utf-8"))
        snapshot["generator"] = {"name": "different-generator", "version": "999"}
        analysis_path.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        raw = analysis_path.read_bytes()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        analysis_entry = next(
            value for value in manifest["files"] if value["path"] == "analysis.json"
        )
        analysis_entry["bytes"] = len(raw)
        analysis_entry["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        provenance = verify_review_package(destination)
        provenance_rules = {value["rule_id"] for value in provenance["findings"]}
        self.assertIn("package.provenance_mismatch", provenance_rules)
        self.assertIn("package.analysis_state_digest_mismatch", provenance_rules)

    def test_review_archive_is_atomic_and_safely_verified(self) -> None:
        archive = export_review_archive(
            self.analysis,
            self.root / "review-package.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        verified = verify_review_package(archive)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["container"], "zip")
        self.assertEqual(verified["checked_files"], 46)
        self.assertTrue(verified["schema_catalog"]["valid"])
        self.assertEqual(
            verified["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "package_provenance_projection_v1",
                "review_views_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertTrue(verified["assurance_work_queue"]["valid"])
        self.assertTrue(verified["analysis_diagnostics"]["valid"])
        self.assertTrue(verified["guidance_traceability"]["valid"])
        self.assertTrue(verified["sfta_projection"]["valid"])
        self.assertTrue(verified["evidence_catalog"]["valid"])
        self.assertTrue(verified["interchange_artifacts"]["valid"])
        self.assertTrue(verified["review_views"]["valid"])
        self.assertTrue(verified["package_provenance"]["valid"])
        self.assertTrue(verified["assurance_register"]["valid"])
        self.assertTrue(
            verified["assurance_work_queue"]["path"].endswith(
                "review-package.zip!/assurance-work.json"
            )
        )
        self.assertNotIn(
            ".pysfmea-verify-",
            verified["assurance_work_queue"]["path"],
        )
        self.assertEqual(len(verified["archive_sha256"]), 64)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(
                set(bundle.namelist()),
                {
                    "analysis.json",
                    "assurance-register.csv",
                    "assurance-register.json",
                    "assurance-work.json",
                    "assurance-register.md",
                    "architecture.md",
                    "audit.csv",
                    "coverage.md",
                    "citations.json",
                    "evidence-catalog.json",
                    "sfta.json",
                    "sfta-gaps.csv",
                    "findings.sarif",
                    "components.cdx.json",
                    "run-manifest.json",
                    "system-context.json",
                    "repository-inventory.json",
                    "adapter-runs.json",
                    "guidance-traceability.csv",
                    "guidance-traceability.json",
                    "inventory.md",
                    "manifest.json",
                    "README.md",
                    "schema-catalog.json",
                    "pysfmea-assurance-program.schema.json",
                    "pysfmea-assurance-program-verification.schema.json",
                    "pysfmea-detached-signature.schema.json",
                    "pysfmea-diagram.schema.json",
                    "pysfmea-diagram-bundle.schema.json",
                    "pysfmea-diagram-bundle-verification.schema.json",
                    "pysfmea-fault-injection-plan.schema.json",
                    "pysfmea-fault-injection-plan-verification.schema.json",
                    "pysfmea-html-report-verification.schema.json",
                    "pysfmea-publication-failure-catalog.schema.json",
                    "pysfmea-publication-failure-catalog-verification.schema.json",
                    "pysfmea-schema-bundle-verification.schema.json",
                    "pysfmea-schema-catalog.schema.json",
                    "pysfmea-review-package-manifest.schema.json",
                    "pysfmea-review-package-verification.schema.json",
                    "pysfmea-workflow-status.schema.json",
                    "pysfmea-assurance-work-queue.schema.json",
                    "pysfmea-assurance-work-queue-verification.schema.json",
                    "summary.json",
                    "traceability.md",
                    "validation.json",
                    "worksheet.csv",
                    "worksheet.md",
                },
            )
            contents = {name: bundle.read(name) for name in bundle.namelist()}
        with self.assertRaisesRegex(ValueError, "already exists"):
            export_review_archive(self.analysis, archive)

        contents["summary.json"] += b"tampered\n"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, raw in contents.items():
                bundle.writestr(name, raw)
        tampered = verify_review_package(archive)
        self.assertFalse(tampered["valid"])
        self.assertIn(
            "package.checksum_mismatch",
            {value["rule_id"] for value in tampered["findings"]},
        )

        refreshed = export_review_archive(
            self.analysis,
            archive,
            overwrite=True,
        )
        self.assertTrue(verify_review_package(refreshed)["valid"])

        malicious = self.root / "unsafe.zip"
        with zipfile.ZipFile(malicious, "w") as bundle:
            bundle.writestr("../escape.txt", "must not escape")
        unsafe = verify_review_package(malicious)
        self.assertFalse(unsafe["valid"])
        self.assertIn(
            "package.archive_path_unsafe",
            {value["rule_id"] for value in unsafe["findings"]},
        )
        self.assertFalse((self.root / "escape.txt").exists())

        duplicate = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as bundle:
                bundle.writestr("analysis.json", "first")
                bundle.writestr("analysis.json", "second")
        duplicated = verify_review_package(duplicate)
        self.assertIn(
            "package.archive_entry_duplicate",
            {value["rule_id"] for value in duplicated["findings"]},
        )

        symlink = self.root / "symlink.zip"
        link_info = zipfile.ZipInfo("analysis.json")
        link_info.create_system = 3
        link_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(symlink, "w") as bundle:
            bundle.writestr(link_info, "outside.json")
        linked = verify_review_package(symlink)
        self.assertIn(
            "package.archive_entry_type",
            {value["rule_id"] for value in linked["findings"]},
        )

        bomb = self.root / "ratio-limit.zip"
        with zipfile.ZipFile(
            bomb, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as bundle:
            bundle.writestr("analysis.json", b"0" * 2_000_000)
        limited = verify_review_package(bomb)
        self.assertIn(
            "package.archive_ratio_limit",
            {value["rule_id"] for value in limited["findings"]},
        )

    @unittest.skipUnless(
        importlib.util.find_spec("cryptography"), "optional signing dependency unavailable"
    )
    def test_detached_signature_authenticates_package_and_claims(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        private_path = self.root / "signing-private.pem"
        public_path = self.root / "signing-public.pem"
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"test-passphrase"),
            )
        )
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        archive = export_review_archive(
            self.analysis,
            self.root / "signed-review.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        signature_path = sign_review_package(
            archive,
            private_path,
            "Quality Engineering Release",
            passphrase=b"test-passphrase",
        )
        verified = verify_review_signature(archive, signature_path, public_path)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["signature"]["valid"])
        self.assertEqual(
            verified["signature"]["signer"], "Quality Engineering Release"
        )
        self.assertTrue(
            verified["signature"]["key_fingerprint"].startswith("sha256:")
        )

        with self.assertRaisesRegex(ValueError, "4096-character limit"):
            sign_review_package(archive, private_path, "x" * 4097)
        with patch("pysfmea.signing.MAX_PASSPHRASE_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "4-byte limit"):
                sign_review_package(
                    archive,
                    private_path,
                    "Bounded passphrase",
                    passphrase=b"12345",
                )

        with patch("pysfmea.signing.MAX_KEY_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "10-byte limit"):
                sign_review_package(
                    archive,
                    private_path,
                    "Bounded private key",
                    destination=self.root / "bounded-private-key.sig.json",
                    passphrase=b"test-passphrase",
                )
            bounded_public = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in bounded_public["findings"]},
        )
        self.assertNotIn(str(self.root), bounded_public["findings"][-1]["message"])

        with patch("pysfmea.signing.MAX_SIGNATURE_BYTES", 10):
            bounded_signature = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in bounded_signature["findings"]},
        )

        invalid_utf8_signature = self.root / "invalid-utf8.sig.json"
        invalid_utf8_signature.write_bytes(b"\xff\xfe")
        invalid_utf8 = verify_review_signature(
            archive, invalid_utf8_signature, public_path
        )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in invalid_utf8["findings"]},
        )

        signature_raw = signature_path.read_text(encoding="utf-8")
        signature_path.write_text(
            '{"format":"ambiguous",' + signature_raw[1:], encoding="utf-8"
        )
        duplicate_key = verify_review_signature(archive, signature_path, public_path)
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in duplicate_key["findings"]},
        )
        for value in ("NaN", "1e9999"):
            with self.subTest(non_finite=value):
                signature_path.write_text(
                    '{"numeric_probe":' + value + "," + signature_raw[1:],
                    encoding="utf-8",
                )
                non_finite = verify_review_signature(
                    archive, signature_path, public_path
                )
                self.assertIn(
                    "signature.input_invalid",
                    {item["rule_id"] for item in non_finite["findings"]},
                )
        signature_path.write_text(signature_raw, encoding="utf-8")
        with patch("pysfmea.signing.MAX_SIGNATURE_JSON_NODES", 2):
            oversized_structure = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in oversized_structure["findings"]},
        )

        with patch("pysfmea.signing._same_file_identity", return_value=False):
            changed_input = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in changed_input["findings"]},
        )
        with patch(
            "pysfmea.signing._same_file_identity",
            side_effect=[True, True, True, False],
        ):
            changed_public_key = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.input_invalid",
            {value["rule_id"] for value in changed_public_key["findings"]},
        )

        with patch("pysfmea.signing.MAX_MANIFEST_BYTES", 10):
            bounded_manifest = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.package_changed",
            {value["rule_id"] for value in bounded_manifest["findings"]},
        )

        with patch("pysfmea.signing.MAX_SIGNED_ARCHIVE_BYTES", 10):
            bounded_archive = verify_review_signature(
                archive, signature_path, public_path
            )
        self.assertIn(
            "signature.package_changed",
            {value["rule_id"] for value in bounded_archive["findings"]},
        )

        stale_verdict = verify_review_package(archive)
        mutated_archive = self.root / "mutated-signed-review.zip"
        mutated_archive.write_bytes(archive.read_bytes())
        with zipfile.ZipFile(mutated_archive, "a") as bundle:
            bundle.writestr("unexpected.txt", "unmanifested content")
        stale_bypass = verify_review_signature(
            mutated_archive,
            signature_path,
            public_path,
            package_verification=stale_verdict,
        )
        self.assertIn(
            "signature.package_invalid",
            {value["rule_id"] for value in stale_bypass["findings"]},
        )

        atomic_destination = self.root / "atomic-signature.json"
        atomic_destination.write_text("prior signature content\n", encoding="utf-8")
        with patch(
            "pysfmea.signing.atomic_replace",
            side_effect=OSError("injected publication failure"),
        ):
            with self.assertRaisesRegex(ValueError, "could not be published safely"):
                sign_review_package(
                    archive,
                    private_path,
                    "Atomic publication",
                    destination=atomic_destination,
                    passphrase=b"test-passphrase",
                    overwrite=True,
                )
        self.assertEqual(
            atomic_destination.read_text(encoding="utf-8"),
            "prior signature content\n",
        )
        self.assertEqual(
            list(self.root.glob(f".{atomic_destination.name}.*.tmp")),
            [],
        )

        race_destination = self.root / "raced-signature.json"
        race_destination.write_text("prior raced content\n", encoding="utf-8")
        with patch(
            "pysfmea.signing._same_file_identity",
            side_effect=[True, True, True, True, False],
        ):
            with self.assertRaisesRegex(ValueError, "changed before publication"):
                sign_review_package(
                    archive,
                    private_path,
                    "Identity-checked publication",
                    destination=race_destination,
                    passphrase=b"test-passphrase",
                    overwrite=True,
                )
        self.assertEqual(
            race_destination.read_text(encoding="utf-8"),
            "prior raced content\n",
        )
        self.assertEqual(
            list(self.root.glob(f".{race_destination.name}.*.tmp")),
            [],
        )

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "verify-package",
                        str(archive),
                        "--signature",
                        str(signature_path),
                        "--public-key",
                        str(public_path),
                        "--json",
                    ]
                ),
                0,
            )
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "verify-package",
                        str(archive),
                        "--signature",
                        str(signature_path),
                    ]
                ),
                2,
            )
        with self.assertRaisesRegex(ValueError, "already exists"):
            sign_review_package(archive, private_path, "Duplicate")

        other_private = Ed25519PrivateKey.generate()
        other_public = self.root / "other-public.pem"
        other_public.write_bytes(
            other_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        wrong_key = verify_review_signature(archive, signature_path, other_public)
        self.assertIn(
            "signature.key_mismatch",
            {value["rule_id"] for value in wrong_key["findings"]},
        )

        envelope = json.loads(signature_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("detached-signature")).validate(envelope)
        original = json.dumps(envelope, indent=2) + "\n"
        envelope["statement"]["signer"] = "Impersonated signer"
        signature_path.write_text(
            json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
        )
        modified = verify_review_signature(archive, signature_path, public_path)
        self.assertIn(
            "signature.verification_failed",
            {value["rule_id"] for value in modified["findings"]},
        )
        signature_path.write_text(original, encoding="utf-8")

        second_archive = export_review_archive(
            self.analysis,
            self.root / "second-review.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        replayed = verify_review_signature(second_archive, signature_path, public_path)
        self.assertIn(
            "signature.subject_mismatch",
            {value["rule_id"] for value in replayed["findings"]},
        )

        directory = export_review_package(
            self.analysis,
            self.root / "unsigned-directory",
        )
        directory_signature = sign_review_package(
            directory,
            private_path,
            "Directory package signer",
            destination=self.root / "directory-package.sig.json",
            passphrase=b"test-passphrase",
        )
        verified_directory_signature = verify_review_signature(
            directory,
            directory_signature,
            public_path,
        )
        self.assertTrue(verified_directory_signature["valid"])
        directory_envelope = json.loads(
            directory_signature.read_text(encoding="utf-8")
        )
        self.assertEqual(
            directory_envelope["statement"]["subject"]["digest_scope"],
            "manifest_bytes",
        )
        with self.assertRaisesRegex(ValueError, "outside the package directory"):
            sign_review_package(
                directory,
                private_path,
                "Invalid destination",
                destination=directory / "signature.json",
                passphrase=b"test-passphrase",
            )

    def test_provider_rejects_spoofed_loopback_and_embedded_credentials(self) -> None:
        payload = {"component": {"evidence_id": "CMP-1"}}
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            OpenAICompatibleProvider(
                "http://localhost.evil.example/v1/chat/completions", "model"
            ).generate(payload, task="test")
        with self.assertRaisesRegex(ValueError, "embedded credentials"):
            OpenAICompatibleProvider(
                "https://user:secret@example.com/v1/chat/completions", "model"
            ).generate(payload, task="test")
        with patch("pysfmea.discovery.MAX_PROVIDER_REQUEST_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "3 MB safety limit"):
                OpenAICompatibleProvider(
                    "http://127.0.0.1:9999/v1/chat/completions", "model"
                ).generate(payload, task="test")

    def test_provider_strictly_decodes_nested_response_json(self) -> None:
        envelope = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"suggestions":[],"suggestions":[]}'
                        }
                    }
                ]
            }
        ).encode("utf-8")

        class FakeResponse:
            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, limit: int) -> bytes:
                self.limit = limit
                return envelope

        class FakeOpener:
            def open(self, request: object, *, timeout: int) -> FakeResponse:
                return FakeResponse()

        with patch("pysfmea.discovery.urllib.request.build_opener", return_value=FakeOpener()):
            with self.assertRaisesRegex(ValueError, "duplicate object key"):
                OpenAICompatibleProvider(
                    "http://127.0.0.1:9999/v1/chat/completions", "model"
                ).generate({"component": {"evidence_id": "CMP-1"}}, task="test")

    def test_grounded_suggestion_review_and_baseline_invalidation(self) -> None:
        self.analysis["guidance"]["active_profiles"] = ["core_sfmea", "security"]
        created = discover_suggestions(
            self.analysis,
            StaticProvider(),
            scope="service.py:checkout",
            limit=1,
        )
        self.assertEqual(len(created), 1)
        self.assertEqual(self.analysis["summary"]["suggestions"]["proposed"], 1)
        self.assertNotIn("severity", created[0]["content"])
        self.assertEqual(
            created[0]["proposed_citation_ids"], ["NIST-SP-800-218-PW.7"]
        )
        reviewed = review_suggestion(
            self.analysis,
            created[0]["id"],
            decision="accept",
            reviewer="Jordan",
            rationale="Credible authorization boundary failure.",
        )
        self.assertEqual(reviewed["status"], "accepted")
        materialized = next(
            item
            for item in self.analysis["items"]
            if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertEqual(materialized["review"]["disposition"], "unreviewed")
        self.assertEqual(materialized["scanner"]["rule_id"], "machine_suggestion")
        self.assertEqual(
            materialized["scanner"]["citations"][0]["status"], "reviewer_accepted"
        )
        persisted_path = self.root / "accepted-citation.json"
        save_analysis(persisted_path, self.analysis)
        persisted = load_analysis(persisted_path)
        persisted_item = next(
            item
            for item in persisted["items"]
            if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertTrue(
            any(
                citation["citation_id"] == "NIST-SP-800-218-PW.7"
                and citation["status"] == "reviewer_accepted"
                for citation in persisted_item["scanner"]["citations"]
            )
        )

        proposed = discover_suggestions(
            self.analysis,
            StaticProvider(),
            scope="service.py:charge",
            limit=1,
        )[0]
        (self.root / "service.py").write_text(
            (self.root / "service.py").read_text(encoding="utf-8") + "\n# baseline change\n",
            encoding="utf-8",
        )
        merged = merge_rescan(self.analysis, scan_repository(self.root))
        stale = next(value for value in merged["suggestions"] if value["id"] == proposed["id"])
        self.assertEqual(stale["status"], "stale")
        retained = next(
            item for item in merged["items"] if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertEqual(retained["source_change"], "manual")
        self.assertEqual(retained["source_status"], "active")

    def test_machine_discovery_rejects_invented_guidance_citation(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown guidance IDs"):
            discover_suggestions(
                self.analysis,
                UnknownCitationProvider(),
                scope="service.py:checkout",
                limit=1,
            )

    def test_machine_discovery_is_closed_bounded_and_transactional(self) -> None:
        class SequencedProvider:
            name = "transaction-provider"
            model = "transaction-model"

            def __init__(self) -> None:
                self.calls = 0

            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                self.calls += 1
                if self.calls == 2:
                    return {"suggestions": "invalid"}
                return {
                    "suggestions": [
                        {
                            "failure_mode": "A transactionally staged proposal.",
                            "evidence_ids": [payload["component"]["evidence_id"]],
                        }
                    ]
                }

        original = copy.deepcopy(self.analysis)
        with self.assertRaisesRegex(ValueError, "suggestions must be a list"):
            discover_suggestions(
                self.analysis, SequencedProvider(), scope="service.py:*", limit=2
            )
        self.assertEqual(self.analysis, original)

        class UnknownFieldProvider(StaticProvider):
            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                result = super().generate(payload, task=task)
                result["suggestions"][0]["hidden_reasoning"] = "must not be retained"
                result["suggestions"][0]["citation_ids"] = []
                return result

        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            discover_suggestions(
                self.analysis,
                UnknownFieldProvider(),
                scope="service.py:checkout",
                limit=1,
            )
        self.assertEqual(self.analysis, original)

        deeply_nested: dict[str, Any] = {"suggestions": []}
        cursor = deeply_nested
        for _ in range(60):
            child: dict[str, Any] = {}
            cursor["nested"] = child
            cursor = child

        class DeepProvider:
            name = "deep-provider"
            model = "deep-model"

            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                return deeply_nested

        with self.assertRaisesRegex(ValueError, "depth limit"):
            discover_suggestions(
                self.analysis, DeepProvider(), scope="service.py:checkout", limit=1
            )
        self.assertEqual(self.analysis, original)

        with patch("pysfmea.discovery.MAX_PROVIDER_RESPONSE_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "byte safety limit"):
                discover_suggestions(
                    self.analysis,
                    StaticProvider(),
                    scope="service.py:checkout",
                    limit=1,
                )
        self.assertEqual(self.analysis, original)

        class TooManyProvider:
            name = "many-provider"
            model = "many-model"

            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                return {"suggestions": [{} for _ in range(26)]}

        with self.assertRaisesRegex(ValueError, "25-suggestion"):
            discover_suggestions(
                self.analysis,
                TooManyProvider(),
                scope="service.py:checkout",
                limit=1,
            )
        self.assertEqual(self.analysis, original)

    def test_suggestion_materialization_rolls_back_on_failure(self) -> None:
        class CitationlessProvider(StaticProvider):
            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                result = super().generate(payload, task=task)
                result["suggestions"][0]["citation_ids"] = []
                return result

        suggestion = discover_suggestions(
            self.analysis,
            CitationlessProvider(),
            scope="service.py:checkout",
            limit=1,
        )[0]
        original = copy.deepcopy(self.analysis)
        with patch(
            "pysfmea.discovery.update_item_review",
            side_effect=RuntimeError("injected materialization failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected materialization"):
                review_suggestion(
                    self.analysis,
                    suggestion["id"],
                    decision="accept",
                    reviewer="Jordan",
                    rationale="Exercise rollback.",
                )
        self.assertEqual(self.analysis, original)

    def test_machine_summary_response_is_closed_bounded_and_side_effect_free(
        self,
    ) -> None:
        class SummaryProvider:
            name = "summary-provider"
            model = "summary-model"

            def __init__(self, response: dict[str, Any]) -> None:
                self.response = response

            def generate(
                self, payload: dict[str, Any], *, task: str
            ) -> dict[str, Any]:
                return self.response

        original = copy.deepcopy(self.analysis)
        with self.assertRaisesRegex(ValueError, "must contain only"):
            generate_summary(
                self.analysis,
                SummaryProvider(
                    {
                        "summary": "Grounded summary.",
                        "evidence_ids": [],
                        "uncertainties": [],
                        "decision": "accept",
                    }
                ),
            )
        self.assertEqual(self.analysis, original)

        with self.assertRaisesRegex(ValueError, "character limit"):
            generate_summary(
                self.analysis,
                SummaryProvider(
                    {
                        "summary": "x" * 20_001,
                        "evidence_ids": [],
                        "uncertainties": [],
                    }
                ),
            )
        self.assertEqual(self.analysis, original)

        record = generate_summary(
            self.analysis,
            SummaryProvider(
                {
                    "summary": "The indexed findings require engineering review.",
                    "evidence_ids": [],
                    "uncertainties": ["Runtime behavior was not supplied."],
                }
            ),
        )
        self.assertEqual(len(record["response_hash"]), 64)
        self.assertEqual(record["prompt_version"], "sfmea-grounded-discovery-3")

    def test_framework_metadata_summary_and_evaluation_hook(self) -> None:
        (self.root / "api.py").write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
            "@router.post('/checkout')\ndef endpoint(value):\n    return value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        endpoint = next(value for value in analysis["components"] if value["qualname"] == "endpoint")
        self.assertIn("fastapi", endpoint["frameworks"])
        self.assertIn("http_route", endpoint["entrypoint_types"])
        summary = deterministic_summary(analysis)
        self.assertGreater(summary["counts"]["failure_modes"], 0)
        expected = {
            "cases": [
                {"component": "endpoint", "rule_id": "functional.omission"}
            ]
        }
        result = evaluate_candidates(analysis, expected)
        self.assertEqual(result["recall"], 1.0)

        (self.root / "other.py").write_text(
            "def endpoint(value):\n    return value\n", encoding="utf-8"
        )
        ambiguous = scan_repository(self.root)
        with self.assertRaisesRegex(ValueError, "ambiguous across sources"):
            evaluate_candidates(ambiguous, expected)
        expected["cases"][0]["source"] = "api.py"
        source_aware = evaluate_candidates(ambiguous, expected)
        self.assertEqual(source_aware["matched"], 1)
        self.assertEqual(source_aware["missing"], [])

    def test_openapi_and_protobuf_contracts_become_analysis_elements(self) -> None:
        (self.root / "openapi.json").write_text(
            json.dumps(
                {
                    "openapi": "3.1.0",
                    "paths": {"/payments": {"post": {"responses": {"200": {}}}}},
                    "components": {"schemas": {"Payment": {"type": "object"}}},
                }
            ),
            encoding="utf-8",
        )
        (self.root / "payments.proto").write_text(
            "syntax = \"proto3\";\nmessage Payment {}\nservice Billing { rpc Charge(Payment) returns (Payment); }\n",
            encoding="utf-8",
        )
        analysis = scan_repository(
            self.root,
            config={
                "hazards": [
                    {
                        "id": "HZ-CONTRACT",
                        "description": "Payment request is misinterpreted.",
                        "end_effect": "A payment is processed incorrectly.",
                        "severity": 8,
                    }
                ],
                "requirements": [
                    {"id": "REQ-CONTRACT", "text": "Maintain API compatibility."}
                ],
                "system_interfaces": [
                    {"id": "IF-PAY", "source": "Client", "target": "Payment API"}
                ],
                "component_mappings": [
                    {
                        "pattern": "openapi.json:Interface contract *",
                        "subsystem": "Payments",
                        "requirements": ["REQ-CONTRACT"],
                        "hazards": ["HZ-CONTRACT"],
                        "interfaces": ["IF-PAY"],
                    }
                ],
            },
        )
        self.assertEqual(len(analysis["context"]["contracts"]), 2)
        contract_items = [
            item
            for item in analysis["items"]
            if item["scanner"]["rule_id"] == "interface.contract_compatibility"
        ]
        self.assertEqual(len(contract_items), 2)
        evidence = " ".join(contract_items[0]["scanner"]["evidence"])
        self.assertTrue("POST /payments" in evidence or "Charge" in evidence)
        openapi_item = next(
            item for item in contract_items if item["source"]["path"] == "openapi.json"
        )
        self.assertEqual(openapi_item["review"]["requirement"], "REQ-CONTRACT")
        self.assertEqual(openapi_item["review"]["linked_hazards"], ["HZ-CONTRACT"])
        self.assertEqual(openapi_item["review"]["severity"], 8)
        openapi_component = next(
            component
            for component in analysis["components"]
            if component["id"] == openapi_item["component_id"]
        )
        self.assertEqual(openapi_component["interface_ids"], ["IF-PAY"])
        self.assertEqual(openapi_component["subsystems"], ["Payments"])

    def test_model_cannot_generate_decision_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "prohibited decision fields"):
            discover_suggestions(
                self.analysis,
                UnsafeProvider(),
                scope="service.py:checkout",
                limit=1,
            )

    def test_evidence_packets_redact_common_secret_shapes(self) -> None:
        self.analysis["context"]["project"]["operating_context"] = (
            "API_KEY=super-secret-value and Bearer abc.def.ghi"
        )
        packet = evidence_packets(
            self.analysis, scope="service.py:checkout", limit=1
        )[0]
        serialized = json.dumps(packet)
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("abc.def.ghi", serialized)
        self.assertIn("[REDACTED]", serialized)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.architecture import architecture_graph, export_architecture
from pysfmea.config import load_config, write_config_template
from pysfmea.discovery import evidence_packets
from pysfmea.guidance import load_organizational_guidance_pack
from pysfmea.json_ingestion import load_bounded_file_snapshot
from pysfmea.model import calculate_rpn
from pysfmea.report import export_audit, export_csv, export_inventory, export_markdown
from pysfmea.repository_inventory import build_repository_inventory
from pysfmea.scanner import (
    _load_coverage,
    _read_python_source_bytes_bounded,
    scan_repository,
)
from pysfmea.store import add_manual_item, merge_rescan, update_item_review

SAMPLE_SOURCE = """
import asyncio
import json
import os
import requests

def calculate_total(value):
    if value < 0:
        return 0
    return value * 2

async def fetch_configuration(key):
    endpoint = os.getenv("CONFIG_ENDPOINT")
    try:
        response = requests.get(endpoint)
    except Exception:
        pass
    await asyncio.sleep(0)
    return json.loads(response.text)[key]

def _private_helper():
    return 1
"""


def _identity_sequence(*values: bool):
    outcomes = iter(values)
    return lambda *_args: next(outcomes, True)


def _identity_changes_once():
    return _identity_sequence(True, False)


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "app.py").write_text(SAMPLE_SOURCE, encoding="utf-8")
        tests = self.root / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text(
            "from app import calculate_total\n\ndef test_total():\n    assert calculate_total(2) == 4\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_scan_finds_components_signals_and_guidewords(self) -> None:
        analysis = scan_repository(self.root)
        components = {entry["qualname"]: entry for entry in analysis["components"]}

        self.assertIn("calculate_total", components)
        self.assertIn("fetch_configuration", components)
        self.assertIn("_private_helper", components)
        self.assertEqual(components["calculate_total"]["test_references"], ["tests/test_app.py"])
        signals = set(components["fetch_configuration"]["signals"])
        self.assertTrue({"concurrency", "configuration", "external_interface", "serialization"} <= signals)

        rules = {
            item["scanner"]["rule_id"]
            for item in analysis["items"]
            if item["component"]["qualname"] == "fetch_configuration"
        }
        self.assertTrue(
            {
                "functional.omission",
                "functional.incorrect",
                "interface.unavailable",
                "interface.bad_response",
                "configuration.missing_or_wrong",
                "data.serialization",
                "timing.order_or_race",
                "detection.masked_failure",
            }
            <= rules
        )
        calculate_rules = {
            item["scanner"]["rule_id"]
            for item in analysis["items"]
            if item["component"]["qualname"] == "calculate_total"
        }
        self.assertIn("calculation.precision_or_range", calculate_rules)

    def test_scan_extracts_circuit_breaker_semantics_without_crediting_control(self) -> None:
        (self.root / "breaker.py").write_text(
            "import asyncio\n"
            "import time\n\n"
            "TIMEOUTS = {'circuit_breaker_cooldown': 300}\n"
            "_circuit_lock = asyncio.Lock()\n"
            "_server_failures = {}\n"
            "_server_circuit_open = {}\n\n"
            "async def check_circuit(server_id):\n"
            "    async with _circuit_lock:\n"
            "        if server_id in _server_circuit_open:\n"
            "            if time.time() - _server_circuit_open[server_id] "
            "< TIMEOUTS['circuit_breaker_cooldown']:\n"
            "                return True\n"
            "            del _server_circuit_open[server_id]\n"
            "            _server_failures.pop(server_id, None)\n"
            "        if _server_failures.get(server_id, 0) >= 3:\n"
            "            _server_circuit_open[server_id] = time.time()\n"
            "            return True\n"
            "        return False\n\n"
            "async def degraded_tool(server_id):\n"
            "    if await check_circuit(server_id):\n"
            "        return 'circuit-breaker: server temporarily unavailable placeholder'\n"
            "    return 'normal'\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        components = {value["qualname"]: value for value in analysis["components"]}
        check = components["check_circuit"]
        self.assertIn("circuit_breaker", check["signals"])
        control = check["detected_controls"][0]
        self.assertEqual(control["kind"], "circuit_breaker")
        self.assertEqual(control["confidence"], "static_candidate")
        self.assertEqual(control["observed_states"], ["open"])
        self.assertTrue(
            {"closed", "open", "half_open"} <= set(control["expected_states"])
        )
        self.assertIn("admission_guard", control["roles"])
        self.assertIn("recovery_timer", control["roles"])
        self.assertIn("time.time", control["clock_sources"])
        self.assertIn("server_id", control["scope_keys"])
        self.assertTrue(control["threshold_expressions"])
        self.assertTrue(control["cooldown_expressions"])
        self.assertEqual(control["synchronization"], ["_circuit_lock"])

        findings = [
            value
            for value in analysis["items"]
            if value["component"]["qualname"] == "check_circuit"
            and value["scanner"]["rule_id"].startswith(
                "resilience.circuit_breaker_"
            )
        ]
        self.assertEqual(
            {value["scanner"]["rule_id"] for value in findings},
            {
                "resilience.circuit_breaker_containment",
                "resilience.circuit_breaker_recovery",
                "resilience.circuit_breaker_isolation",
            },
        )
        self.assertTrue(
            all(
                "python.resilience_control_analyzer"
                in value["scanner"]["adapter_ids"]
                for value in findings
            )
        )
        self.assertTrue(
            all(not value["review"]["prevention_controls"] for value in findings)
        )
        obligations = {
            value["rule_id"]: value
            for value in analysis["assurance"]["obligations"]
            if value["finding_id"] in {finding["id"] for finding in findings}
        }
        obligation = obligations["resilience.circuit_breaker_containment"]
        self.assertEqual(obligation["verification_method"], "fault_injection_test")
        self.assertEqual(
            obligation["detected_control_model"]["kind"], "circuit_breaker"
        )
        self.assertFalse(
            any("HALF-OPEN" in value for value in obligation["acceptance_criteria"])
        )
        recovery = obligations["resilience.circuit_breaker_recovery"]
        self.assertTrue(
            any("HALF-OPEN" in value for value in recovery["acceptance_criteria"])
        )
        self.assertTrue(recovery["control_review_questions"])
        isolation = obligations["resilience.circuit_breaker_isolation"]
        self.assertTrue(
            any("unrelated isolation key" in value for value in isolation["acceptance_criteria"])
        )
        self.assertFalse(
            any("Cooldown" in value for value in isolation["acceptance_criteria"])
        )
        fallback = next(
            value
            for value in analysis["assurance"]["obligations"]
            if value["rule_id"] == "resilience.circuit_breaker_fallback"
        )
        self.assertTrue(
            any("Fallback/degraded output" in value for value in fallback["acceptance_criteria"])
        )
        self.assertFalse(
            any("Cooldown" in value for value in fallback["acceptance_criteria"])
        )

    def test_scan_correlates_distributed_class_breaker_members(self) -> None:
        (self.root / "class_breaker.py").write_text(
            "import time\n\n"
            "class CircuitBreaker:\n"
            "    def __init__(self, failure_threshold=3, recovery_timeout=30):\n"
            "        self.state = 'CLOSED'\n"
            "        self.failure_count = 0\n"
            "        self.failure_threshold = failure_threshold\n"
            "        self.recovery_timeout = recovery_timeout\n"
            "        self.last_failure_time = 0.0\n\n"
            "    def allow_request(self):\n"
            "        if self.state == 'OPEN':\n"
            "            if time.monotonic() - self.last_failure_time >= self.recovery_timeout:\n"
            "                self.state = 'HALF_OPEN'\n"
            "                return True\n"
            "            return False\n"
            "        return True\n\n"
            "    def record_failure(self):\n"
            "        self.failure_count += 1\n"
            "        if self.failure_count >= self.failure_threshold:\n"
            "            self.state = 'OPEN'\n"
            "            self.last_failure_time = time.monotonic()\n\n"
            "    def record_success(self):\n"
            "        self.failure_count = 0\n"
            "        self.state = 'CLOSED'\n",
            encoding="utf-8",
        )

        analysis = scan_repository(self.root)
        members = {
            value["qualname"]: value
            for value in analysis["components"]
            if value["qualname"].startswith("CircuitBreaker.")
        }
        controls = [
            value["detected_controls"][0]
            for value in members.values()
            if value["detected_controls"]
        ]

        self.assertEqual(len(controls), 4)
        self.assertEqual(
            {value["scope_qualname"] for value in controls}, {"CircuitBreaker"}
        )
        self.assertEqual(
            {value["member_qualname"] for value in controls}, set(members)
        )
        self.assertTrue(
            {"admission_guard", "failure_recording", "success_reset", "recovery_timer"}
            <= {role for value in controls for role in value["roles"]}
        )
        self.assertTrue(all(value["detection_basis"] for value in controls))

    def test_scan_does_not_treat_descriptive_circuit_text_as_a_control(self) -> None:
        (self.root / "documentation.py").write_text(
            "def describe_circuit_diagram():\n"
            "    return 'A circuit diagram connects ordinary components.'\n",
            encoding="utf-8",
        )

        analysis = scan_repository(self.root)
        component = next(
            value
            for value in analysis["components"]
            if value["qualname"] == "describe_circuit_diagram"
        )
        self.assertNotIn("circuit_breaker", component["signals"])
        self.assertEqual(component["detected_controls"], [])
        self.assertFalse(
            any(
                item["component_id"] == component["id"]
                and item["scanner"]["rule_id"].startswith(
                    "resilience.circuit_breaker_"
                )
                for item in analysis["items"]
            )
        )

    def test_scan_records_context_repository_coverage_and_adapter_contributions(self) -> None:
        (self.root / "README.md").write_text("# System\n", encoding="utf-8")
        (self.root / "opaque.bin").write_bytes(b"\x00\x01")
        excluded = self.root / "generated"
        excluded.mkdir()
        (excluded / "generated.py").write_text("def hidden():\n    pass\n", encoding="utf-8")
        (self.root / "broken.py").write_text("def broken(:\n", encoding="utf-8")

        analysis = scan_repository(
            self.root,
            config={
                "project": {
                    "name": "Context example",
                    "purpose": "Exercise governed discovery.",
                    "boundary": "Temporary repository.",
                    "operating_context": "Local analysis only.",
                    "operational_modes": ["normal"],
                    "safe_states": ["stopped"],
                },
                "scan": {"exclude": ["generated/**"]},
            },
        )

        context = analysis["system_context"]
        self.assertEqual(context["schema_version"], "pysfmea-system-context-1")
        self.assertEqual(context["status"], "partial")
        self.assertIn("must_work_functions", context["missing_recommended"])
        self.assertEqual(len(context["context_sha256"]), 64)

        inventory = analysis["repository_inventory"]
        by_path = {entry["path"]: entry for entry in inventory["entries"]}
        self.assertEqual(by_path["app.py"]["status"], "analyzed")
        self.assertEqual(by_path["tests/test_app.py"]["status"], "excluded_region")
        self.assertEqual(by_path["broken.py"]["status"], "unresolved")
        self.assertEqual(by_path["opaque.bin"]["status"], "opaque")
        self.assertEqual(
            inventory["summary"]["by_snapshot_source"]["analysis_source_snapshot"],
            2,
        )
        self.assertEqual(
            inventory["summary"]["by_snapshot_source"]["test_evidence_snapshot"],
            1,
        )
        self.assertTrue(
            any(region["path"] == "generated/" for region in inventory["regions"])
        )
        self.assertEqual(
            analysis["project"]["baseline"]["repository_inventory_sha256"],
            inventory["inventory_sha256"],
        )

        contributor_ids = {
            adapter_id
            for item in analysis["items"]
            for adapter_id in item["scanner"]["adapter_ids"]
        }
        self.assertGreater(len(contributor_ids), 2)
        self.assertIn("python.concurrency_analyzer", contributor_ids)
        self.assertIn("repository.configuration_analyzer", contributor_ids)
        ledger = analysis["adapter_runs"]
        self.assertEqual(ledger["schema_version"], "pysfmea-adapter-run-ledger-1")
        self.assertEqual(len(ledger["ledger_sha256"]), 64)
        failure_run = next(
            run
            for run in ledger["runs"]
            if run["adapter_id"] == "python.failure_rule_analyzer"
        )
        self.assertEqual(failure_run["status"], "completed")
        self.assertEqual(failure_run["contribution_count"], len(analysis["items"]))

    def test_organizational_guidance_pack_is_hashed_and_traced_to_findings(self) -> None:
        pack = {
            "schema_version": "pysfmea-organizational-guidance-pack-1",
            "profile": {
                "id": "org.example_assurance",
                "title": "Example organizational software assurance",
                "status": "approved_internal",
                "applicability": "Projects that formally adopt EX-STD-1.",
                "risk_semantics": "Use the approved project risk matrix.",
                "verification_semantics": "Controls require independent objective evidence.",
                "tailoring": "Record the approved tailoring decision.",
                "compliance_claim": False,
            },
            "sources": [
                {
                    "id": "ORG-EX-STD-1",
                    "publisher": "Example Engineering",
                    "title": "Software Assurance Standard",
                    "version": "1.0",
                    "status": "approved",
                    "published_at": "2026-08-01",
                    "url": "https://example.invalid/standards/ex-std-1",
                    "official_source": "Controlled document system EX-STD-1",
                    "scope": "Safety-related Python services",
                    "use": "Failure analysis and verification planning",
                    "access": "licensed_internal",
                    "quote_policy": "Do not reproduce controlled text; locator summaries only.",
                }
            ],
            "citations": [
                {
                    "id": "ORG-CIT-EX-OMISSION",
                    "source_id": "ORG-EX-STD-1",
                    "locator": {"section": "4.2", "heading": "Omission failures"},
                    "summary": "Review required functions for omitted behavior.",
                }
            ],
            "rule_mappings": [
                {
                    "id": "ORG-MAP-EX-OMISSION",
                    "rule_selector": "functional.omission",
                    "citation_id": "ORG-CIT-EX-OMISSION",
                    "relationship": "failure_taxonomy",
                    "strength": "direct",
                }
            ],
        }
        pack_path = self.root / "example-guidance.json"
        pack_path.write_text(json.dumps(pack), encoding="utf-8")

        analysis = scan_repository(
            self.root,
            config={"analysis": {"guidance_packs": ["example-guidance.json"]}},
        )

        guidance = analysis["guidance"]
        self.assertIn("org.example_assurance", guidance["active_profiles"])
        self.assertEqual(guidance["organizational_packs"][0]["path"], pack_path.name)
        self.assertEqual(len(guidance["organizational_packs"][0]["sha256"]), 64)
        omission = next(
            item
            for item in analysis["items"]
            if item["scanner"]["rule_id"] == "functional.omission"
        )
        self.assertIn(
            "ORG-CIT-EX-OMISSION",
            {value["citation_id"] for value in omission["scanner"]["citations"]},
        )
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"]["guidance_catalog_sha256"],
            guidance["catalog_sha256"],
        )
        packets = evidence_packets(analysis, limit=2)
        self.assertTrue(packets)
        self.assertIn(
            "ORG-CIT-EX-OMISSION", packets[0]["allowed_citation_ids"]
        )

        loaded = load_organizational_guidance_pack(pack_path)
        raw = pack_path.read_bytes()
        self.assertEqual(loaded["provenance"]["bytes"], len(raw))
        self.assertEqual(
            loaded["provenance"]["sha256"],
            hashlib.sha256(raw).hexdigest(),
        )

        canonical_pack = json.dumps(pack, separators=(",", ":"))
        pack_path.write_text(
            '{"schema_version":"ambiguous",' + canonical_pack[1:],
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            load_organizational_guidance_pack(pack_path)
        for value in ("NaN", "1e9999"):
            with self.subTest(non_finite=value):
                pack_path.write_text(
                    '{"numeric_probe":' + value + "," + canonical_pack[1:],
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "non-finite number"):
                    load_organizational_guidance_pack(pack_path)
        pack_path.write_text(canonical_pack, encoding="utf-8")
        with patch(
            "pysfmea.guidance.MAX_ORGANIZATIONAL_GUIDANCE_PACK_NODES", 2
        ):
            with self.assertRaisesRegex(ValueError, "2-node JSON structure limit"):
                load_organizational_guidance_pack(pack_path)
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            with self.assertRaisesRegex(ValueError, "changed during bounded consumption"):
                load_organizational_guidance_pack(pack_path)

        pack_directory = self.root / "guidance-directory"
        pack_directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link file"):
            load_organizational_guidance_pack(pack_directory)

        invalid_utf8 = self.root / "invalid-guidance.json"
        invalid_utf8.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
            load_organizational_guidance_pack(invalid_utf8)

        oversized = self.root / "oversized-guidance.json"
        oversized.write_bytes(b"x" * 11)
        with patch(
            "pysfmea.guidance.MAX_ORGANIZATIONAL_GUIDANCE_PACK_BYTES", 10
        ):
            with self.assertRaisesRegex(ValueError, "10-byte safety limit"):
                load_organizational_guidance_pack(oversized)

        with patch("pysfmea.json_ingestion.stat.S_ISLNK", return_value=True):
            with self.assertRaisesRegex(ValueError, "non-symbolic-link"):
                load_organizational_guidance_pack(pack_path)

        linked_pack = self.root / "linked-guidance.json"
        try:
            linked_pack.symlink_to(pack_path)
        except OSError:
            linked_pack = None
        if linked_pack is not None:
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                load_organizational_guidance_pack(linked_pack)

    def test_faa_failure_classes_and_configured_scope(self) -> None:
        (self.root / "device.py").write_text(
            "import math\nimport serial\nimport sys\n\ndef control(port, value):\n"
            "    device = serial.Serial(port)\n"
            "    if sys.platform == 'win32':\n"
            "        device.write(bytes([round(math.sqrt(value))]))\n"
            "    return value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        rules = {
            item["scanner"]["rule_id"]
            for item in analysis["items"]
            if item["component"]["qualname"] == "control"
        }
        self.assertTrue(
            {
                "calculation.precision_or_range",
                "environment.runtime_incompatibility",
                "hardware.abnormal_response",
                "data.invalid_input",
            }
            <= rules
        )
        functional_only = scan_repository(
            self.root,
            config={"analysis": {"included_failure_classes": ["functional"]}},
        )
        self.assertEqual(
            {
                item["scanner"]["failure_class"]
                for item in functional_only["items"]
            },
            {"functional"},
        )

    def test_dependency_environment_is_inventoried_and_change_tracked(self) -> None:
        (self.root / "requirements.txt").write_text(
            "requests==2.32.0\ncritical-lib>=1.0\n",
            encoding="utf-8",
        )
        first = scan_repository(self.root)
        environment = next(
            item
            for item in first["items"]
            if item["scanner"]["rule_id"] == "environment.dependency_drift"
        )
        self.assertTrue(
            {"requests", "critical-lib", "manifest:requirements.txt"}
            <= {entry["name"] for entry in first["context"]["dependencies"]}
        )
        dependency_entries = {
            entry["name"]: entry for entry in first["context"]["dependencies"]
        }
        requirements_raw = (self.root / "requirements.txt").read_bytes()
        requirements_digest = hashlib.sha256(requirements_raw).hexdigest()
        self.assertEqual(
            dependency_entries["manifest:requirements.txt"],
            {
                "name": "manifest:requirements.txt",
                "specification": f"sha256:{requirements_digest}",
                "source": "requirements.txt",
                "evidence_type": "manifest_snapshot",
                "bytes": len(requirements_raw),
                "sha256": requirements_digest,
            },
        )
        self.assertEqual(
            first["run_manifest"]["resolved_inputs"]["dependency_inventory_sha256"],
            hashlib.sha256(
                json.dumps(
                    first["context"]["dependencies"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        dependency_run = next(
            run
            for run in first["adapter_runs"]["runs"]
            if run["adapter_id"] == "python.dependency_inventory"
        )
        self.assertEqual(dependency_run["adapter_version"], "4")
        update_item_review(first, environment["id"], {"disposition": "accepted"})
        (self.root / "requirements.txt").write_text(
            "requests==2.33.0\ncritical-lib>=1.0\n",
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        updated = next(item for item in merged["items"] if item["id"] == environment["id"])
        self.assertEqual(updated["source_change"], "changed")
        self.assertTrue(updated["review"]["revalidation_required"])

    def test_dependency_and_contract_snapshots_are_reused_by_inventory(self) -> None:
        evidence_root = self.root / "supporting-evidence-snapshots"
        evidence_root.mkdir()
        service = evidence_root / "service.py"
        requirements = evidence_root / "requirements.txt"
        contract = evidence_root / "openapi.json"
        service.write_text("def execute():\n    return True\n", encoding="utf-8")
        requirements_raw = b"critical-lib==1.0\n"
        contract_raw = json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {"/ready": {"get": {}}},
                "components": {"schemas": {}},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        requirements.write_bytes(requirements_raw)
        contract.write_bytes(contract_raw)

        def replace_before_inventory(*args, **kwargs):
            requirements.write_text("critical-lib==9.9\n", encoding="utf-8")
            contract.write_text(
                '{"openapi":"3.1.0","paths":{},"components":{"schemas":{}}}',
                encoding="utf-8",
            )
            return build_repository_inventory(*args, **kwargs)

        with patch(
            "pysfmea.repository_inventory.load_bounded_file_snapshot",
            wraps=load_bounded_file_snapshot,
        ) as inventory_reader, patch(
            "pysfmea.scanner.build_repository_inventory",
            side_effect=replace_before_inventory,
        ):
            analysis = scan_repository(evidence_root)

        self.assertEqual(inventory_reader.call_count, 0)
        dependency = next(
            entry
            for entry in analysis["context"]["dependencies"]
            if entry["name"] == "manifest:requirements.txt"
        )
        self.assertEqual(
            dependency["sha256"], hashlib.sha256(requirements_raw).hexdigest()
        )
        contract_entry = analysis["context"]["contracts"][0]
        self.assertEqual(contract_entry["sha256"], hashlib.sha256(contract_raw).hexdigest())
        self.assertEqual(contract_entry["operations"], ["GET /ready"])
        inventory = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(
            inventory["requirements.txt"]["sha256"],
            hashlib.sha256(requirements_raw).hexdigest(),
        )
        self.assertEqual(
            inventory["requirements.txt"]["snapshot_source"],
            "dependency_manifest_snapshot",
        )
        self.assertEqual(
            inventory["openapi.json"]["sha256"],
            hashlib.sha256(contract_raw).hexdigest(),
        )
        self.assertEqual(
            inventory["openapi.json"]["snapshot_source"],
            "interface_contract_snapshot",
        )
        snapshot_counts = analysis["repository_inventory"]["summary"][
            "by_snapshot_source"
        ]
        self.assertEqual(snapshot_counts["dependency_manifest_snapshot"], 1)
        self.assertEqual(snapshot_counts["interface_contract_snapshot"], 1)
        contract_run = next(
            run
            for run in analysis["adapter_runs"]["runs"]
            if run["adapter_id"] == "contracts.local_schema"
        )
        self.assertEqual(contract_run["adapter_version"], "3")

    def test_lockfile_and_included_requirement_changes_are_tracked(self) -> None:
        constraints = self.root / "constraints"
        constraints.mkdir()
        (constraints / "base.txt").write_text("critical-lib==1.0\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text(
            "-r constraints/base.txt\n", encoding="utf-8"
        )
        (self.root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        first = scan_repository(self.root)
        environment = next(
            item
            for item in first["items"]
            if item["scanner"]["rule_id"] == "environment.dependency_drift"
        )
        names = {entry["name"] for entry in first["context"]["dependencies"]}
        self.assertIn("critical-lib", names)
        self.assertIn("manifest:constraints/base.txt", names)
        self.assertIn("manifest:uv.lock", names)
        update_item_review(first, environment["id"], {"disposition": "rejected"})
        (self.root / "uv.lock").write_text("version = 2\n", encoding="utf-8")
        merged = merge_rescan(first, scan_repository(self.root))
        updated = next(item for item in merged["items"] if item["id"] == environment["id"])
        self.assertEqual(updated["source_change"], "changed")
        self.assertTrue(updated["review"]["revalidation_required"])

    def test_dependency_manifest_ingestion_is_bounded_link_safe_and_aggregate_limited(
        self,
    ) -> None:
        constraints = self.root / "constraints"
        constraints.mkdir()
        base = constraints / "base.txt"
        base.write_text("critical-lib==1.0\n", encoding="utf-8")
        invalid = constraints / "invalid.txt"
        invalid.write_bytes(b"invalid-lib==1.0\n\xff")
        requirements = self.root / "requirements.txt"
        requirements.write_text(
            "requests==2.32.0\n"
            "-r constraints/base.txt\n"
            "-r constraints/invalid.txt\n"
            "-r ../outside.txt\n",
            encoding="utf-8",
        )
        (self.root / "uv.lock").write_bytes(b"x" * 256)
        pipfile = self.root / "Pipfile"
        pipfile.write_text("requests = '*'\n", encoding="utf-8")
        original_is_symlink = Path.is_symlink

        def marked_link(path: Path) -> bool:
            return path.name == pipfile.name or original_is_symlink(path)

        with (
            patch("pysfmea.scanner.MAX_DEPENDENCY_MANIFEST_BYTES", 128),
            patch(
                "pysfmea.scanner.Path.is_symlink",
                autospec=True,
                side_effect=marked_link,
            ),
        ):
            analysis = scan_repository(self.root)

        dependencies = {
            entry["name"]: entry for entry in analysis["context"]["dependencies"]
        }
        self.assertIn("requests", dependencies)
        self.assertIn("critical-lib", dependencies)
        self.assertIn("manifest:requirements.txt", dependencies)
        self.assertIn("manifest:constraints/base.txt", dependencies)
        self.assertEqual(
            dependencies["manifest:constraints/invalid.txt"]["specification"],
            f"sha256:{hashlib.sha256(invalid.read_bytes()).hexdigest()}",
        )
        self.assertNotIn("manifest:uv.lock", dependencies)
        self.assertNotIn("manifest:Pipfile", dependencies)
        warnings = {
            (warning["path"], warning["message"])
            for warning in analysis["warnings"]
            if warning["type"] == "DependencyError"
        }
        self.assertIn(
            ("uv.lock", "Dependency manifest exceeds the 128-byte analysis limit"),
            warnings,
        )
        self.assertIn(
            ("constraints/invalid.txt", "Dependency manifest is not valid UTF-8 text"),
            warnings,
        )
        self.assertIn(
            ("Pipfile", "Dependency manifest must be a regular non-symbolic-link file"),
            warnings,
        )
        self.assertTrue(
            any(message == "Dependency manifest resolves outside the repository" for _, message in warnings)
        )

        with patch("pysfmea.scanner.MAX_DEPENDENCY_MANIFEST_FILES", 1):
            file_limited = scan_repository(self.root)
        file_limited_names = {
            entry["name"] for entry in file_limited["context"]["dependencies"]
        }
        self.assertIn("requests", file_limited_names)
        self.assertNotIn("critical-lib", file_limited_names)
        self.assertTrue(
            any(
                warning["type"] == "DependencyError"
                and warning["message"]
                == "Dependency manifest discovery reached the 1-file limit"
                for warning in file_limited["warnings"]
            )
        )

        with patch(
            "pysfmea.scanner.MAX_DEPENDENCY_MANIFEST_TOTAL_BYTES",
            len(requirements.read_bytes()),
        ):
            aggregate_limited = scan_repository(self.root)
        self.assertTrue(
            any(
                warning["path"] == "constraints/base.txt"
                and warning["type"] == "DependencyError"
                and "aggregate limit" in warning["message"]
                for warning in aggregate_limited["warnings"]
            )
        )
        aggregate_names = {
            entry["name"] for entry in aggregate_limited["context"]["dependencies"]
        }
        self.assertIn("requests", aggregate_names)
        self.assertNotIn("critical-lib", aggregate_names)

        race_root = self.root / "dependency-race"
        race_root.mkdir()
        changing = race_root / "requirements.txt"
        changing.write_text("changing-lib==1.0\n", encoding="utf-8")
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            raced = scan_repository(race_root)
        self.assertEqual(raced["context"]["dependencies"], [])
        self.assertTrue(
            any(
                warning["path"] == changing.name
                and warning["type"] == "DependencyError"
                and "changed during bounded consumption" in warning["message"]
                for warning in raced["warnings"]
            )
        )

    def test_pyproject_dependency_shape_and_encoding_fail_closed(self) -> None:
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "invalid-shape"\ndependencies = "requests"\n',
            encoding="utf-8",
        )
        malformed = scan_repository(self.root)
        malformed_names = {
            entry["name"] for entry in malformed["context"]["dependencies"]
        }
        self.assertIn("manifest:pyproject.toml", malformed_names)
        self.assertNotIn("requests", malformed_names)
        self.assertTrue(
            any(
                warning["path"] == "pyproject.toml"
                and warning["type"] == "DependencyError"
                and warning["message"]
                == "Dependency manifest is not valid supported TOML"
                for warning in malformed["warnings"]
            )
        )

        pyproject.write_bytes(b"\xff\xfe")
        invalid_encoding = scan_repository(self.root)
        invalid_names = {
            entry["name"] for entry in invalid_encoding["context"]["dependencies"]
        }
        self.assertIn("manifest:pyproject.toml", invalid_names)
        self.assertTrue(
            any(
                warning["path"] == "pyproject.toml"
                and warning["type"] == "DependencyError"
                and warning["message"] == "Dependency manifest is not valid UTF-8 TOML"
                for warning in invalid_encoding["warnings"]
            )
        )

    def test_contract_ingestion_is_bounded_link_safe_and_type_safe(self) -> None:
        openapi = self.root / "openapi.json"
        openapi.write_text("[]", encoding="utf-8")
        invalid_schema = self.root / "invalid.schema.json"
        invalid_schema.write_bytes(b"\xff\xfe")
        many = self.root / "many.proto"
        many.write_text(
            "service Example { rpc First(Request) returns (Reply); "
            "rpc Second(Request) returns (Reply); }\n"
            "message Request {}\nmessage Reply {}\n",
            encoding="utf-8",
        )
        oversized = self.root / "oversized.proto"
        oversized.write_bytes(b"x" * 256)
        linked = self.root / "linked.proto"
        linked.write_text("message Linked {}\n", encoding="utf-8")
        escaped = self.root / "escaped.proto"
        escaped.write_text("message Escaped {}\n", encoding="utf-8")
        original_is_symlink = Path.is_symlink
        original_resolve = Path.resolve

        def marked_link(path: Path) -> bool:
            return path.name == linked.name or original_is_symlink(path)

        def redirected_contract(path: Path, strict: bool = False) -> Path:
            if path.name == escaped.name:
                return self.root.parent / "outside.proto"
            return original_resolve(path, strict=strict)

        with (
            patch("pysfmea.scanner.MAX_CONTRACT_BYTES", 160),
            patch("pysfmea.scanner.MAX_CONTRACT_ENTITIES", 1),
            patch(
                "pysfmea.scanner.Path.is_symlink",
                autospec=True,
                side_effect=marked_link,
            ),
            patch(
                "pysfmea.scanner.Path.resolve",
                autospec=True,
                side_effect=redirected_contract,
            ),
        ):
            analysis = scan_repository(self.root)

        contracts = {
            contract["path"]: contract for contract in analysis["context"]["contracts"]
        }
        self.assertEqual(
            set(contracts),
            {"invalid.schema.json", "many.proto", "openapi.json"},
        )
        self.assertEqual(
            contracts["invalid.schema.json"]["sha256"],
            hashlib.sha256(invalid_schema.read_bytes()).hexdigest(),
        )
        self.assertEqual(contracts["many.proto"]["bytes"], len(many.read_bytes()))
        self.assertEqual(len(contracts["many.proto"]["operations"]), 1)
        self.assertEqual(len(contracts["many.proto"]["data_types"]), 1)
        self.assertEqual(contracts["openapi.json"]["operations"], [])
        warnings = {
            (warning["path"], warning["type"]): warning["message"]
            for warning in analysis["warnings"]
        }
        self.assertEqual(
            warnings[("openapi.json", "ContractError")],
            "Contract JSON has malformed or unsupported structure",
        )
        self.assertEqual(
            warnings[("invalid.schema.json", "ContractError")],
            "Contract is not valid UTF-8 text",
        )
        self.assertEqual(
            warnings[("oversized.proto", "ContractTooLarge")],
            "Contract exceeds the 160-byte analysis limit",
        )
        self.assertEqual(
            warnings[("linked.proto", "ContractBoundary")],
            "Contract must be a regular non-symbolic-link file",
        )
        self.assertEqual(
            warnings[("escaped.proto", "OutsideRepository")],
            "Contract resolves outside the repository",
        )
        self.assertIn(
            "1-entity per-category limit",
            warnings[("many.proto", "ContractLimit")],
        )

        with patch("pysfmea.scanner.MAX_CONTRACT_FILES", 1):
            file_limited = scan_repository(self.root)
        self.assertEqual(len(file_limited["context"]["contracts"]), 1)
        self.assertTrue(
            any(
                warning["type"] == "ContractLimit"
                and warning["message"] == "Contract discovery reached the 1-file analysis limit"
                for warning in file_limited["warnings"]
            )
        )

    def test_contract_json_is_strict_structurally_bounded_and_identity_stable(
        self,
    ) -> None:
        duplicate = self.root / "duplicate.schema.json"
        duplicate.write_text(
            '{"title":"First","title":"Second","properties":{}}',
            encoding="utf-8",
        )
        overflow = self.root / "overflow.schema.json"
        overflow.write_text(
            '{"title":"Overflow","probe":1e9999,"properties":{}}',
            encoding="utf-8",
        )
        structured = self.root / "structured.schema.json"
        structured.write_text(
            json.dumps(
                {
                    "title": "Structured",
                    "properties": {"value": {"type": "string"}},
                }
            ),
            encoding="utf-8",
        )

        with patch("pysfmea.scanner.MAX_CONTRACT_JSON_NODES", 2):
            analysis = scan_repository(self.root)

        contracts = {
            contract["path"]: contract for contract in analysis["context"]["contracts"]
        }
        self.assertEqual(
            contracts[duplicate.name]["sha256"],
            hashlib.sha256(duplicate.read_bytes()).hexdigest(),
        )
        self.assertEqual(contracts[duplicate.name]["bytes"], len(duplicate.read_bytes()))
        warnings = {
            warning["path"]: warning["message"]
            for warning in analysis["warnings"]
            if warning["type"] == "ContractError"
        }
        self.assertIn("duplicate object key", warnings[duplicate.name])
        self.assertIn("non-finite number", warnings[overflow.name])
        self.assertIn("2-node JSON structure limit", warnings[structured.name])
        self.assertEqual(contracts[duplicate.name]["data_types"], [])
        self.assertEqual(contracts[overflow.name]["data_types"], [])
        self.assertEqual(contracts[structured.name]["data_types"], [])
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"]["contract_inventory_sha256"],
            hashlib.sha256(
                json.dumps(
                    analysis["context"]["contracts"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )

        race_root = self.root / "contract-race"
        race_root.mkdir()
        changing = race_root / "changing.proto"
        changing.write_text("message Changing {}\n", encoding="utf-8")
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            raced = scan_repository(race_root)
        self.assertEqual(raced["context"]["contracts"], [])
        self.assertTrue(
            any(
                warning["path"] == changing.name
                and warning["type"] == "ContractError"
                and "changed during bounded consumption" in warning["message"]
                for warning in raced["warnings"]
            )
        )

        with patch("pysfmea.scanner.MAX_CONTRACT_TOTAL_BYTES", 1):
            aggregate_limited = scan_repository(self.root)
        self.assertEqual(aggregate_limited["context"]["contracts"], [])
        self.assertTrue(
            any(
                warning["type"] == "ContractLimit"
                and warning["message"]
                == "Contract ingestion exceeds the 1-byte aggregate limit"
                for warning in aggregate_limited["warnings"]
            )
        )

    def test_repository_inventory_hashing_is_consumption_bounded_and_accounted(self) -> None:
        inventory_root = self.root / "inventory-case"
        inventory_root.mkdir()
        a_path = inventory_root / "a.txt"
        a_path.write_bytes(b"a" * 6)
        (inventory_root / "b.txt").write_bytes(b"b" * 6)
        (inventory_root / "c.txt").write_bytes(b"c" * 6)

        with (
            patch("pysfmea.repository_inventory.MAX_HASH_BYTES", 10),
            patch("pysfmea.repository_inventory.MAX_TOTAL_HASH_BYTES", 10),
        ):
            inventory = build_repository_inventory(
                inventory_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )

        entries = {entry["path"]: entry for entry in inventory["entries"]}
        self.assertEqual(
            entries["a.txt"]["sha256"],
            hashlib.sha256(a_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(entries["b.txt"]["sha256"], "")
        self.assertEqual(entries["b.txt"]["analysis_depth"], "metadata_only")
        self.assertEqual(entries["c.txt"]["sha256"], "")
        self.assertTrue(inventory["truncated"])
        self.assertTrue(
            any(
                region["path"] == "./"
                and region["status"] == "unresolved"
                and "10-byte aggregate safety limit" in region["reason"]
                for region in inventory["regions"]
            )
        )
        material = {
            key: inventory[key] for key in ("entries", "regions", "truncated")
        }
        self.assertEqual(
            inventory["inventory_sha256"],
            hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
        )

        oversized_root = self.root / "oversized-inventory"
        oversized_root.mkdir()
        (oversized_root / "large.bin").write_bytes(b"x" * 11)
        with (
            patch("pysfmea.repository_inventory.MAX_HASH_BYTES", 10),
            patch("pysfmea.repository_inventory.MAX_TOTAL_HASH_BYTES", 100),
        ):
            oversized = build_repository_inventory(
                oversized_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )
        oversized_entry = oversized["entries"][0]
        self.assertEqual(oversized_entry["status"], "opaque")
        self.assertEqual(oversized_entry["analysis_depth"], "metadata_only")
        self.assertEqual(oversized_entry["sha256"], "")
        self.assertIn("10-byte hashing and analysis limit", oversized_entry["reason"])

        snapshot_root = self.root / "snapshot-inventory"
        snapshot_root.mkdir()
        source = snapshot_root / "changing.py"
        accepted_raw = b"def accepted():\n    return True\n"
        source.write_bytes(b"def replacement():\n    return False\n")
        snapshot_inventory = build_repository_inventory(
            snapshot_root,
            selected_python_paths={source.name},
            parsed_python_paths={source.name},
            include_tests=False,
            source_snapshots={source.name: accepted_raw},
        )
        snapshot_entry = snapshot_inventory["entries"][0]
        self.assertEqual(snapshot_entry["status"], "analyzed")
        self.assertEqual(snapshot_entry["size"], len(accepted_raw))
        self.assertEqual(
            snapshot_entry["sha256"], hashlib.sha256(accepted_raw).hexdigest()
        )
        self.assertEqual(snapshot_entry["snapshot_source"], "analysis_source_snapshot")

        identity_root = self.root / "identity-inventory"
        identity_root.mkdir()
        (identity_root / "changing.txt").write_bytes(b"change")
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            identity_inventory = build_repository_inventory(
                identity_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )
        identity_entry = identity_inventory["entries"][0]
        self.assertEqual(identity_entry["status"], "unresolved")
        self.assertEqual(identity_entry["analysis_depth"], "none")
        self.assertEqual(identity_entry["sha256"], "")
        self.assertIn("changed during bounded consumption", identity_entry["reason"])

        linked_root = self.root / "linked-inventory"
        linked_root.mkdir()
        linked = linked_root / "linked.txt"
        linked.write_text("linked", encoding="utf-8")
        original_is_symlink = Path.is_symlink

        def marked_link(path: Path) -> bool:
            return path.name == linked.name or original_is_symlink(path)

        with patch(
            "pysfmea.repository_inventory.Path.is_symlink",
            autospec=True,
            side_effect=marked_link,
        ):
            linked_inventory = build_repository_inventory(
                linked_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )
        self.assertEqual(linked_inventory["entries"][0]["status"], "opaque")
        self.assertEqual(linked_inventory["entries"][0]["analysis_depth"], "none")

        nonregular_root = self.root / "nonregular-inventory"
        nonregular_root.mkdir()
        (nonregular_root / "device.bin").write_bytes(b"not-opened")
        with patch("pysfmea.repository_inventory.stat.S_ISREG", return_value=False):
            nonregular = build_repository_inventory(
                nonregular_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )
        self.assertEqual(nonregular["entries"][0]["status"], "opaque")
        self.assertEqual(nonregular["entries"][0]["analysis_depth"], "none")
        self.assertEqual(
            nonregular["entries"][0]["reason"],
            "Non-regular repository artifact is not opened or hashed.",
        )

        region_root = self.root / "region-inventory"
        region_root.mkdir()
        (region_root / ".a").mkdir()
        (region_root / ".b").mkdir()
        with patch("pysfmea.repository_inventory.MAX_REGIONS", 1):
            region_limited = build_repository_inventory(
                region_root,
                selected_python_paths=set(),
                parsed_python_paths=set(),
                include_tests=False,
            )
        self.assertTrue(region_limited["truncated"])
        self.assertTrue(
            any(
                "1 regions" in region["reason"]
                for region in region_limited["regions"]
            )
        )

    def test_exclude_private(self) -> None:
        analysis = scan_repository(self.root, include_private=False)
        self.assertNotIn("_private_helper", {entry["qualname"] for entry in analysis["components"]})

    def test_python_symlink_outside_repository_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as external_temp:
            external = Path(external_temp) / "external.py"
            external.write_text("def outside_secret():\n    return True\n", encoding="utf-8")
            link = self.root / "linked.py"
            try:
                os.symlink(external, link)
            except OSError as exc:
                self.skipTest(f"file symlinks unavailable: {exc}")
            analysis = scan_repository(self.root)
        self.assertNotIn(
            "outside_secret", {component["qualname"] for component in analysis["components"]}
        )
        self.assertTrue(
            any(warning["type"] == "OutsideRepository" for warning in analysis["warnings"])
        )

    def test_python_source_and_test_evidence_ingestion_is_bounded_and_encoded(self) -> None:
        (self.root / "encoded.py").write_bytes(
            b"# -*- coding: latin-1 -*-\ndef encoded():\n    return 'caf\xe9'\n"
        )
        (self.root / "oversized.py").write_text(
            "def oversized():\n    return True\n" + ("#" * 2_000),
            encoding="utf-8",
        )
        (self.root / "invalid_encoding.py").write_bytes(
            b"# coding: unavailable-codec\ndef invalid_encoding():\n    return True\n"
        )
        (self.root / "tests" / "test_oversized.py").write_text(
            "calculate_total\n" + ("#" * 2_000),
            encoding="utf-8",
        )

        with patch("pysfmea.scanner.MAX_PYTHON_SOURCE_BYTES", 1_024):
            analysis = scan_repository(self.root)

        components = {component["qualname"]: component for component in analysis["components"]}
        self.assertIn("encoded", components)
        self.assertNotIn("oversized", components)
        self.assertNotIn("invalid_encoding", components)
        self.assertNotIn(
            "tests/test_oversized.py",
            components["calculate_total"]["test_references"],
        )
        warnings = {
            (warning["path"], warning["type"]): warning["message"]
            for warning in analysis["warnings"]
        }
        self.assertEqual(
            warnings[("oversized.py", "PythonSourceError")],
            "Python source exceeds the 1024-byte analysis limit",
        )
        self.assertEqual(
            warnings[("invalid_encoding.py", "PythonSourceError")],
            "Python source has an invalid or unsupported encoding",
        )
        self.assertEqual(
            warnings[("tests/test_oversized.py", "TestEvidenceError")],
            "Python source exceeds the 1024-byte analysis limit",
        )
        inventory = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(inventory["oversized.py"]["status"], "unresolved")
        self.assertEqual(inventory["invalid_encoding.py"]["status"], "unresolved")

    def test_python_source_snapshot_is_identity_stable_reused_and_manifest_bound(
        self,
    ) -> None:
        snapshot_root = self.root / "source-snapshot"
        snapshot_root.mkdir()
        tests_root = snapshot_root / "tests"
        tests_root.mkdir()
        app = snapshot_root / "app.py"
        test_app = tests_root / "test_app.py"
        app.write_text("def calculate(value):\n    return value * 2\n", encoding="utf-8")
        test_app.write_text(
            "from app import calculate\n\ndef test_calculate():\n"
            "    assert calculate(2) == 4\n",
            encoding="utf-8",
        )

        with patch(
            "pysfmea.scanner._read_python_source_bytes_bounded",
            wraps=_read_python_source_bytes_bounded,
        ) as bounded_reader, patch(
            "pysfmea.repository_inventory.load_bounded_file_snapshot",
            wraps=load_bounded_file_snapshot,
        ) as inventory_reader:
            analysis = scan_repository(snapshot_root, include_tests=True)

        self.assertEqual(bounded_reader.call_count, 2)
        self.assertEqual(inventory_reader.call_count, 0)
        baseline = analysis["project"]["baseline"]
        self.assertEqual(baseline["source_snapshot_files"], 2)
        self.assertEqual(
            baseline["source_snapshot_bytes"],
            len(app.read_bytes()) + len(test_app.read_bytes()),
        )
        self.assertEqual(baseline["source_snapshot_rejected_files"], 0)
        records = [
            {
                "path": path.relative_to(snapshot_root).as_posix(),
                "status": "accepted",
                "bytes": len(path.read_bytes()),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in (app, test_app)
        ]
        expected_snapshot_digest = hashlib.sha256(
            json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(baseline["source_snapshot_sha256"], expected_snapshot_digest)
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"]["source_snapshot_sha256"],
            expected_snapshot_digest,
        )
        parser_run = next(
            run
            for run in analysis["adapter_runs"]["runs"]
            if run["adapter_id"] == "python.ast_parser"
        )
        self.assertEqual(parser_run["adapter_version"], "2")
        inventory_entries = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        for path in (app, test_app):
            relative = path.relative_to(snapshot_root).as_posix()
            self.assertEqual(
                inventory_entries[relative]["sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                inventory_entries[relative]["snapshot_source"],
                "analysis_source_snapshot",
            )

        race_root = self.root / "source-race"
        race_root.mkdir()
        changing = race_root / "changing.py"
        changing.write_text("def changing():\n    return True\n", encoding="utf-8")
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            raced = scan_repository(race_root)
        self.assertEqual(raced["components"], [])
        raced_baseline = raced["project"]["baseline"]
        self.assertEqual(raced_baseline["source_snapshot_files"], 0)
        self.assertEqual(raced_baseline["source_snapshot_rejected_files"], 1)
        self.assertEqual(
            raced["run_manifest"]["resolved_inputs"]["source_snapshot_sha256"],
            raced_baseline["source_snapshot_sha256"],
        )
        self.assertTrue(
            any(
                warning["path"] == changing.name
                and warning["type"] == "PythonSourceError"
                and "changed during bounded consumption" in warning["message"]
                for warning in raced["warnings"]
            )
        )

    def test_python_source_internal_link_is_rejected_consistently(self) -> None:
        linked = self.root / "linked.py"
        linked.write_text("def linked_alias():\n    return True\n", encoding="utf-8")
        original_is_symlink = Path.is_symlink

        def marked_link(path: Path) -> bool:
            return path.name == linked.name or original_is_symlink(path)

        with patch("pysfmea.scanner.Path.is_symlink", autospec=True, side_effect=marked_link):
            analysis = scan_repository(self.root)

        self.assertNotIn(
            "linked_alias", {component["qualname"] for component in analysis["components"]}
        )
        self.assertTrue(
            any(
                warning["path"] == "linked.py"
                and warning["type"] == "PythonSourceBoundary"
                and "regular non-symbolic-link" in warning["message"]
                for warning in analysis["warnings"]
            )
        )
        inventory = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(inventory["linked.py"]["status"], "opaque")

    def test_test_evidence_index_has_aggregate_file_and_byte_limits(self) -> None:
        extra_test = self.root / "tests" / "test_extra.py"
        extra_test.write_text(
            "from app import fetch_configuration\n\n"
            "def test_fetch():\n    assert fetch_configuration\n",
            encoding="utf-8",
        )

        with patch("pysfmea.scanner.MAX_TEST_EVIDENCE_FILES", 1):
            file_limited = scan_repository(self.root)
        self.assertTrue(
            any(
                warning["type"] == "TestEvidenceLimit"
                and warning["message"] == "Test evidence indexing reached the 1-file limit"
                for warning in file_limited["warnings"]
            )
        )
        fetch = next(
            component
            for component in file_limited["components"]
            if component["qualname"] == "fetch_configuration"
        )
        self.assertNotIn("tests/test_extra.py", fetch["test_references"])
        self.assertEqual(
            file_limited["project"]["baseline"][
                "test_evidence_snapshot_rejected_files"
            ],
            1,
        )

        with patch("pysfmea.scanner.MAX_TEST_EVIDENCE_BYTES", 10):
            byte_limited = scan_repository(self.root)
        self.assertTrue(
            any(
                warning["type"] == "TestEvidenceLimit"
                and warning["message"]
                == "Test evidence indexing exceeds the 10-byte aggregate limit"
                for warning in byte_limited["warnings"]
            )
        )
        calculate = next(
            component
            for component in byte_limited["components"]
            if component["qualname"] == "calculate_total"
        )
        self.assertEqual(calculate["test_references"], [])
        self.assertEqual(
            byte_limited["project"]["baseline"]["test_evidence_snapshot_files"],
            0,
        )
        self.assertEqual(
            byte_limited["project"]["baseline"][
                "test_evidence_snapshot_rejected_files"
            ],
            1,
        )

    def test_test_evidence_is_single_snapshot_scoped_and_manifest_bound(self) -> None:
        evidence_root = self.root / "test-evidence-snapshot"
        evidence_root.mkdir()
        tests_root = evidence_root / "tests"
        tests_root.mkdir()
        app = evidence_root / "app.py"
        test_app = tests_root / "test_app.py"
        excluded_test = tests_root / "excluded_test.py"
        app.write_text("def calculate(value):\n    return value * 2\n", encoding="utf-8")
        accepted_raw = (
            b"from app import calculate\n\ndef test_calculate():\n"
            b"    assert calculate(2) == 4\n"
        )
        test_app.write_bytes(accepted_raw)
        excluded_test.write_text(
            "from app import calculate\n\ndef test_excluded():\n    assert calculate\n",
            encoding="utf-8",
        )

        def replace_after_test_index(*args, **kwargs):
            test_app.write_text(
                "def test_replacement():\n    assert False\n", encoding="utf-8"
            )
            return build_repository_inventory(*args, **kwargs)

        with patch(
            "pysfmea.scanner._read_python_source_bytes_bounded",
            wraps=_read_python_source_bytes_bounded,
        ) as bounded_reader, patch(
            "pysfmea.repository_inventory.load_bounded_file_snapshot",
            wraps=load_bounded_file_snapshot,
        ) as inventory_reader, patch(
            "pysfmea.scanner.build_repository_inventory",
            side_effect=replace_after_test_index,
        ):
            analysis = scan_repository(
                evidence_root,
                config={"scan": {"exclude": ["tests/excluded_test.py"]}},
            )

        self.assertEqual(bounded_reader.call_count, 2)
        self.assertEqual(inventory_reader.call_count, 1)
        self.assertEqual(inventory_reader.call_args.args[0], excluded_test)
        component = next(
            value
            for value in analysis["components"]
            if value["qualname"] == "calculate"
        )
        self.assertEqual(component["test_references"], ["tests/test_app.py"])
        inventory = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(
            inventory["tests/test_app.py"]["sha256"],
            hashlib.sha256(accepted_raw).hexdigest(),
        )
        self.assertEqual(
            inventory["tests/test_app.py"]["snapshot_source"],
            "test_evidence_snapshot",
        )
        self.assertEqual(inventory["tests/excluded_test.py"]["status"], "excluded_region")
        baseline = analysis["project"]["baseline"]
        record = [
            {
                "path": "tests/test_app.py",
                "status": "accepted",
                "bytes": len(accepted_raw),
                "sha256": hashlib.sha256(accepted_raw).hexdigest(),
            }
        ]
        expected_digest = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(baseline["test_evidence_snapshot_files"], 1)
        self.assertEqual(baseline["test_evidence_snapshot_bytes"], len(accepted_raw))
        self.assertEqual(baseline["test_evidence_snapshot_rejected_files"], 0)
        self.assertEqual(baseline["test_evidence_snapshot_sha256"], expected_digest)
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"][
                "test_evidence_snapshot_sha256"
            ],
            expected_digest,
        )
        discoverer_run = next(
            run
            for run in analysis["adapter_runs"]["runs"]
            if run["adapter_id"] == "python.repository_discoverer"
        )
        self.assertEqual(discoverer_run["adapter_version"], "6")

        race_root = self.root / "test-evidence-race"
        race_root.mkdir()
        race_tests = race_root / "tests"
        race_tests.mkdir()
        (race_root / "app.py").write_text(
            "def calculate(value):\n    return value * 2\n", encoding="utf-8"
        )
        changing_test = race_tests / "test_app.py"
        changing_test.write_bytes(accepted_raw)
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_sequence(True, True, True, False),
        ):
            raced = scan_repository(race_root)
        raced_component = next(
            value
            for value in raced["components"]
            if value["qualname"] == "calculate"
        )
        self.assertEqual(raced_component["test_references"], [])
        raced_baseline = raced["project"]["baseline"]
        self.assertEqual(raced_baseline["test_evidence_snapshot_files"], 0)
        self.assertEqual(raced_baseline["test_evidence_snapshot_rejected_files"], 1)
        self.assertEqual(
            raced["run_manifest"]["resolved_inputs"][
                "test_evidence_snapshot_sha256"
            ],
            raced_baseline["test_evidence_snapshot_sha256"],
        )
        self.assertTrue(
            any(
                warning["path"] == "tests/test_app.py"
                and warning["type"] == "TestEvidenceError"
                and "changed during bounded consumption" in warning["message"]
                for warning in raced["warnings"]
            )
        )

    def test_constructor_and_module_initialization_are_analyzed(self) -> None:
        (self.root / "startup.py").write_text(
            "import os\nCONFIG = os.getenv('MODE')\n\n"
            "class Controller:\n"
            "    def __init__(self, device):\n"
            "        self.device = device\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        components = {component["qualname"]: component for component in analysis["components"]}
        self.assertIn("<module initialization>", components)
        self.assertIn("Controller.__init__", components)
        self.assertIn("configuration", components["<module initialization>"]["signals"])

    def test_declarative_data_models_are_analysis_components(self) -> None:
        (self.root / "models.py").write_text(
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class Command:\n"
            "    target: str\n"
            "    amount: float\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        component = next(
            component for component in analysis["components"] if component["qualname"] == "Command"
        )
        self.assertEqual(component["kind"], "class_model")
        self.assertEqual(component["parameters"], ["target", "amount"])
        rules = {
            item["scanner"]["rule_id"]
            for item in analysis["items"]
            if item["component"]["qualname"] == "Command"
        }
        self.assertIn("data.model_contract", rules)

    def test_rescan_preserves_review_and_marks_removed(self) -> None:
        first = scan_repository(self.root)
        target = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "calculate_total"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(
            first,
            target["id"],
            {
                "disposition": "accepted",
                "end_effect": "Customer is charged the wrong amount.",
                "severity": 8,
            },
        )
        manual = add_manual_item(first, target["component_id"])
        (self.root / "app.py").write_text(
            "def replacement(value):\n    return value\n",
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        old = next(item for item in merged["items"] if item["id"] == target["id"])
        manual_after = next(item for item in merged["items"] if item["id"] == manual["id"])
        self.assertEqual(old["source_status"], "removed")
        self.assertEqual(old["review"]["severity"], 8)
        self.assertEqual(old["review"]["disposition"], "accepted")
        self.assertEqual(manual_after["source_status"], "active")

    def test_changed_source_requires_review_revalidation(self) -> None:
        first = scan_repository(self.root)
        first_baseline = first["project"]["baseline"]["id"]
        target = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "calculate_total"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(first, target["id"], {"disposition": "accepted", "severity": 8})
        source = (self.root / "app.py").read_text(encoding="utf-8")
        (self.root / "app.py").write_text(
            source.replace("return value * 2", "return round(value * 2, 2)"),
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        changed = next(item for item in merged["items"] if item["id"] == target["id"])
        self.assertEqual(changed["source_change"], "changed")
        self.assertTrue(changed["review"]["revalidation_required"])
        self.assertEqual(
            changed["review_history"][-1]["event"],
            "source_change_revalidation_required",
        )
        self.assertNotEqual(merged["project"]["baseline"]["id"], first_baseline)
        self.assertEqual(merged["summary"]["revalidation_required"], 1)
        update_item_review(merged, target["id"], {"revalidation_required": False})
        self.assertEqual(
            changed["review"]["validated_fingerprint"],
            changed["scanner"]["source_fingerprint"],
        )
        self.assertEqual(
            changed["review"]["validated_baseline_id"],
            merged["project"]["baseline"]["id"],
        )

    def test_module_context_change_requires_revalidation(self) -> None:
        (self.root / "contextual.py").write_text(
            "FACTOR = 2\n\ndef scale(value):\n    return value * FACTOR\n",
            encoding="utf-8",
        )
        first = scan_repository(self.root)
        target = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "scale"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(first, target["id"], {"disposition": "accepted"})
        (self.root / "contextual.py").write_text(
            "FACTOR = 3\n\ndef scale(value):\n    return value * FACTOR\n",
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        changed = next(item for item in merged["items"] if item["id"] == target["id"])
        self.assertEqual(changed["source_change"], "changed")
        self.assertIn("module or class context changed", changed["change_reasons"])
        self.assertTrue(changed["review"]["revalidation_required"])

    def test_project_hazard_change_requires_revalidation(self) -> None:
        config = {
            "project": {"purpose": "Billing"},
            "hazards": [
                {"id": "HZ-1", "end_effect": "Incorrect charge.", "severity": 8}
            ],
            "component_mappings": [
                {
                    "pattern": "app.py:calculate_total",
                    "subsystem": "Billing",
                    "hazards": ["HZ-1"],
                }
            ],
        }
        first = scan_repository(self.root, config=config)
        target = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "calculate_total"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(first, target["id"], {"disposition": "accepted"})
        config["hazards"][0]["end_effect"] = "Incorrect or duplicate charge."

        merged = merge_rescan(first, scan_repository(self.root, config=config))
        changed = next(item for item in merged["items"] if item["id"] == target["id"])
        self.assertEqual(changed["source_change"], "changed")
        self.assertIn("SFMEA project context changed", changed["change_reasons"])
        self.assertTrue(changed["review"]["revalidation_required"])

    def test_callee_change_transitively_revalidates_reviewed_callers(self) -> None:
        (self.root / "chain.py").write_text(
            "def helper(value):\n    return value + 1\n\n"
            "def caller(value):\n    return helper(value)\n",
            encoding="utf-8",
        )
        first = scan_repository(self.root)
        caller_item = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "caller"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(first, caller_item["id"], {"disposition": "accepted"})
        (self.root / "chain.py").write_text(
            "def helper(value):\n    return value + 2\n\n"
            "def caller(value):\n    return helper(value)\n",
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        caller_after = next(item for item in merged["items"] if item["id"] == caller_item["id"])
        self.assertEqual(caller_after["source_change"], "impacted")
        self.assertTrue(caller_after["review"]["revalidation_required"])
        self.assertTrue(
            any("chain.py:helper" in reason for reason in caller_after["change_reasons"])
        )

    def test_renamed_component_preserves_review_with_traceability(self) -> None:
        first = scan_repository(self.root)
        target = next(
            item
            for item in first["items"]
            if item["component"]["qualname"] == "calculate_total"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        update_item_review(
            first,
            target["id"],
            {"disposition": "accepted", "severity": 8, "reviewer": "Alex"},
        )
        source = (self.root / "app.py").read_text(encoding="utf-8")
        (self.root / "app.py").write_text(
            source.replace("def calculate_total(value):", "def compute_total(value):"),
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        moved = next(
            item
            for item in merged["items"]
            if item["component"]["qualname"] == "compute_total"
            and item["scanner"]["rule_id"] == "functional.incorrect"
        )
        self.assertEqual(moved["source_change"], "moved")
        self.assertIn(target["id"], moved["previous_ids"])
        self.assertEqual(moved["review"]["severity"], 8)
        self.assertTrue(moved["review"]["revalidation_required"])
        self.assertFalse(
            any(
                item["id"] == target["id"] and item["source_status"] == "removed"
                for item in merged["items"]
            )
        )

    def test_project_config_hazards_custom_rules_focus_and_coverage(self) -> None:
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps(
                {
                    "files": {
                        "app.py": {
                            "executed_lines": [7, 8],
                            "missing_lines": [9],
                            "executed_branches": [[8, 9]],
                            "missing_branches": [[8, 10]],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        config = {
            "project": {"name": "Billing", "purpose": "Calculate customer totals"},
            "scan": {
                "focus": ["app.py:calculate_total"],
                "exclude": [],
                "coverage_json": str(coverage),
            },
            "risk": {"method": "sod_rpn"},
            "analysis": {
                "phase": "implementation",
                "revision": "A",
                "ground_rules": ["Analyze worst credible effects."],
            },
            "hazards": [
                {
                    "id": "HZ-PRICE",
                    "description": "Incorrect charge",
                    "end_effect": "Customer is charged incorrectly.",
                    "severity": 8,
                }
            ],
            "critical_functions": [
                {
                    "pattern": "app.py:calculate_total",
                    "rationale": "Financial boundary",
                    "hazards": ["HZ-PRICE"],
                }
            ],
            "requirements": [
                {
                    "id": "REQ-PRICE",
                    "text": "Calculate totals correctly.",
                    "source": "Billing requirements",
                    "hazards": ["HZ-PRICE"],
                }
            ],
            "component_mappings": [
                {
                    "pattern": "app.py:calculate_total",
                    "subsystem": "Billing",
                    "requirements": ["REQ-PRICE"],
                    "hazards": ["HZ-PRICE"],
                }
            ],
            "common_causes": [
                {
                    "id": "CC-CONFIG",
                    "description": "A shared configuration error corrupts billing decisions.",
                    "component_patterns": ["app.py:calculate_total", "app.py:fetch_configuration"],
                    "hazards": ["HZ-PRICE"],
                    "requirements": ["REQ-PRICE"],
                    "causes": ["Shared invalid configuration"],
                    "controls": ["Independent configuration validation"],
                }
            ],
            "custom_rules": [
                {
                    "id": "domain.rounding",
                    "pattern": "app.py:calculate_total",
                    "guideword": "Precision",
                    "failure_mode": "The total is rounded using the wrong policy.",
                    "trigger": "A fractional value is calculated.",
                    "local_effect": "The computed charge differs from policy.",
                    "causes": ["Wrong rounding mode"],
                    "actions": ["Test currency boundary values"],
                }
            ],
        }

        with patch(
            "pysfmea.repository_inventory.load_bounded_file_snapshot",
            wraps=load_bounded_file_snapshot,
        ) as inventory_reader:
            analysis = scan_repository(self.root, config=config)
        self.assertEqual(inventory_reader.call_count, 0)
        self.assertEqual(analysis["project"]["name"], "Billing")
        coverage_raw = coverage.read_bytes()
        coverage_evidence = analysis["project"]["settings"]["coverage_evidence"]
        self.assertEqual(coverage_evidence["bytes"], len(coverage_raw))
        self.assertEqual(
            coverage_evidence["sha256"],
            hashlib.sha256(coverage_raw).hexdigest(),
        )
        self.assertEqual(coverage_evidence["file_records"], 1)
        self.assertEqual(coverage_evidence["accepted_file_records"], 1)
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"]["coverage_json_sha256"],
            coverage_evidence["sha256"],
        )
        coverage_inventory = next(
            entry
            for entry in analysis["repository_inventory"]["entries"]
            if entry["path"] == "coverage.json"
        )
        self.assertEqual(coverage_inventory["sha256"], coverage_evidence["sha256"])
        self.assertEqual(
            coverage_inventory["snapshot_source"], "coverage_evidence_snapshot"
        )
        self.assertEqual(
            analysis["repository_inventory"]["summary"]["by_snapshot_source"][
                "coverage_evidence_snapshot"
            ],
            1,
        )
        code_components = [
            component for component in analysis["components"] if component["kind"] != "common_cause"
        ]
        self.assertEqual([c["qualname"] for c in code_components], ["calculate_total"])
        component = code_components[0]
        self.assertEqual(component["coverage"]["covered_lines"], 2)
        self.assertEqual(component["coverage"]["branch_percent"], 50.0)
        custom = next(
            item for item in analysis["items"] if item["scanner"]["rule_id"] == "domain.rounding"
        )
        self.assertEqual(custom["review"]["linked_hazards"], ["HZ-PRICE"])
        self.assertEqual(custom["review"]["end_effect"], "Customer is charged incorrectly.")
        self.assertEqual(custom["review"]["severity"], 8)
        self.assertEqual(custom["review"]["requirement"], "REQ-PRICE")
        self.assertEqual(custom["component"]["subsystems"], ["Billing"])
        common_cause = next(
            item
            for item in analysis["items"]
            if item["scanner"]["rule_id"] == "common_cause.CC-CONFIG"
        )
        self.assertEqual(common_cause["review"]["linked_hazards"], ["HZ-PRICE"])
        self.assertEqual(common_cause["scanner"]["screening_priority"], "high")
        with self.assertRaisesRegex(ValueError, "unknown linked hazard"):
            update_item_review(analysis, custom["id"], {"linked_hazards": ["HZ-TYPO"]})

    def test_coverage_ingestion_is_bounded_link_safe_and_path_strict(self) -> None:
        coverage = self.root / "adversarial-coverage.json"
        coverage_payload = {
            "files": {
                "../app.py": {
                    "executed_lines": [7, 8, 9],
                    "missing_lines": [],
                },
                "app.py": {
                    "executed_lines": [7, "bad", True],
                    "missing_lines": "not-a-list",
                    "executed_branches": [[7, 8], ["bad", 9]],
                    "missing_branches": [],
                },
                "./app.py": {
                    "executed_lines": [7, 8],
                    "missing_lines": [9],
                },
                "other.py": {
                    "executed_lines": [],
                    "missing_lines": [],
                    "executed_branches": [[7, -1]],
                    "missing_branches": [],
                },
            }
        }
        coverage.write_text(json.dumps(coverage_payload), encoding="utf-8")
        indexed, warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(set(indexed), {"app.py", "other.py"})
        self.assertEqual(indexed["app.py"]["executed_lines"], [7])
        self.assertEqual(indexed["app.py"]["missing_lines"], [])
        self.assertEqual(indexed["other.py"]["executed_branches"], [[7, -1]])
        self.assertEqual(len(warnings), 1)
        self.assertIn("unsafe=1", warnings[0]["message"])
        self.assertIn("malformed=1", warnings[0]["message"])
        self.assertIn("duplicates=1", warnings[0]["message"])

        coverage.write_text('{"files":{},"files":{}}', encoding="utf-8")
        duplicate, duplicate_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(duplicate, {})
        self.assertIn("duplicate object key", duplicate_warnings[0]["message"])

        for non_finite_payload in ('{"files":{},"probe":NaN}', '{"files":{},"probe":1e9999}'):
            coverage.write_text(non_finite_payload, encoding="utf-8")
            non_finite, non_finite_warnings = _load_coverage(
                coverage,
                self.root.resolve(),
            )
            self.assertEqual(non_finite, {})
            self.assertIn("non-finite number", non_finite_warnings[0]["message"])

        coverage.write_text(json.dumps(coverage_payload), encoding="utf-8")
        with patch("pysfmea.scanner.MAX_COVERAGE_JSON_NODES", 2):
            oversized, oversized_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(oversized, {})
        self.assertIn("2-node JSON structure limit", oversized_warnings[0]["message"])

        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=_identity_changes_once(),
        ):
            changed, changed_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(changed, {})
        self.assertIn("changed during bounded consumption", changed_warnings[0]["message"])

        with patch("pysfmea.scanner.MAX_COVERAGE_FILE_RECORDS", 2):
            excessive_files, excessive_file_warnings = _load_coverage(
                coverage,
                self.root.resolve(),
            )
        self.assertEqual(excessive_files, {})
        self.assertIn("2-file record limit", excessive_file_warnings[0]["message"])

        with patch("pysfmea.scanner.MAX_COVERAGE_PATH_CHARS", 3):
            excessive_paths, excessive_path_warnings = _load_coverage(
                coverage,
                self.root.resolve(),
            )
        self.assertEqual(excessive_paths, {})
        self.assertIn("unsafe=4", excessive_path_warnings[0]["message"])

        with patch("pysfmea.scanner.MAX_COVERAGE_JSON_BYTES", 10):
            bounded, bounded_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(bounded, {})
        self.assertIn("10-byte import limit", bounded_warnings[0]["message"])

        coverage.write_bytes(b"\xff\xfe")
        invalid, invalid_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(invalid, {})
        self.assertEqual(
            invalid_warnings[0]["message"],
            "coverage JSON is not valid bounded UTF-8 JSON",
        )
        coverage.write_text("[]", encoding="utf-8")
        scalar, scalar_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(scalar, {})
        self.assertEqual(
            scalar_warnings[0]["message"],
            "coverage JSON root must be an object",
        )
        coverage.write_text("{}", encoding="utf-8")
        missing, missing_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(missing, {})
        self.assertEqual(
            missing_warnings[0]["message"],
            "coverage JSON has no files object",
        )
        coverage.write_text(json.dumps(coverage_payload), encoding="utf-8")
        with patch("pysfmea.json_ingestion.stat.S_ISLNK", return_value=True):
            linked, linked_warnings = _load_coverage(coverage, self.root.resolve())
        self.assertEqual(linked, {})
        self.assertIn("regular non-symbolic-link", linked_warnings[0]["message"])

        analysis = scan_repository(
            self.root,
            config={"scan": {"coverage_json": str(coverage)}},
        )
        self.assertTrue(
            any(
                value.get("type") == "CoverageError"
                and "unsafe=1" in value.get("message", "")
                for value in analysis["warnings"]
            )
        )

    def test_coverage_snapshot_is_reused_and_external_evidence_stays_external(
        self,
    ) -> None:
        coverage_root = self.root / "coverage-snapshot"
        coverage_root.mkdir()
        app = coverage_root / "app.py"
        coverage = coverage_root / "coverage.json"
        app.write_text("def calculate():\n    return 1\n", encoding="utf-8")
        accepted_raw = json.dumps(
            {
                "files": {
                    "app.py": {
                        "executed_lines": [1, 2],
                        "missing_lines": [],
                        "executed_branches": [],
                        "missing_branches": [],
                    }
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        coverage.write_bytes(accepted_raw)

        def replace_before_inventory(*args, **kwargs):
            coverage.write_text('{"files":{}}', encoding="utf-8")
            return build_repository_inventory(*args, **kwargs)

        with patch(
            "pysfmea.repository_inventory.load_bounded_file_snapshot",
            wraps=load_bounded_file_snapshot,
        ) as inventory_reader, patch(
            "pysfmea.scanner.build_repository_inventory",
            side_effect=replace_before_inventory,
        ):
            analysis = scan_repository(coverage_root, coverage_json=coverage)

        self.assertEqual(inventory_reader.call_count, 0)
        component = next(
            value
            for value in analysis["components"]
            if value["qualname"] == "calculate"
        )
        self.assertEqual(component["coverage"]["line_percent"], 100.0)
        evidence = analysis["project"]["settings"]["coverage_evidence"]
        accepted_digest = hashlib.sha256(accepted_raw).hexdigest()
        self.assertEqual(evidence["sha256"], accepted_digest)
        inventory = {
            entry["path"]: entry for entry in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(inventory["coverage.json"]["sha256"], accepted_digest)
        self.assertEqual(
            inventory["coverage.json"]["snapshot_source"],
            "coverage_evidence_snapshot",
        )
        self.assertEqual(
            analysis["run_manifest"]["resolved_inputs"]["coverage_json_sha256"],
            accepted_digest,
        )
        coverage_run = next(
            run
            for run in analysis["adapter_runs"]["runs"]
            if run["adapter_id"] == "coverage.py_json"
        )
        self.assertEqual(coverage_run["adapter_version"], "2")

        with tempfile.TemporaryDirectory() as outside_temp:
            external_coverage = Path(outside_temp) / "coverage.json"
            external_coverage.write_bytes(accepted_raw)
            external = scan_repository(
                coverage_root,
                coverage_json=external_coverage,
            )
        self.assertEqual(
            external["project"]["settings"]["coverage_evidence"]["sha256"],
            accepted_digest,
        )
        self.assertNotIn(
            "coverage_evidence_snapshot",
            external["repository_inventory"]["summary"]["by_snapshot_source"],
        )

    def test_configuration_template_round_trip(self) -> None:
        path = write_config_template(self.root / "sfmea.toml")
        config, resolved = load_config(path)
        self.assertEqual(resolved, path.resolve())
        self.assertEqual(config["risk"]["method"], "severity_only")
        self.assertEqual(config["hazards"][0]["id"], "HZ-001")

    def test_configuration_ingestion_is_bounded_link_safe_and_identity_preserving(
        self,
    ) -> None:
        config_path = self.root / "bounded.toml"
        coverage_link = self.root / "coverage-link.json"
        guidance_link = self.root / "guidance-link.json"
        coverage_link.write_text('{"files": {}}', encoding="utf-8")
        guidance_link.write_text("{}", encoding="utf-8")
        config_path.write_text(
            '[project]\nname = "Bounded configuration"\n'
            '[scan]\ncoverage_json = "coverage-link.json"\n'
            '[analysis]\nguidance_packs = ["guidance-link.json"]\n',
            encoding="utf-8",
        )
        original_resolve = Path.resolve
        redirected = self.root / "resolved-target.json"

        def redirect_inputs(path: Path, strict: bool = False) -> Path:
            if path.name in {coverage_link.name, guidance_link.name}:
                return redirected
            return original_resolve(path, strict=strict)

        with patch(
            "pysfmea.config.Path.resolve",
            autospec=True,
            side_effect=redirect_inputs,
        ):
            config, resolved = load_config(config_path)
        self.assertEqual(resolved, config_path.resolve())
        self.assertEqual(
            config["scan"]["coverage_json"],
            os.path.abspath(coverage_link),
        )
        self.assertEqual(
            config["analysis"]["guidance_packs"],
            [os.path.abspath(guidance_link)],
        )
        self.assertNotEqual(config["scan"]["coverage_json"], str(redirected))
        self.assertNotEqual(config["analysis"]["guidance_packs"][0], str(redirected))

        with patch("pysfmea.config.MAX_CONFIG_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "10-byte import limit"):
                load_config(config_path)

        with patch("pysfmea.config.os.path.samestat", return_value=False):
            with self.assertRaisesRegex(ValueError, "changed during safe open"):
                load_config(config_path)

        config_path.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 TOML"):
            load_config(config_path)
        config_path.write_text("[project\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 TOML"):
            load_config(config_path)

        config_directory = self.root / "config-directory"
        config_directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            load_config(config_directory)
        with self.assertRaisesRegex(ValueError, "regular file path"):
            write_config_template(config_directory, overwrite=True)

        atomic_destination = self.root / "atomic.toml"
        atomic_destination.write_text("prior-content\n", encoding="utf-8")
        with patch(
            "pysfmea.config.os.replace",
            side_effect=OSError("injected publication failure"),
        ):
            with self.assertRaisesRegex(ValueError, "could not be published safely"):
                write_config_template(atomic_destination, overwrite=True)
        self.assertEqual(
            atomic_destination.read_text(encoding="utf-8"),
            "prior-content\n",
        )
        self.assertEqual(
            list(self.root.glob(f".{atomic_destination.name}.*.tmp")),
            [],
        )

        config_path.write_text('[project]\nname = "Linked"\n', encoding="utf-8")
        original_is_symlink = Path.is_symlink

        def marked_link(path: Path) -> bool:
            return path.name == config_path.name or original_is_symlink(path)

        with patch(
            "pysfmea.config.Path.is_symlink",
            autospec=True,
            side_effect=marked_link,
        ):
            with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
                load_config(config_path)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                write_config_template(config_path, overwrite=True)

    def test_reserved_custom_rule_id_is_rejected(self) -> None:
        path = self.root / "invalid.toml"
        path.write_text(
            "[[custom_rules]]\n"
            'id = "functional.omission"\n'
            'pattern = "*.py:*"\n'
            'guideword = "Duplicate"\n'
            'failure_mode = "Duplicate built-in rule."\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "reserved"):
            load_config(path)

    def test_programmatic_configuration_is_normalized_and_validated(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown configuration section"):
            scan_repository(self.root, config={"projet": {"name": "typo"}})
        analysis = scan_repository(
            self.root,
            config={
                "custom_rules": [
                    {
                        "id": "domain.privacy",
                        "failure_class": "privacy",
                        "pattern": "*.py:*",
                        "guideword": "Disclosure",
                        "failure_mode": "Sensitive information crosses a privacy boundary.",
                    }
                ]
            },
        )
        custom = [
            item
            for item in analysis["items"]
            if item["scanner"]["rule_id"] == "domain.privacy"
        ]
        self.assertTrue(custom)
        self.assertTrue(all(item["scanner"]["failure_class"] == "privacy" for item in custom))
        with self.assertRaisesRegex(ValueError, "unknown failure classes"):
            scan_repository(
                self.root,
                config={"analysis": {"included_failure_classes": ["functonal"]}},
            )

    def test_unknown_configuration_sections_and_fields_are_rejected(self) -> None:
        path = self.root / "invalid.toml"
        path.write_text("[projet]\nname = 'typo'\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown configuration section"):
            load_config(path)

        path.write_text("[project]\nname = 'demo'\npurpoze = 'typo'\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, r"unknown \[project\] field"):
            load_config(path)

        path.write_text(
            "[[custom_rules]]\nid = 'domain.test'\npattern = '*.py:*'\n"
            "guideword = 'Test'\nfailure_mode = 'Test failure.'\ntriger = 'typo'\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, r"unknown \[\[custom_rules\]\] field"):
            load_config(path)

    def test_nested_functions_are_included_by_default_and_can_be_excluded(self) -> None:
        (self.root / "nested.py").write_text(
            "def outer(value):\n"
            "    def transform(item):\n"
            "        return item * 2\n"
            "    return transform(value)\n",
            encoding="utf-8",
        )
        included = scan_repository(self.root)
        self.assertIn(
            "outer.transform", {component["qualname"] for component in included["components"]}
        )
        excluded = scan_repository(self.root, include_nested=False)
        self.assertNotIn(
            "outer.transform", {component["qualname"] for component in excluded["components"]}
        )

    def test_named_lambdas_are_analyzed(self) -> None:
        (self.root / "lambda_code.py").write_text(
            "normalize = lambda value: value / 100\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        component = next(
            component
            for component in analysis["components"]
            if component["qualname"] == "normalize"
        )
        self.assertEqual(component["kind"], "lambda")
        self.assertIn("calculation", component["signals"])

    def test_exports(self) -> None:
        analysis = scan_repository(self.root)
        item = analysis["items"][0]
        update_item_review(
            analysis,
            item["id"],
            {
                "post_action_severity": 7,
                "post_action_occurrence": 2,
                "post_action_detection": 3,
            },
        )
        self.assertEqual(calculate_rpn(item, post_action=True), 42)
        csv_path = export_csv(analysis, self.root / "analysis.csv")
        md_path = export_markdown(analysis, self.root / "analysis.md")
        audit_path = export_audit(analysis, self.root / "analysis.audit.csv")
        inventory_path = export_inventory(analysis, self.root / "analysis.inventory.md")
        csv_text = csv_path.read_text(encoding="utf-8-sig")
        self.assertIn("post_action_rpn", csv_text.splitlines()[0])
        self.assertIn(",42,", csv_text)
        self.assertIn("# Software FMEA", md_path.read_text(encoding="utf-8"))
        self.assertIn("review_update", audit_path.read_text(encoding="utf-8-sig"))
        inventory_text = inventory_path.read_text(encoding="utf-8")
        self.assertIn("## Repository artifact accounting", inventory_text)
        self.assertIn("- Reconciliation: reconciled", inventory_text)
        self.assertIn("## Components", inventory_text)

    def test_csv_exports_neutralize_spreadsheet_formulas(self) -> None:
        analysis = scan_repository(self.root)
        item = analysis["items"][0]
        update_item_review(
            analysis,
            item["id"],
            {
                "notes": "=HYPERLINK(\"https://invalid.example\",\"click\")",
                "reviewer": "@reviewer",
            },
        )
        csv_path = export_csv(analysis, self.root / "analysis.csv")
        audit_path = export_audit(analysis, self.root / "analysis.audit.csv")
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            row = next(csv.DictReader(handle))
        self.assertTrue(row["notes"].startswith("'="))
        with audit_path.open(encoding="utf-8-sig", newline="") as handle:
            audit_rows = list(csv.DictReader(handle))
        reviewer_rows = [row for row in audit_rows if row["reviewer"]]
        self.assertTrue(reviewer_rows)
        self.assertTrue(all(row["reviewer"].startswith("'@") for row in reviewer_rows))

    def test_architecture_boundary_ids_and_labels_are_collision_safe(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "system_interfaces": [
                    {
                        "id": "IF-1",
                        "source": "A-B",
                        "target": "A B",
                        "description": "first",
                    },
                    {
                        "id": "IF-2",
                        "source": "Line\n`source`",
                        "target": "Target",
                        "description": "second",
                    },
                ]
            },
        )
        graph = architecture_graph(analysis)
        boundary_nodes = [node for node in graph["nodes"] if node["kind"] == "system_boundary"]
        self.assertEqual(len(boundary_nodes), 4)
        self.assertEqual(len({node["id"] for node in boundary_nodes}), 4)
        text = export_architecture(analysis, self.root / "architecture.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Line\\n'source'", text)

    def test_markdown_exports_escape_user_authored_html(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "project": {
                    "name": "<script>alert(1)</script>",
                    "purpose": "<img src=x onerror=alert(1)>",
                },
                "analysis": {"ground_rules": ["Do not trust <raw HTML>."]},
            },
        )
        worksheet = export_markdown(analysis, self.root / "analysis.md").read_text(
            encoding="utf-8"
        )
        inventory = export_inventory(analysis, self.root / "inventory.md").read_text(
            encoding="utf-8"
        )
        architecture = export_architecture(
            analysis, self.root / "architecture.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("<script>", worksheet)
        self.assertIn("&lt;script&gt;", worksheet)
        self.assertIn("&lt;img", inventory)
        self.assertIn("&lt;raw HTML&gt;", architecture)

    def test_functional_architecture_graph_and_export(self) -> None:
        (self.root / "flow.py").write_text(
            "from app import calculate_total\n\ndef checkout(value):\n    return calculate_total(value)\n",
            encoding="utf-8",
        )
        analysis = scan_repository(
            self.root,
            config={
                "analysis": {"phase": "implementation", "ground_rules": ["Trace calls."]},
                "system_interfaces": [
                    {
                        "id": "IF-USER",
                        "source": "User",
                        "target": "Application",
                        "description": "Checkout request",
                    }
                ],
            },
        )
        graph = architecture_graph(analysis)
        self.assertTrue(any(edge["kind"] == "internal_call" for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] == "system_interface" for edge in graph["edges"]))
        calculate = next(
            component for component in analysis["components"] if component["qualname"] == "calculate_total"
        )
        self.assertTrue(
            any(path[0] == "flow.py:checkout" for path in calculate["upstream_paths"])
        )
        path = export_architecture(analysis, self.root / "architecture.md")
        text = path.read_text(encoding="utf-8")
        self.assertIn("```mermaid", text)
        self.assertIn("IF-USER", text)

    def test_cyclic_call_graph_is_bounded(self) -> None:
        (self.root / "cycle.py").write_text(
            "def first(value):\n    return second(value)\n\n"
            "def second(value):\n    return first(value)\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        first = next(
            component for component in analysis["components"] if component["qualname"] == "first"
        )
        self.assertTrue(first["upstream_paths"])
        self.assertLessEqual(max(len(path) for path in first["upstream_paths"]), 7)

    def test_caller_path_inventory_discloses_path_and_depth_limits(self) -> None:
        fanout = ["def target(value):\n    return value"]
        fanout.extend(
            f"def caller_{index:02d}(value):\n    return target(value)"
            for index in range(30)
        )
        chain = [
            f"def chain_{index}(value):\n    return chain_{index + 1}(value)"
            for index in range(8)
        ]
        chain.append("def chain_8(value):\n    return value")
        (self.root / "bounded_calls.py").write_text(
            "\n\n".join([*fanout, *chain]) + "\n", encoding="utf-8"
        )

        analysis = scan_repository(self.root)
        components = {
            value["qualname"]: value for value in analysis["components"]
        }
        target = components["target"]
        deepest = components["chain_8"]

        self.assertEqual(len(target["upstream_paths"]), 25)
        self.assertTrue(target["upstream_path_analysis"]["path_limit_truncated"])
        self.assertFalse(
            target["upstream_path_analysis"]["complete_within_static_call_model"]
        )
        self.assertGreater(
            deepest["upstream_path_analysis"]["depth_limited_paths"], 0
        )
        self.assertFalse(
            deepest["upstream_path_analysis"]["complete_within_static_call_model"]
        )
        target_item = next(
            value for value in analysis["items"] if value["component_id"] == target["id"]
        )
        self.assertEqual(
            target_item["scanner"]["upstream_path_analysis"],
            target["upstream_path_analysis"],
        )
        obligation = next(
            value
            for value in analysis["assurance"]["obligations"]
            if value["finding_id"] == target_item["id"]
        )
        self.assertFalse(
            obligation["cascade_context"]["static_path_analysis"][
                "complete_within_static_call_model"
            ]
        )
        self.assertTrue(
            any("caller-path inventory is bounded" in gap for gap in obligation["planning_gaps"])
        )
        self.assertTrue(
            any(
                "compensating runtime" in criterion
                for criterion in obligation["acceptance_criteria"]
            )
        )

    def test_analysis_is_json_serializable(self) -> None:
        analysis = scan_repository(self.root)
        json.dumps(analysis)
        self.assertEqual(analysis["generator"]["name"], "PySFMEA")
        self.assertEqual(
            analysis["generator"]["analysis_schema_version"],
            analysis["schema_version"],
        )


if __name__ == "__main__":
    unittest.main()

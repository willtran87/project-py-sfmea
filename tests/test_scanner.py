from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.architecture import architecture_graph, export_architecture
from pysfmea.config import load_config, write_config_template
from pysfmea.discovery import evidence_packets
from pysfmea.model import calculate_rpn
from pysfmea.report import export_audit, export_csv, export_inventory, export_markdown
from pysfmea.scanner import scan_repository
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
        update_item_review(first, environment["id"], {"disposition": "accepted"})
        (self.root / "requirements.txt").write_text(
            "requests==2.33.0\ncritical-lib>=1.0\n",
            encoding="utf-8",
        )

        merged = merge_rescan(first, scan_repository(self.root))
        updated = next(item for item in merged["items"] if item["id"] == environment["id"])
        self.assertEqual(updated["source_change"], "changed")
        self.assertTrue(updated["review"]["revalidation_required"])

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

        analysis = scan_repository(self.root, config=config)
        self.assertEqual(analysis["project"]["name"], "Billing")
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

    def test_configuration_template_round_trip(self) -> None:
        path = write_config_template(self.root / "sfmea.toml")
        config, resolved = load_config(path)
        self.assertEqual(resolved, path.resolve())
        self.assertEqual(config["risk"]["method"], "severity_only")
        self.assertEqual(config["hazards"][0]["id"], "HZ-001")

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
        self.assertIn("## Components", inventory_path.read_text(encoding="utf-8"))

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

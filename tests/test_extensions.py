from __future__ import annotations

import contextlib
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.discovery import (
    OpenAICompatibleProvider,
    deterministic_summary,
    discover_suggestions,
    evidence_packets,
    evaluate_candidates,
    review_suggestion,
)
from pysfmea.cli import main
from pysfmea.report import (
    export_review_archive,
    export_review_package,
    verify_review_package,
)
from pysfmea.readiness import repository_readiness
from pysfmea.config import write_config_template
from pysfmea.runtime import import_runtime_trace
from pysfmea.scanner import scan_repository
from pysfmea.signing import sign_review_package, verify_review_signature
from pysfmea.store import load_analysis, merge_rescan, save_analysis
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
        self.assertIn(
            "SFMEA analysis coverage",
            export_coverage(self.analysis, self.root / "coverage.md").read_text(
                encoding="utf-8"
            ),
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

    def test_review_package_is_complete_and_manifested(self) -> None:
        destination = self.root / "review-package"
        result = export_review_package(
            self.analysis,
            destination,
            source_analysis=self.root / "analysis.json",
        )
        manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
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

    def test_review_package_verification_rejects_tampering_and_unsafe_content(self) -> None:
        destination = export_review_package(
            self.analysis,
            self.root / "verified-package",
            source_analysis=self.root / "analysis.json",
        )
        verified = verify_review_package(destination)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["checked_files"], 23)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-package", str(destination), "--json"]), 0)

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

        export_review_package(self.analysis, destination, overwrite=True)
        unexpected = destination / "reviewer-notes.txt"
        unexpected.write_text("not manifested\n", encoding="utf-8")
        extra = verify_review_package(destination)
        self.assertIn(
            "package.file_unexpected",
            {value["rule_id"] for value in extra["findings"]},
        )
        unexpected.unlink()

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
        self.assertIn(
            "package.provenance_mismatch",
            {value["rule_id"] for value in provenance["findings"]},
        )

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
        self.assertEqual(verified["checked_files"], 23)
        self.assertEqual(len(verified["archive_sha256"]), 64)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(
                set(bundle.namelist()),
                {
                    "analysis.json",
                    "assurance-register.csv",
                    "assurance-register.json",
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
                    "guidance-traceability.csv",
                    "guidance-traceability.json",
                    "inventory.md",
                    "manifest.json",
                    "README.md",
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

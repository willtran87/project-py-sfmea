from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance import (
    ASSURANCE_WORK_QUEUE_FORMAT,
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    assurance_work_queue,
    export_pytest_scaffold,
    verify_assurance_work_queue,
    verify_pytest_scaffold,
)
from pysfmea.cli import main
from pysfmea.diagrams import (
    DIAGRAM_BUNDLE_SCHEMA,
    DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
    DIAGRAM_SCHEMA,
    MAX_DIAGRAMS,
)
from pysfmea.html_report import HTML_REPORT_VERIFICATION_FORMAT
from pysfmea.integrity import canonical_json_sha256
from pysfmea.publication import (
    MAX_PUBLICATION_FAILURE_CATALOG_BYTES,
    PUBLICATION_FAILURE_CATALOG_ALGORITHM,
    PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
    PUBLICATION_FAILURE_CATALOG_FORMAT,
    PUBLICATION_FAILURE_CATALOG_SHA256,
    PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT,
    PUBLICATION_FAILURES,
    export_publication_failure_catalog,
    publication_failure_catalog,
    verify_publication_failure_catalog,
    verify_publication_failure_catalog_file,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import (
    JSON_SCHEMA_DRAFT,
    MAX_SCHEMA_BUNDLE_FILE_BYTES,
    REVIEW_PACKAGE_FORMAT,
    REVIEW_PACKAGE_VERIFICATION_FORMAT,
    SCHEMA_BUNDLE_VERIFICATION_FORMAT,
    SCHEMA_CATALOG_FILENAME,
    SCHEMA_CATALOG_FORMAT,
    SCHEMA_FILENAMES,
    schema_bundle_documents,
    schema_catalog,
    schema_document,
    verify_schema_bundle_documents,
    verify_schema_bundle_path,
)
from pysfmea.signing import SIGNATURE_FORMAT, STATEMENT_FORMAT
from pysfmea.workflow import WORKFLOW_STATUS_FORMAT, workflow_status


class SchemaCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_catalog_is_deterministic_and_content_addressed(self) -> None:
        first = schema_catalog()
        second = schema_catalog()
        self.assertEqual(first, second)
        self.assertEqual(first["format"], SCHEMA_CATALOG_FORMAT)
        self.assertEqual(
            [entry["name"] for entry in first["schemas"]],
            [
                "accessibility-evidence",
                "accessibility-evidence-draft",
                "accessibility-evidence-verification",
                "activation-apply-receipt",
                "activation-records",
                "activation-records-import-receipt",
                "activation-workspace",
                "activation-workspace-verification",
                "assurance-case",
                "assurance-case-verification",
                "assurance-program",
                "assurance-program-report-verification",
                "assurance-program-verification",
                "assurance-scaffold",
                "assurance-scaffold-verification",
                "assurance-test-generation-campaign-plan",
                "assurance-test-generation-campaign-plan-verification",
                "assurance-test-generation-fault-evidence",
                "assurance-test-generation-quality-corpus",
                "assurance-test-generation-quality-corpus-v2",
                "assurance-test-generation-quality-corpus-v3",
                "assurance-test-generation-quality-result",
                "assurance-test-generation-quality-result-v2",
                "assurance-test-generation-quality-result-v3",
                "assurance-test-generation-readiness",
                "assurance-test-proposal",
                "assurance-test-proposal-apply-receipt",
                "assurance-test-proposal-apply-receipt-verification",
                "assurance-test-proposal-stage",
                "assurance-test-proposal-stage-verification",
                "assurance-test-proposal-verification",
                "assurance-work-queue",
                "assurance-work-queue-verification",
                "calibration-comparison",
                "configuration-authoring",
                "configuration-authoring-apply-receipt",
                "configuration-authoring-draft",
                "configuration-authoring-verification",
                "conformance-verification",
                "conformance-workspace",
                "cross-reference",
                "cross-reference-verification",
                "detached-signature",
                "diagram",
                "diagram-bundle",
                "diagram-bundle-verification",
                "enhancement-scope-preview",
                "enhancement-workbench",
                "enhancement-workbench-verification",
                "evaluation-result",
                "evidence-onboarding-receipt",
                "evidence-onboarding-receipt-verification",
                "evidence-preflight",
                "fault-injection-plan",
                "fault-injection-plan-verification",
                "golden-corpus",
                "html-report-verification",
                "json-evidence-signature",
                "json-evidence-signature-verification",
                "plugin-manifest",
                "plugin-request",
                "plugin-response",
                "plugin-run",
                "plugin-run-verification",
                "publication-failure-catalog",
                "publication-failure-catalog-verification",
                "pull-request-analysis",
                "pull-request-analysis-verification",
                "qualification-campaign-manifest",
                "qualification-campaign-result",
                "qualification-campaign-verification",
                "qualification-report-verification",
                "report-browser-quality",
                "report-browser-quality-verification",
                "review-package-manifest",
                "review-package-verification",
                "schema-bundle-verification",
                "schema-catalog",
                "sfta-authoring",
                "sfta-authoring-apply-receipt",
                "sfta-authoring-draft",
                "sfta-authoring-verification",
                "slsa-provenance",
                "slsa-provenance-verification",
                "standards-catalog",
                "synthesis-apply-receipt",
                "synthesis-apply-receipt-verification",
                "synthesis-workspace",
                "synthesis-workspace-draft",
                "synthesis-workspace-verification",
                "workflow-status",
            ],
        )
        for entry in first["schemas"]:
            document = schema_document(entry["name"])
            Draft202012Validator.check_schema(document)
            self.assertEqual(document["$schema"], JSON_SCHEMA_DRAFT)
            self.assertEqual(document["$id"], entry["schema_id"])
            self.assertEqual(entry["filename"], SCHEMA_FILENAMES[entry["name"]])
            self.assertEqual(canonical_json_sha256(document), entry["sha256"])
        Draft202012Validator(schema_document("schema-catalog")).validate(first)

    def test_assurance_scaffold_and_verdict_are_publicly_schema_backed(self) -> None:
        (self.root / "subject.py").write_text(
            "def calculate(value: int) -> float:\n    return 10 / value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "assurance-tests",
            disposition="all",
            limit=2,
        )
        manifest = json.loads(
            (scaffold / "assurance-manifest.json").read_text(encoding="utf-8")
        )
        verdict = verify_pytest_scaffold(analysis, scaffold)
        Draft202012Validator(schema_document("assurance-scaffold")).validate(manifest)
        Draft202012Validator(
            schema_document("assurance-scaffold-verification")
        ).validate(verdict)

    def test_publication_failure_catalog_is_discoverable_and_schema_backed(
        self,
    ) -> None:
        catalog = publication_failure_catalog()
        self.assertEqual(catalog["format"], PUBLICATION_FAILURE_CATALOG_FORMAT)
        self.assertEqual(catalog["algorithm"], PUBLICATION_FAILURE_CATALOG_ALGORITHM)
        self.assertEqual(
            catalog["canonicalization"],
            PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
        )
        self.assertEqual(catalog["content_sha256"], PUBLICATION_FAILURE_CATALOG_SHA256)
        catalog_content = dict(catalog)
        catalog_content.pop("content_sha256")
        self.assertEqual(
            canonical_json_sha256(catalog_content),
            catalog["content_sha256"],
        )
        self.assertEqual(len(catalog["failures"]), len(PUBLICATION_FAILURES))
        Draft202012Validator(schema_document("publication-failure-catalog")).validate(
            catalog
        )
        catalog_validator = Draft202012Validator(
            schema_document("publication-failure-catalog")
        )
        changed_notice = dict(catalog)
        changed_notice["notice"] = f"{catalog['notice']} altered"
        self.assertTrue(list(catalog_validator.iter_errors(changed_notice)))
        changed_digest = dict(catalog)
        changed_digest["content_sha256"] = "0" * 64
        self.assertTrue(list(catalog_validator.iter_errors(changed_digest)))
        changed_algorithm = dict(catalog)
        changed_algorithm["algorithm"] = "sha1"
        self.assertTrue(list(catalog_validator.iter_errors(changed_algorithm)))
        changed_canonicalization = dict(catalog)
        changed_canonicalization["canonicalization"] = "unspecified"
        self.assertTrue(list(catalog_validator.iter_errors(changed_canonicalization)))
        self.assertEqual(
            schema_document("review-package-verification")[
                "x-pysfmea-publication-failure-catalog"
            ],
            catalog,
        )

        with contextlib.redirect_stdout(io.StringIO()) as human_output:
            self.assertEqual(main(["publication-catalog"]), 0)
        human = human_output.getvalue()
        self.assertIn("analysis_missing", human)
        self.assertIn("provide_analysis", human)
        self.assertIn(PUBLICATION_FAILURE_CATALOG_SHA256, human)

        with contextlib.redirect_stdout(io.StringIO()) as json_output:
            self.assertEqual(main(["publication-catalog", "--json"]), 0)
        machine = json.loads(json_output.getvalue())
        self.assertEqual(machine, catalog)
        Draft202012Validator(schema_document("publication-failure-catalog")).validate(
            machine
        )

        exported_path = self.root / "catalogs" / "publication-catalog.json"
        with contextlib.redirect_stdout(io.StringIO()) as export_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(exported_path),
                    ]
                ),
                0,
            )
        self.assertIn(str(exported_path), export_output.getvalue())
        self.assertEqual(json.loads(exported_path.read_text(encoding="utf-8")), catalog)
        receipt_path = self.root / "catalogs" / "receipt-catalog.json"
        with contextlib.redirect_stdout(io.StringIO()) as receipt_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(receipt_path),
                        "--json",
                    ]
                ),
                0,
            )
        export_receipt = json.loads(receipt_output.getvalue())
        self.assertTrue(export_receipt["valid"])
        self.assertEqual(Path(export_receipt["source"]), receipt_path)
        Draft202012Validator(
            schema_document("publication-failure-catalog-verification")
        ).validate(export_receipt)
        with contextlib.redirect_stderr(io.StringIO()) as exists_error:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(exported_path),
                    ]
                ),
                2,
            )
        self.assertIn("already exists", exists_error.getvalue())

        drifted = dict(catalog)
        drifted["notice"] = "Recognized catalog requiring refresh."
        exported_path.write_text(
            json.dumps(drifted, ensure_ascii=False), encoding="utf-8"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(exported_path),
                        "--force",
                    ]
                ),
                0,
            )
        self.assertEqual(json.loads(exported_path.read_text(encoding="utf-8")), catalog)

        original = exported_path.read_bytes()
        with patch(
            "pysfmea.file_publication.os.replace", side_effect=OSError("blocked")
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "publication-catalog",
                            "--output",
                            str(exported_path),
                            "--force",
                        ]
                    ),
                    2,
                )
        self.assertEqual(exported_path.read_bytes(), original)
        self.assertFalse(
            any(
                path.name.startswith(f".{exported_path.name}.")
                and path.name.endswith(".tmp")
                for path in exported_path.parent.iterdir()
            )
        )

        def verify_then_replace(path: str | Path) -> dict[str, object]:
            verdict = verify_publication_failure_catalog_file(path)
            Path(path).write_text("concurrent owner\n", encoding="utf-8")
            return verdict

        with patch(
            "pysfmea.publication.verify_publication_failure_catalog_file",
            side_effect=verify_then_replace,
        ):
            with self.assertRaisesRegex(ValueError, "changed before staging"):
                export_publication_failure_catalog(exported_path, overwrite=True)
        self.assertEqual(
            exported_path.read_text(encoding="utf-8"), "concurrent owner\n"
        )
        self.assertFalse(any(exported_path.parent.glob(".*.tmp")))

        exported_path.write_bytes(original)

        unrelated_path = self.root / "unrelated.json"
        unrelated = '{"format":"unrelated","keep":true}'
        unrelated_path.write_text(unrelated, encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as unrelated_error:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(unrelated_path),
                        "--force",
                    ]
                ),
                2,
            )
        self.assertIn("not a recognized catalog", unrelated_error.getvalue())
        self.assertEqual(unrelated_path.read_text(encoding="utf-8"), unrelated)
        spoofed_path = self.root / "spoofed-catalog.json"
        spoofed = json.dumps(
            {"format": PUBLICATION_FAILURE_CATALOG_FORMAT, "keep": True}
        )
        spoofed_path.write_text(spoofed, encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as spoofed_error:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--output",
                        str(spoofed_path),
                        "--force",
                    ]
                ),
                2,
            )
        self.assertIn("not a recognized catalog envelope", spoofed_error.getvalue())
        self.assertEqual(spoofed_path.read_text(encoding="utf-8"), spoofed)
        for invalid_args in (
            ["publication-catalog", "--force"],
            [
                "publication-catalog",
                "--verify",
                str(exported_path),
                "--output",
                str(self.root / "conflict.json"),
            ],
        ):
            with self.subTest(invalid_args=invalid_args):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(invalid_args), 2)

        verification_schema = schema_document(
            "publication-failure-catalog-verification"
        )
        verdict = verify_publication_failure_catalog(catalog)
        self.assertEqual(
            verdict["format"], PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT
        )
        self.assertTrue(verdict["valid"])
        self.assertTrue(all(verdict["checks"].values()))
        Draft202012Validator(verification_schema).validate(verdict)
        malformed_phases = json.loads(json.dumps(catalog))
        malformed_phases["failures"][0]["phases"] = [{}]
        malformed_verdict = verify_publication_failure_catalog(malformed_phases)
        self.assertFalse(malformed_verdict["valid"])
        self.assertFalse(malformed_verdict["checks"]["structure"])
        Draft202012Validator(verification_schema).validate(malformed_verdict)

        catalog_path = self.root / "publication-catalog.json"
        catalog_path.write_text(
            json.dumps(catalog, ensure_ascii=False), encoding="utf-8"
        )
        with contextlib.redirect_stdout(io.StringIO()) as verify_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--verify",
                        str(catalog_path),
                        "--json",
                    ]
                ),
                0,
            )
        file_verdict = json.loads(verify_output.getvalue())
        self.assertTrue(file_verdict["valid"])
        Draft202012Validator(verification_schema).validate(file_verdict)

        changed_catalog = dict(catalog)
        changed_catalog["notice"] = "Altered catalog notice."
        catalog_path.write_text(
            json.dumps(changed_catalog, ensure_ascii=False), encoding="utf-8"
        )
        with contextlib.redirect_stdout(io.StringIO()) as rejected_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--verify",
                        str(catalog_path),
                        "--json",
                    ]
                ),
                1,
            )
        rejected = json.loads(rejected_output.getvalue())
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["canonical_catalog"])
        Draft202012Validator(verification_schema).validate(rejected)

        with contextlib.redirect_stdout(io.StringIO()) as missing_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--verify",
                        str(self.root / "missing-catalog.json"),
                        "--json",
                    ]
                ),
                1,
            )
        missing = json.loads(missing_output.getvalue())
        self.assertFalse(missing["valid"])
        self.assertEqual(missing["errors"][0]["code"], "publication_catalog.input")
        Draft202012Validator(verification_schema).validate(missing)

        oversized_path = self.root / "oversized-catalog.json"
        oversized_path.write_bytes(b" " * (MAX_PUBLICATION_FAILURE_CATALOG_BYTES + 1))
        with contextlib.redirect_stdout(io.StringIO()) as oversized_output:
            self.assertEqual(
                main(
                    [
                        "publication-catalog",
                        "--verify",
                        str(oversized_path),
                        "--json",
                    ]
                ),
                1,
            )
        oversized = json.loads(oversized_output.getvalue())
        self.assertFalse(oversized["valid"])
        self.assertIn("byte limit", oversized["errors"][0]["message"])
        Draft202012Validator(verification_schema).validate(oversized)

        for filename, document, message in (
            ("duplicate-catalog.json", '{"format":"a","format":"b"}', "duplicate"),
            ("nonfinite-catalog.json", '{"value":NaN}', "non-finite"),
        ):
            with self.subTest(filename=filename):
                malformed_path = self.root / filename
                malformed_path.write_text(document, encoding="utf-8")
                malformed = verify_publication_failure_catalog_file(malformed_path)
                self.assertFalse(malformed["valid"])
                self.assertIn(message, malformed["errors"][0]["message"])
                Draft202012Validator(verification_schema).validate(malformed)

        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=[True, False],
        ):
            changed_during_read = verify_publication_failure_catalog_file(catalog_path)
        self.assertFalse(changed_during_read["valid"])
        self.assertIn(
            "changed during bounded consumption",
            changed_during_read["errors"][0]["message"],
        )
        Draft202012Validator(verification_schema).validate(changed_during_read)

    def test_offline_bundle_verification_detects_catalog_and_schema_drift(self) -> None:
        documents = schema_bundle_documents()
        verification = verify_schema_bundle_documents(documents)
        self.assertEqual(verification["format"], SCHEMA_BUNDLE_VERIFICATION_FORMAT)
        self.assertTrue(verification["valid"])
        self.assertTrue(all(verification["checks"].values()))
        self.assertEqual(verification["schema_count"], len(SCHEMA_FILENAMES))
        Draft202012Validator(schema_document("schema-bundle-verification")).validate(
            verification
        )

        changed = json.loads(json.dumps(documents))
        changed[SCHEMA_FILENAMES["diagram"]]["title"] = "Changed contract"
        rejected = verify_schema_bundle_documents(changed)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])
        self.assertEqual(rejected["errors"][0]["code"], "schema.digest")
        Draft202012Validator(schema_document("schema-bundle-verification")).validate(
            rejected
        )

        incomplete = json.loads(json.dumps(documents))
        incomplete.pop(SCHEMA_CATALOG_FILENAME)
        rejected = verify_schema_bundle_documents(incomplete)
        self.assertFalse(rejected["checks"]["file_set"])
        self.assertIn(
            "schema.file_missing", {value["code"] for value in rejected["errors"]}
        )

        pre_synthesis = json.loads(json.dumps(documents))
        synthesis_names = {"assurance-scaffold", "assurance-scaffold-verification"}
        pre_synthesis[SCHEMA_CATALOG_FILENAME]["schemas"] = [
            value
            for value in pre_synthesis[SCHEMA_CATALOG_FILENAME]["schemas"]
            if value["name"] not in synthesis_names
        ]
        for name in synthesis_names:
            pre_synthesis.pop(SCHEMA_FILENAMES[name])
        legacy_verification = verify_schema_bundle_documents(pre_synthesis)
        self.assertTrue(legacy_verification["valid"])
        self.assertEqual(legacy_verification["schema_count"], len(SCHEMA_FILENAMES) - 2)

        pre_onboarding = json.loads(json.dumps(documents))
        onboarding_names = {
            "evidence-onboarding-receipt",
            "evidence-onboarding-receipt-verification",
        }
        pre_onboarding[SCHEMA_CATALOG_FILENAME]["schemas"] = [
            value
            for value in pre_onboarding[SCHEMA_CATALOG_FILENAME]["schemas"]
            if value["name"] not in onboarding_names
        ]
        for name in onboarding_names:
            pre_onboarding.pop(SCHEMA_FILENAMES[name])
        previous_verification = verify_schema_bundle_documents(pre_onboarding)
        self.assertTrue(previous_verification["valid"])
        self.assertEqual(
            previous_verification["schema_count"], len(SCHEMA_FILENAMES) - 2
        )

        mixed = json.loads(json.dumps(documents))
        removed = mixed[SCHEMA_CATALOG_FILENAME]["schemas"].pop()
        mixed.pop(removed["filename"])
        rejected = verify_schema_bundle_documents(mixed)
        self.assertFalse(rejected["checks"]["catalog_completeness"])
        self.assertIn(
            "schema.catalog_completeness",
            {value["code"] for value in rejected["errors"]},
        )

    def test_contracts_match_public_format_names_and_bounds(self) -> None:
        detached_signature = schema_document("detached-signature")
        self.assertEqual(
            detached_signature["properties"]["format"]["const"], SIGNATURE_FORMAT
        )
        work_queue_schema = schema_document("assurance-work-queue")
        self.assertEqual(
            work_queue_schema["properties"]["format"]["const"],
            ASSURANCE_WORK_QUEUE_FORMAT,
        )
        work_queue = assurance_work_queue(scan_repository(self.root))
        Draft202012Validator(work_queue_schema).validate(work_queue)
        work_queue_verification_schema = schema_document(
            "assurance-work-queue-verification"
        )
        self.assertEqual(
            work_queue_verification_schema["properties"]["format"]["const"],
            ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
        )
        Draft202012Validator(work_queue_verification_schema).validate(
            verify_assurance_work_queue(work_queue)
        )
        self.assertEqual(
            detached_signature["properties"]["statement"]["properties"]["format"][
                "const"
            ],
            STATEMENT_FORMAT,
        )
        diagram = schema_document("diagram")
        self.assertEqual(
            diagram["properties"]["schema_version"]["const"], DIAGRAM_SCHEMA
        )
        bundle = schema_document("diagram-bundle")
        self.assertEqual(
            bundle["properties"]["schema_version"]["const"], DIAGRAM_BUNDLE_SCHEMA
        )
        self.assertEqual(bundle["properties"]["diagrams"]["maxItems"], MAX_DIAGRAMS)
        self.assertEqual(
            bundle["$defs"]["diagram"]["properties"]["schema_version"]["const"],
            DIAGRAM_SCHEMA,
        )
        diagram_verification = schema_document("diagram-bundle-verification")
        self.assertEqual(
            diagram_verification["properties"]["format"]["const"],
            DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
        )
        html_verification = schema_document("html-report-verification")
        self.assertEqual(
            html_verification["properties"]["format"]["const"],
            HTML_REPORT_VERIFICATION_FORMAT,
        )
        self.assertIn(
            "document_integrity",
            html_verification["properties"]["checks"]["required"],
        )
        for verification_schema in (
            html_verification,
            diagram_verification,
            schema_document("assurance-work-queue-verification"),
        ):
            verifier = verification_schema["properties"]["verifier"]
            self.assertEqual(verifier["properties"]["name"]["const"], "PySFMEA")
            self.assertEqual(set(verifier["required"]), {"name", "version"})
        package_manifest = schema_document("review-package-manifest")
        self.assertEqual(
            package_manifest["properties"]["format"]["const"],
            REVIEW_PACKAGE_FORMAT,
        )
        package_verification = schema_document("review-package-verification")
        self.assertEqual(
            package_verification["properties"]["verification_format"]["const"],
            REVIEW_PACKAGE_VERIFICATION_FORMAT,
        )
        publication = package_verification["properties"]["publication"]["properties"]
        self.assertEqual(
            publication["catalog_format"]["const"],
            PUBLICATION_FAILURE_CATALOG_FORMAT,
        )
        self.assertEqual(
            publication["catalog_algorithm"]["const"],
            PUBLICATION_FAILURE_CATALOG_ALGORITHM,
        )
        self.assertEqual(
            publication["catalog_canonicalization"]["const"],
            PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
        )
        self.assertEqual(
            publication["catalog_sha256"]["const"],
            PUBLICATION_FAILURE_CATALOG_SHA256,
        )
        self.assertEqual(
            set(publication["failure_code"]["enum"]),
            set(PUBLICATION_FAILURES),
        )
        self.assertEqual(
            set(publication["failure_rule_id"]["enum"]),
            {failure.rule_id for failure in PUBLICATION_FAILURES.values()},
        )
        self.assertEqual(
            set(publication["next_action"]["enum"]),
            {failure.next_action for failure in PUBLICATION_FAILURES.values()},
        )
        self.assertEqual(
            set(publication["retry_policy"]["enum"]),
            {failure.retry_policy for failure in PUBLICATION_FAILURES.values()},
        )
        workflow = schema_document("workflow-status")
        self.assertEqual(
            workflow["properties"]["format"]["const"], WORKFLOW_STATUS_FORMAT
        )
        status = workflow_status(self.root)
        Draft202012Validator(workflow).validate(status)
        self.assertEqual(
            status["handoff_gate_summary"]["total"], len(status["handoff_gates"])
        )
        action_ids = {action["id"] for action in status["next_actions"]}
        self.assertTrue(
            all(
                gate["passed"] or gate["remediation_action_id"] in action_ids
                for gate in status["handoff_gates"]
            )
        )
        with self.assertRaisesRegex(ValueError, "unknown schema"):
            schema_document("not-a-schema")

    def test_cli_lists_prints_and_atomically_exports_schemas(self) -> None:
        catalog_output = io.StringIO()
        with contextlib.redirect_stdout(catalog_output):
            result = main(["schema", "--list", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(catalog_output.getvalue())["format"], SCHEMA_CATALOG_FORMAT
        )

        schema_output = io.StringIO()
        with contextlib.redirect_stdout(schema_output):
            result = main(["schema", "diagram"])
        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(schema_output.getvalue())["$id"], "urn:pysfmea:schema:diagram:1"
        )

        destination = self.root / "contracts" / "diagram-bundle.schema.json"
        export_output = io.StringIO()
        with contextlib.redirect_stdout(export_output):
            result = main(["schema", "diagram-bundle", "-o", str(destination)])
        self.assertEqual(result, 0)
        self.assertTrue(destination.is_file())
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8"))["$id"],
            "urn:pysfmea:schema:diagram-bundle:1",
        )
        self.assertFalse(any(destination.parent.glob(".*.tmp")))

        original_schema = destination.read_bytes()
        with patch(
            "pysfmea.file_publication.os.replace",
            side_effect=OSError("injected schema publication failure"),
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["schema", "diagram-bundle", "-o", str(destination)]),
                    2,
                )
        self.assertEqual(destination.read_bytes(), original_schema)
        self.assertFalse(any(destination.parent.glob(".*.tmp")))

        bundle = self.root / "offline-contracts"
        bundle_output = io.StringIO()
        with contextlib.redirect_stdout(bundle_output):
            result = main(["schema", "--bundle", str(bundle)])
        self.assertEqual(result, 0)
        self.assertEqual(
            {path.name for path in bundle.iterdir()}, set(schema_bundle_documents())
        )
        self.assertIn("--verify-bundle", bundle_output.getvalue())

        verification_output = io.StringIO()
        with contextlib.redirect_stdout(verification_output):
            result = main(["schema", "--verify-bundle", str(bundle), "--json"])
        self.assertEqual(result, 0)
        verification = json.loads(verification_output.getvalue())
        self.assertTrue(verification["valid"])
        Draft202012Validator(schema_document("schema-bundle-verification")).validate(
            verification
        )

        changed_path = bundle / SCHEMA_FILENAMES["diagram"]
        changed = json.loads(changed_path.read_text(encoding="utf-8"))
        changed["title"] = "Changed after export"
        changed_path.write_text(
            json.dumps(changed, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        rejected_output = io.StringIO()
        with contextlib.redirect_stdout(rejected_output):
            result = main(["schema", "--verify-bundle", str(bundle), "--json"])
        self.assertEqual(result, 1)
        rejected = json.loads(rejected_output.getvalue())
        self.assertIn("schema.digest", {error["code"] for error in rejected["errors"]})

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle)]), 2)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle), "--force"]), 0)
        notes = bundle / "reviewer-notes.txt"
        notes.write_text("preserve me\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle), "--force"]), 2)
        self.assertEqual(notes.read_text(encoding="utf-8"), "preserve me\n")
        notes.unlink()
        invalid_type = bundle / SCHEMA_FILENAMES["diagram"]
        invalid_type.unlink()
        invalid_type.mkdir()
        type_output = io.StringIO()
        with contextlib.redirect_stdout(type_output):
            self.assertEqual(
                main(["schema", "--verify-bundle", str(bundle), "--json"]), 1
            )
        self.assertIn(
            "schema.file_type",
            {error["code"] for error in json.loads(type_output.getvalue())["errors"]},
        )
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle), "--force"]), 2)
        self.assertFalse(
            any(
                path.name.startswith(".offline-contracts.")
                for path in self.root.iterdir()
            )
        )

        missing_output = io.StringIO()
        with contextlib.redirect_stdout(missing_output):
            result = main(
                [
                    "schema",
                    "--verify-bundle",
                    str(self.root / "missing-contracts"),
                    "--json",
                ]
            )
        self.assertEqual(result, 1)
        self.assertFalse(json.loads(missing_output.getvalue())["valid"])

    def test_schema_bundle_file_reads_are_bounded_and_link_safe(self) -> None:
        self.assertEqual(MAX_SCHEMA_BUNDLE_FILE_BYTES, 2_000_000)
        bundle = self.root / "bounded-contracts"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle)]), 0)
        verdict_schema = Draft202012Validator(
            schema_document("schema-bundle-verification")
        )

        with patch("pysfmea.schemas.MAX_SCHEMA_BUNDLE_FILE_BYTES", 10):
            oversized = verify_schema_bundle_path(bundle)
        self.assertFalse(oversized["valid"])
        self.assertTrue(
            any(
                error["code"] == "schema.file_invalid"
                and "10-byte limit" in error["message"]
                for error in oversized["errors"]
            )
        )
        verdict_schema.validate(oversized)

        target = bundle / SCHEMA_FILENAMES["diagram"]
        original = target.read_bytes()
        target.write_bytes(b"\xff\xfe")
        invalid_utf8 = verify_schema_bundle_path(bundle)
        self.assertFalse(invalid_utf8["valid"])
        self.assertIn(
            "schema.file_invalid",
            {error["code"] for error in invalid_utf8["errors"]},
        )
        verdict_schema.validate(invalid_utf8)
        target.write_bytes(original)

        target.write_text('{"$id":"first","$id":"second"}', encoding="utf-8")
        duplicate = verify_schema_bundle_path(bundle)
        self.assertFalse(duplicate["valid"])
        self.assertTrue(
            any(
                "duplicate object key" in error["message"]
                for error in duplicate["errors"]
            )
        )
        verdict_schema.validate(duplicate)
        target.write_bytes(original)

        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            return_value=False,
        ):
            changed_during_read = verify_schema_bundle_path(bundle)
        self.assertFalse(changed_during_read["valid"])
        self.assertTrue(
            any(
                "changed during safe open" in error["message"]
                for error in changed_during_read["errors"]
            )
        )
        verdict_schema.validate(changed_during_read)

        with patch("pysfmea.schemas.MAX_SCHEMA_BUNDLE_JSON_DEPTH", 1):
            too_deep = verify_schema_bundle_path(bundle)
        self.assertFalse(too_deep["valid"])
        self.assertTrue(
            any("JSON depth limit" in error["message"] for error in too_deep["errors"])
        )
        verdict_schema.validate(too_deep)

        with patch(
            "pysfmea.schemas.Path.is_symlink",
            autospec=True,
            side_effect=lambda candidate: candidate.name == target.name,
        ):
            linked = verify_schema_bundle_path(bundle)
        self.assertFalse(linked["valid"])
        self.assertIn("schema.file_type", {error["code"] for error in linked["errors"]})
        verdict_schema.validate(linked)

        linked_target = bundle / SCHEMA_FILENAMES["workflow-status"]
        linked_original = linked_target.read_bytes()
        linked_target.unlink()
        try:
            linked_target.symlink_to(bundle / SCHEMA_CATALOG_FILENAME)
        except OSError:
            linked_target.write_bytes(linked_original)
        else:
            linked_verdict = verify_schema_bundle_path(bundle)
            self.assertFalse(linked_verdict["valid"])
            self.assertIn(
                "schema.file_type",
                {error["code"] for error in linked_verdict["errors"]},
            )
            verdict_schema.validate(linked_verdict)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance import (
    ASSURANCE_WORK_QUEUE_FORMAT,
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    assurance_work_queue,
    verify_assurance_work_queue,
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
from pysfmea.scanner import scan_repository
from pysfmea.schemas import (
    JSON_SCHEMA_DRAFT,
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
)
from pysfmea.signing import SIGNATURE_FORMAT, STATEMENT_FORMAT
from pysfmea.workflow import WORKFLOW_STATUS_FORMAT, workflow_status


class SchemaCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

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
                "assurance-work-queue",
                "assurance-work-queue-verification",
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

    def test_offline_bundle_verification_detects_catalog_and_schema_drift(self) -> None:
        documents = schema_bundle_documents()
        verification = verify_schema_bundle_documents(documents)
        self.assertEqual(verification["format"], SCHEMA_BUNDLE_VERIFICATION_FORMAT)
        self.assertTrue(verification["valid"])
        self.assertTrue(all(verification["checks"].values()))
        self.assertEqual(verification["schema_count"], len(SCHEMA_FILENAMES))
        Draft202012Validator(
            schema_document("schema-bundle-verification")
        ).validate(verification)

        changed = json.loads(json.dumps(documents))
        changed[SCHEMA_FILENAMES["diagram"]]["title"] = "Changed contract"
        rejected = verify_schema_bundle_documents(changed)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])
        self.assertEqual(rejected["errors"][0]["code"], "schema.digest")
        Draft202012Validator(
            schema_document("schema-bundle-verification")
        ).validate(rejected)

        incomplete = json.loads(json.dumps(documents))
        incomplete.pop(SCHEMA_CATALOG_FILENAME)
        rejected = verify_schema_bundle_documents(incomplete)
        self.assertFalse(rejected["checks"]["file_set"])
        self.assertIn(
            "schema.file_missing", {value["code"] for value in rejected["errors"]}
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
        self.assertEqual(diagram["properties"]["schema_version"]["const"], DIAGRAM_SCHEMA)
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
            result = main(
                ["schema", "--verify-bundle", str(bundle), "--json"]
            )
        self.assertEqual(result, 0)
        verification = json.loads(verification_output.getvalue())
        self.assertTrue(verification["valid"])
        Draft202012Validator(
            schema_document("schema-bundle-verification")
        ).validate(verification)

        changed_path = bundle / SCHEMA_FILENAMES["diagram"]
        changed = json.loads(changed_path.read_text(encoding="utf-8"))
        changed["title"] = "Changed after export"
        changed_path.write_text(
            json.dumps(changed, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        rejected_output = io.StringIO()
        with contextlib.redirect_stdout(rejected_output):
            result = main(
                ["schema", "--verify-bundle", str(bundle), "--json"]
            )
        self.assertEqual(result, 1)
        rejected = json.loads(rejected_output.getvalue())
        self.assertIn("schema.digest", {error["code"] for error in rejected["errors"]})

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["schema", "--bundle", str(bundle)]), 2)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["schema", "--bundle", str(bundle), "--force"]), 0
            )
        notes = bundle / "reviewer-notes.txt"
        notes.write_text("preserve me\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(["schema", "--bundle", str(bundle), "--force"]), 2
            )
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
            self.assertEqual(
                main(["schema", "--bundle", str(bundle), "--force"]), 2
            )
        self.assertFalse(
            any(path.name.startswith(".offline-contracts.") for path in self.root.iterdir())
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


if __name__ == "__main__":
    unittest.main()

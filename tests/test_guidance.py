from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.guidance import (
    citations_for_rule,
    guidance_bundle,
    guidance_traceability,
    validate_guidance_catalog,
)
from pysfmea.html_report import build_html_report_data, export_html_report
from pysfmea.report import export_guidance_traceability
from pysfmea.scanner import scan_repository
from pysfmea.store import load_analysis, save_analysis
from pysfmea.validation import validate_analysis


class GuidanceTraceabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def transform(value):\n    return value / 100\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_catalog_and_findings_have_typed_versioned_relationships(self) -> None:
        validate_guidance_catalog()
        trace = guidance_traceability(self.analysis)
        self.assertEqual(trace["schema_version"], "1.1")
        self.assertTrue(trace["catalog_sha256"])
        self.assertEqual(trace["coverage"]["finding_coverage_percent"], 100.0)
        self.assertGreater(trace["coverage"]["directly_cited_findings"], 0)
        self.assertGreater(trace["coverage"]["direct_finding_coverage_percent"], 0)
        self.assertIn("direct", trace["coverage"]["uses_by_mapping_strength"])
        self.assertGreater(trace["coverage"]["total_citation_uses"], 0)
        self.assertGreater(trace["coverage"]["average_citations_per_finding"], 0)
        self.assertIsInstance(trace["coverage"]["broadly_reused_citations"], dict)
        self.assertIn("80%", trace["coverage"]["specificity_notice"])
        self.assertEqual(trace["mapping_governance"]["mapping_integrity_failures"], 0)
        self.assertEqual(trace["mapping_governance"]["review_integrity_failures"], 0)
        self.assertEqual(trace["mapping_governance"]["unverifiable_legacy_mappings"], 0)
        self.assertGreater(trace["mapping_governance"]["active_mappings"], 0)
        self.assertEqual(
            trace["mapping_governance"]["independently_approved_mappings"], 0
        )
        self.assertEqual(
            trace["mapping_governance"]["effective_independently_approved_mappings"],
            0,
        )
        self.assertEqual(trace["mapping_governance"]["expired_mapping_reviews"], 0)
        self.assertEqual(
            trace["mapping_governance"]["review_audit_as_of"],
            self.analysis["run_manifest"]["created_at"][:10],
        )
        self.assertTrue(
            all(
                finding["strongest_mapping"]
                in {"direct", "supporting", "contextual", "uncited"}
                for finding in trace["finding_links"]
            )
        )
        faa = next(
            source for source in trace["sources"] if source["id"] == "FAA-RLV-SCS-2006"
        )
        self.assertEqual(faa["status"], "legacy")
        links = [
            link for finding in trace["finding_links"] for link in finding["citations"]
        ]
        self.assertTrue(links)
        self.assertTrue(all(link["status"] == "curated" for link in links))
        self.assertNotIn(
            "potential_nonconformance", {link["relationship"] for link in links}
        )

    def test_legacy_mapping_without_record_digest_is_explicitly_unverifiable(
        self,
    ) -> None:
        legacy = json.loads(json.dumps(self.analysis))
        active_profiles = set(legacy["guidance"]["active_profiles"])
        mapping = next(
            value
            for value in legacy["guidance"]["rule_mappings"]
            if active_profiles.intersection(value["profile_ids"])
        )
        mapping.pop("record_sha256")

        governance = guidance_traceability(legacy)["mapping_governance"]

        self.assertEqual(governance["mapping_integrity_failures"], 0)
        self.assertEqual(governance["unverifiable_legacy_mappings"], 1)

    def test_tampered_mapping_review_is_reported_independently(self) -> None:
        tampered = json.loads(json.dumps(self.analysis))
        active_profiles = set(tampered["guidance"]["active_profiles"])
        mapping = next(
            value
            for value in tampered["guidance"]["rule_mappings"]
            if active_profiles.intersection(value["profile_ids"])
        )
        mapping["review"] = {
            "decision": "approved",
            "reviewer": "Independent reviewer",
            "record_sha256": "0" * 64,
        }

        governance = guidance_traceability(tampered)["mapping_governance"]

        self.assertEqual(governance["mapping_integrity_failures"], 1)
        self.assertEqual(governance["review_integrity_failures"], 1)

    def test_profiles_prevent_cross_domain_citation_leakage(self) -> None:
        core_links = citations_for_rule("functional.omission", ["core_sfmea"])
        commercial_links = citations_for_rule(
            "functional.omission", ["faa_commercial_space"]
        )
        airworthiness_links = citations_for_rule(
            "functional.omission", ["faa_airworthiness"]
        )
        self.assertTrue(core_links)
        self.assertTrue(
            all(link["source_id"].startswith("NASA-") for link in core_links)
        )
        self.assertEqual(
            {link["source_id"] for link in commercial_links},
            {"FAA-AC-450.141-1A"},
        )
        self.assertEqual(
            {link["source_id"] for link in airworthiness_links},
            {"FAA-AC-20-115D"},
        )
        self.assertTrue(
            any(
                link["citation_id"] == "FAA-AC-450.141-1A-B.1.1-SFMEA"
                and link["strength"] == "direct"
                for link in commercial_links
            )
        )
        commercial_timing = citations_for_rule(
            "timing.late_or_early", ["faa_commercial_space"]
        )
        self.assertTrue(
            any(
                link["citation_id"] == "FAA-AC-450.141-1A-B.1.2-TAXONOMY"
                and link["strength"] == "direct"
                for link in commercial_timing
            )
        )

    def test_source_and_selection_integrity_are_machine_readable(self) -> None:
        bundle = guidance_bundle(["core_sfmea", "faa_commercial_space"])
        self.assertEqual(bundle["schema_version"], "1.1")
        self.assertEqual(
            bundle["active_profiles"], ["core_sfmea", "faa_commercial_space"]
        )
        self.assertEqual(len(bundle["selection_sha256"]), 64)
        self.assertTrue(
            all(len(source["record_sha256"]) == 64 for source in bundle["sources"])
        )
        self.assertTrue(
            all(
                len(citation["locator_summary_sha256"]) == 64
                for citation in bundle["citations"]
            )
        )
        self.assertTrue(
            all(
                len(mapping["record_sha256"]) == 64
                and mapping["review_status"]
                in {
                    "maintainer_curated",
                    "organization_supplied",
                }
                for mapping in bundle["rule_mappings"]
            )
        )
        faa = next(
            source
            for source in bundle["sources"]
            if source["id"] == "FAA-AC-450.141-1A"
        )
        self.assertEqual(len(faa["artifact"]["sha256"]), 64)

    def test_security_profile_uses_specific_weakness_mappings(self) -> None:
        authorization = citations_for_rule("domain.cross_scope_access", ["security"])
        outbound = citations_for_rule("domain.outbound_rebinding", ["security"])
        resources = citations_for_rule("resource.exhaustion", ["security"])
        self.assertIn(
            "MITRE-CWE-862", {value["citation_id"] for value in authorization}
        )
        self.assertIn("MITRE-CWE-918", {value["citation_id"] for value in outbound})
        self.assertIn("MITRE-CWE-400", {value["citation_id"] for value in resources})

    def test_json_csv_cli_and_persistence_outputs(self) -> None:
        json_path = export_guidance_traceability(
            self.analysis, self.root / "guidance.json", format="json"
        )
        csv_path = export_guidance_traceability(
            self.analysis, self.root / "guidance.csv", format="csv"
        )
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertTrue(payload["finding_links"])
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        self.assertTrue(rows[0]["citation_id"])
        self.assertTrue(rows[0]["section"])

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        persisted = json.loads(analysis_path.read_text(encoding="utf-8"))
        self.assertIn("guidance", persisted)
        self.assertTrue(persisted["items"][0]["scanner"]["citations"])
        with contextlib.redirect_stdout(io.StringIO()):
            result = main(["citations", str(analysis_path), "--format", "json"])
        self.assertEqual(result, 0)
        self.assertTrue((self.root / "analysis.guidance.json").is_file())
        self.assertIn("guidance", load_analysis(analysis_path))

    def test_validation_rejects_an_invented_citation(self) -> None:
        item = self.analysis["items"][0]
        item["scanner"]["citations"][0]["citation_id"] = "NASA-INVENTED-99.99"
        findings = validate_analysis(self.analysis)["findings"]
        self.assertIn(
            "guidance.unknown_citation", {value["rule_id"] for value in findings}
        )

    def test_html_report_has_navigable_guidance_data(self) -> None:
        payload = build_html_report_data(self.analysis)
        self.assertEqual(
            payload["guidance"]["coverage"]["finding_coverage_percent"], 100.0
        )
        self.assertEqual(
            payload["guidance"]["mapping_governance"]["mapping_integrity_failures"],
            0,
        )
        self.assertTrue(payload["records"][0]["citations"])
        report = export_html_report(self.analysis, self.root / "report.html")
        document = report.read_text(encoding="utf-8")
        self.assertIn('data-view="guidance"', document)
        self.assertIn("Guidance-to-finding traceability", document)
        self.assertIn("Show findings", document)
        self.assertIn("direct mapping coverage", document)


if __name__ == "__main__":
    unittest.main()

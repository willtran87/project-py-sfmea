from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance_case import assurance_case, export_assurance_case
from pysfmea.cli import main
from pysfmea.conformance import (
    assess_objective,
    conformance_workspace,
    export_conformance_workspace,
    standards_catalog,
)
from pysfmea.industry_exchange import (
    export_exchange,
    verify_exchange,
    verify_exchange_file,
)
from pysfmea.qualification_bases import qualification_bases_catalog
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.standards_crosswalk import (
    CROSSWALK_MAPPING_FORMAT,
    export_standards_crosswalk,
    standards_crosswalk,
    verify_standards_crosswalk_file,
)
from pysfmea.store import save_analysis
from pysfmea.vex import (
    VEX_DECISIONS_FORMAT,
    export_cyclonedx_vex,
    verify_cyclonedx_vex_file,
)


class IndustryInteroperabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "service.py").write_text(
            "def ratio(total: float, count: int) -> float:\n"
            "    return total / count\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        self.analysis_path = self.root / "analysis.json"
        save_analysis(self.analysis_path, self.analysis)
        self.workspace = conformance_workspace(
            self.analysis,
            ["iso-29148-2018"],
            system="ratio service",
            lifecycle_phase="verification",
            applicability_basis="project assurance plan",
            authority="independent assurance lead",
            generated_at="2026-08-27T12:00:00+00:00",
        )
        for objective in self.workspace["profiles"][0]["objectives"]:
            self.workspace = assess_objective(
                self.workspace,
                objective["id"],
                applicability="applicable",
                status="satisfied",
                rationale="Reviewed against controlled requirements evidence.",
                reviewer="assurance@example.test",
                evidence_refs=[f"evidence://{objective['id']}"],
                reviewed_at="2026-08-27T13:00:00+00:00",
            )
        self.workspace_path = self.root / "conformance.json"
        export_conformance_workspace(self.workspace, self.workspace_path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _mapping_path(self) -> Path:
        active = [
            item["id"]
            for item in self.analysis["items"]
            if item.get("source_status", "active") == "active"
        ]
        links = []
        for index, objective in enumerate(self.workspace["profiles"][0]["objectives"]):
            links.append(
                {
                    "objective_id": objective["id"],
                    "relationship": "direct",
                    "finding_ids": active if index == 0 else [],
                    "obligation_ids": [],
                    "rationale": "The objective governs this static-analysis evidence.",
                    "authority": "independent assurance lead",
                    "evidence_refs": [f"evidence://{objective['id']}"],
                }
            )
        path = self.root / "mapping.json"
        path.write_text(
            json.dumps({"format": CROSSWALK_MAPPING_FORMAT, "links": links}),
            encoding="utf-8",
        )
        return path

    def test_catalog_adds_system_risk_and_dependability_profiles(self) -> None:
        identifiers = {profile["id"] for profile in standards_catalog()["profiles"]}
        self.assertGreaterEqual(len(identifiers), 30)
        self.assertTrue(
            {
                "iso-29148-2018",
                "iso-42010-2022",
                "iso-15288-2023",
                "iso-16085-2021",
                "iec-61025-2006",
                "iec-62502-2010",
                "iec-62740-2015",
            }.issubset(identifiers)
        )

    def test_qualification_basis_packs_cover_all_dossier_objectives(self) -> None:
        catalog = qualification_bases_catalog()
        self.assertEqual(len(catalog["packs"]), 3)
        for pack in catalog["packs"]:
            self.assertEqual(
                {item["objective_id"] for item in pack["objective_crosswalk"]},
                {
                    "TQ-CLASSIFY",
                    "TQ-TOR",
                    "TQ-TQP",
                    "TQ-TVP",
                    "TQ-TVR",
                    "TQ-CONFIG",
                    "TQ-ANOMALY",
                    "TQ-TQAS",
                    "TQ-REQUALIFY",
                },
            )
        Draft202012Validator(schema_document("tool-qualification-bases")).validate(
            catalog
        )

    def test_crosswalk_exact_regeneration_schema_and_tamper_rejection(self) -> None:
        mapping_path = self._mapping_path()
        value = standards_crosswalk(
            self.analysis,
            self.analysis_path,
            self.workspace_path,
            mapping_path,
            generated_at="2026-08-27T14:00:00+00:00",
        )
        self.assertTrue(value["summary"]["trace_complete"])
        Draft202012Validator(schema_document("standards-crosswalk")).validate(value)
        output = self.root / "crosswalk.json"
        export_standards_crosswalk(value, output)
        verdict = verify_standards_crosswalk_file(
            output,
            analysis_source=self.analysis_path,
            workspace_source=self.workspace_path,
            mapping_source=mapping_path,
        )
        self.assertTrue(verdict["valid"])
        Draft202012Validator(
            schema_document("standards-crosswalk-verification")
        ).validate(verdict)
        changed = json.loads(output.read_text(encoding="utf-8"))
        changed["summary"]["trace_complete"] = False
        output.write_text(json.dumps(changed), encoding="utf-8")
        self.assertFalse(verify_standards_crosswalk_file(output)["valid"])

    def test_sacm_sfpm_reqif_and_spdx_round_trip(self) -> None:
        case = assurance_case(
            self.analysis,
            self.analysis_path,
            generated_at="2026-08-27T14:00:00+00:00",
        )
        case_path = self.root / "case.json"
        export_assurance_case(case, case_path)
        sources = {"sacm": case, "sfpm": self.analysis, "reqif": self.analysis, "spdx": self.analysis}
        extensions = {"sacm": ".xmi", "sfpm": ".xmi", "reqif": ".reqif", "spdx": ".spdx.json"}
        for kind, source in sources.items():
            with self.subTest(kind=kind):
                output = self.root / f"exchange{extensions[kind]}"
                export_exchange(kind, source, output, generated_at="2026-08-27T15:00:00+00:00")
                verdict = verify_exchange_file(kind, output, source)
                self.assertTrue(verdict["valid"], verdict["errors"])
                Draft202012Validator(
                    schema_document("industry-exchange-verification")
                ).validate(verdict)
        tampered = copy.deepcopy(self.analysis)
        tampered["project"]["name"] = "different"
        spdx_path = self.root / "exchange.spdx.json"
        self.assertFalse(verify_exchange_file("spdx", spdx_path, tampered)["valid"])
        self.assertFalse(verify_exchange("unsupported", {}, self.analysis)["valid"])

    def test_cli_crosswalk_and_exchange(self) -> None:
        mapping = self._mapping_path()
        crosswalk = self.root / "crosswalk-cli.json"
        sfpm = self.root / "sfpm-cli.xmi"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["standards-crosswalk", str(self.analysis_path), str(self.workspace_path), str(mapping), "-o", str(crosswalk)]),
                0,
            )
            self.assertEqual(
                main(["standards-crosswalk-verify", str(crosswalk), "--analysis", str(self.analysis_path), "--conformance", str(self.workspace_path), "--mapping", str(mapping)]),
                0,
            )
            self.assertEqual(
                main(["industry-exchange", "sfpm", str(self.analysis_path), "-o", str(sfpm)]),
                0,
            )
            self.assertEqual(
                main(["industry-exchange-verify", "sfpm", str(sfpm), str(self.analysis_path)]),
                0,
            )

    def test_cyclonedx_vex_requires_and_preserves_governed_decisions(self) -> None:
        decisions = {
            "format": VEX_DECISIONS_FORMAT,
            "authority": "product security authority",
            "issued_at": "2026-08-27T16:00:00+00:00",
            "vulnerabilities": [
                {
                    "id": "CVE-2099-0001",
                    "source_name": "NVD",
                    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "response": [],
                    "detail": "Reviewed data flow shows the affected entry point is unreachable.",
                    "affected_refs": ["project"],
                    "evidence_refs": ["evidence://security-review/42"],
                }
            ],
        }
        decisions_path = self.root / "vex-decisions.json"
        decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
        output = self.root / "vex.cdx.json"
        export_cyclonedx_vex(self.analysis, decisions_path, output)
        verdict = verify_cyclonedx_vex_file(
            output, self.analysis, decisions_path
        )
        self.assertTrue(verdict["valid"], verdict["errors"])
        Draft202012Validator(schema_document("vex-verification")).validate(verdict)
        decisions["vulnerabilities"][0]["justification"] = None
        decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
        self.assertFalse(
            verify_cyclonedx_vex_file(output, self.analysis, decisions_path)["valid"]
        )

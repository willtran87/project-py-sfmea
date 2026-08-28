from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.assurance_case import assurance_case, export_assurance_case
from pysfmea.benchmark_v2 import (
    benchmark_v2_assessment,
    export_benchmark_v2_assessment,
    seal_benchmark_v2_source,
)
from pysfmea.gsn import (
    export_gsn_projection,
    gsn_projection,
    verify_gsn_projection,
    verify_gsn_projection_file,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.release_qualification import (
    export_release_qualification_assessment,
    export_release_qualification_source,
    release_qualification_assessment,
    release_qualification_source_template,
    seal_release_qualification_source,
    verify_release_qualification_assessment_file,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.ssvc import (
    DECISION_POINTS,
    export_ssvc_assessment,
    export_ssvc_source,
    seal_ssvc_source,
    ssvc_assessment,
    ssvc_observations_template,
    ssvc_policy_template,
    verify_ssvc_assessment_file,
)
from pysfmea.store import save_analysis


class IndustryReleaseControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "service.py").write_text(
            "def deliver(value: int) -> int:\n    return value + 1\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _passing_benchmark(self, name: str) -> Path:
        examples = Path(__file__).resolve().parents[1] / "examples"
        protocol = json.loads(
            (examples / "independent-benchmark-protocol-v2.json").read_text(encoding="utf-8")
        )
        observations = json.loads(
            (examples / "independent-benchmark-observations-v2.json").read_text(encoding="utf-8")
        )
        protocol["statistics"]["metric_thresholds"]["propagation_paths"] = {
            "minimum_recall_lower": 0.5,
            "minimum_precision_lower": 0.5,
        }
        protocol["statistics"]["bootstrap_replicates"] = 200
        for repository in observations["repositories"]:
            repository["metrics"]["propagation_paths"] = {
                "true_positive": 20,
                "false_positive": 0,
                "false_negative": 0,
                "true_negative": 20,
            }
        protocol_path = self.root / f"{name}-protocol.json"
        observations_path = self.root / f"{name}-observations.json"
        protocol_path.write_text(json.dumps(protocol), encoding="utf-8")
        observations_path.write_text(json.dumps(observations), encoding="utf-8")
        seal_benchmark_v2_source(protocol_path, protocol_path)
        seal_benchmark_v2_source(
            observations_path, observations_path, protocol_source=protocol_path
        )
        value = benchmark_v2_assessment(
            protocol_path,
            observations_path,
            generated_at="2026-08-28T12:00:00+00:00",
        )
        self.assertTrue(value["summary"]["passed"])
        output = self.root / f"{name}-assessment.json"
        export_benchmark_v2_assessment(value, output)
        return output

    def test_release_qualification_enforces_holdout_noninferiority_and_budgets(self) -> None:
        candidate = self._passing_benchmark("candidate")
        baseline = self._passing_benchmark("baseline")
        source = release_qualification_source_template(authority="protocol-owner")
        source.update(
            {
                "id": "release-qualification-065",
                "pre_registered_at": "2026-08-01T00:00:00+00:00",
                "pre_registration_evidence_ref": "registry://release-qualification-065",
                "authority": {
                    "protocol_owner": "protocol-owner",
                    "benchmark_authority": "independent-benchmark-authority",
                    "approval_authority": "release-approval-authority",
                    "independence_basis": "Distinct organizations and reporting lines.",
                },
                "candidate": {"version": "0.65.0", "subject_sha256": "9" * 64, "assessment_ref": candidate.name},
                "baseline": {"version": "0.64.0", "subject_sha256": "a" * 64, "assessment_ref": baseline.name},
                "corpus": {
                    "temporal_cutoff": "2026-01-01T00:00:00+00:00",
                    "similarity_threshold": 0.9,
                    "candidate_repositories": [
                        {
                            "id": f"replace-repository-{index}",
                            "source_ref": f"evidence://candidate/repo/{index}",
                            "content_sha256": str(index) * 64,
                            "history_root_sha256": str(index + 3) * 64,
                            "lineage_ids": [f"candidate-lineage-{index}"],
                            "observed_at": "2026-08-01T00:00:00+00:00",
                        }
                        for index in range(1, 4)
                    ],
                    "excluded_reference_repositories": [
                        {
                            "id": "reference-repo",
                            "source_ref": "evidence://reference/repo",
                            "content_sha256": "7" * 64,
                            "history_root_sha256": "8" * 64,
                            "lineage_ids": ["reference-lineage"],
                            "observed_at": "2025-12-01T00:00:00+00:00",
                        }
                    ],
                    "pairwise_similarity_evidence": [
                        {
                            "candidate_id": f"replace-repository-{index}",
                            "reference_id": "reference-repo",
                            "similarity": 0.1,
                            "method": "content and history fingerprint comparison",
                            "evidence_ref": f"evidence://similarity/{index}",
                        }
                        for index in range(1, 4)
                    ],
                },
                "noninferiority": {
                    "metric_margins": {"propagation_paths": 0.0},
                    "maximum_duration_ratio": 1.1,
                    "maximum_peak_rss_ratio": 1.1,
                    "maximum_artifact_size_ratio": 1.1,
                },
                "performance": {
                    "candidate": {"duration_seconds": 10.0, "peak_rss_bytes": 1000, "artifact_size_bytes": 1000, "evidence_ref": "evidence://performance/candidate"},
                    "baseline": {"duration_seconds": 10.0, "peak_rss_bytes": 1000, "artifact_size_bytes": 1000, "evidence_ref": "evidence://performance/baseline"},
                },
                "evidence_refs": ["evidence://release/campaign"],
            }
        )
        source["content_sha256"] = "0" * 64
        source_path = self.root / "release-source.json"
        export_release_qualification_source(source, source_path)
        seal_release_qualification_source(source_path, source_path)
        result = release_qualification_assessment(
            source_path,
            candidate,
            baseline,
            generated_at="2026-08-28T13:00:00+00:00",
        )
        self.assertTrue(result["summary"]["passed"])
        Draft202012Validator(schema_document("release-qualification-assessment")).validate(result)
        output = self.root / "release-assessment.json"
        export_release_qualification_assessment(result, output)
        verdict = verify_release_qualification_assessment_file(
            output,
            source_path=source_path,
            candidate_assessment_path=candidate,
            baseline_assessment_path=baseline,
        )
        self.assertTrue(verdict["valid"], verdict["errors"])
        self.assertTrue(verdict["passed"])

        unrelated = json.loads(source_path.read_text(encoding="utf-8"))
        unrelated["corpus"]["candidate_repositories"][0]["id"] = "unrelated-repository"
        unrelated["corpus"]["pairwise_similarity_evidence"][0]["candidate_id"] = "unrelated-repository"
        unrelated["content_sha256"] = "0" * 64
        unrelated_path = self.root / "unrelated-release-source.json"
        export_release_qualification_source(unrelated, unrelated_path)
        seal_release_qualification_source(unrelated_path, unrelated_path)
        blocked = release_qualification_assessment(unrelated_path, candidate, baseline)
        self.assertFalse(blocked["summary"]["passed"])
        self.assertFalse(blocked["checks"]["candidate_corpus_bound_to_benchmark"])

    def test_controlled_ssvc_table_is_complete_and_reproducible(self) -> None:
        incomplete = ssvc_policy_template(authority="product-security-authority")
        incomplete.update(
            {
                "model_version": "controlled-local-profile-2026-08",
                "approved_at": "2026-08-28T10:00:00+00:00",
                "rules": [
                    {
                        "id": "RULE-INCOMPLETE",
                        "conditions": {name: [values[0]] for name, values in DECISION_POINTS.items()},
                        "outcome": "track",
                        "rationale": "Deliberately incomplete negative control.",
                    }
                ],
            }
        )
        incomplete["content_sha256"] = "0" * 64
        incomplete_path = self.root / "ssvc-incomplete.json"
        export_ssvc_source(incomplete, incomplete_path)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            seal_ssvc_source(incomplete_path, incomplete_path)

        policy = ssvc_policy_template(authority="product-security-authority")
        policy.update(
            {
                "model_version": "controlled-local-profile-2026-08",
                "approved_at": "2026-08-28T10:00:00+00:00",
                "rules": [
                    {
                        "id": "RULE-ALL-ATTEND",
                        "conditions": {name: list(values) for name, values in DECISION_POINTS.items()},
                        "outcome": "attend",
                        "rationale": "Controlled test policy covering the complete decision space.",
                    }
                ],
            }
        )
        policy["content_sha256"] = "0" * 64
        policy_path = self.root / "ssvc-policy.json"
        export_ssvc_source(policy, policy_path)
        seal_ssvc_source(policy_path, policy_path)
        sealed_policy = json.loads(policy_path.read_text(encoding="utf-8"))

        observations = ssvc_observations_template(
            policy_id=sealed_policy["content_sha256"], authority="vulnerability-review-board"
        )
        observations["vulnerabilities"] = [
            {
                "id": "CVE-2099-0001",
                "exploitation": "active",
                "automatable": "yes",
                "technical_impact": "total",
                "mission_prevalence": "essential",
                "public_wellbeing_impact": "material",
                "evidence_refs": ["evidence://vulnerability/2099-0001"],
                "rationale": "Decision points were reviewed by the vulnerability board.",
                "next_review_at": "2026-09-01T00:00:00+00:00",
            }
        ]
        observations["content_sha256"] = "0" * 64
        observations_path = self.root / "ssvc-observations.json"
        export_ssvc_source(observations, observations_path)
        seal_ssvc_source(observations_path, observations_path, policy_source=policy_path)
        result = ssvc_assessment(
            policy_path, observations_path, generated_at="2026-08-28T11:00:00+00:00"
        )
        self.assertEqual(result["decisions"][0]["outcome"], "attend")
        Draft202012Validator(schema_document("ssvc-assessment")).validate(result)
        output = self.root / "ssvc-assessment.json"
        export_ssvc_assessment(result, output)
        verdict = verify_ssvc_assessment_file(
            output, policy_source=policy_path, observations_source=observations_path
        )
        self.assertTrue(verdict["valid"], verdict["errors"])

    def test_gsn_projection_retains_assumptions_defeaters_and_exact_binding(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        case_value = assurance_case(
            self.analysis, analysis_path, generated_at="2026-08-28T10:00:00+00:00"
        )
        case_path = self.root / "assurance-case.json"
        export_assurance_case(case_value, case_path)
        projection = gsn_projection(case_path)
        self.assertGreater(projection["summary"]["goals"], 0)
        self.assertGreater(projection["summary"]["assumptions"], 0)
        self.assertGreater(projection["summary"]["open_defeaters"], 0)
        Draft202012Validator(schema_document("gsn-projection")).validate(projection)
        output = self.root / "gsn.json"
        export_gsn_projection(projection, output)
        verdict = verify_gsn_projection_file(output, assurance_case_source=case_path)
        self.assertTrue(verdict["valid"], verdict["errors"])

        forged = copy.deepcopy(projection)
        forged["edges"].append(
            {"source": projection["top_node_id"], "target": "missing-node", "kind": "supported_by"}
        )
        forged["summary"]["edges"] += 1
        forged["summary"]["dangling_edges"] = 1
        forged.pop("content_sha256")
        forged["content_sha256"] = canonical_json_sha256(forged)
        self.assertFalse(verify_gsn_projection(forged)["valid"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.clusterfuzz_intake import (
    import_clusterfuzzlite_intake,
    verify_clusterfuzzlite_intake,
)
from pysfmea.conformance import standards_catalog
from pysfmea.governed_artifact import seal
from pysfmea.samate_assessment import samate_assessment, samate_source_template
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.sfmea_benchmark import (
    run_sfmea_semantic_benchmark,
    verify_sfmea_semantic_benchmark,
)
from pysfmea.test_dossier import test_dossier as generate_test_dossier
from pysfmea.test_dossier import verify_test_dossier
from pysfmea.vulnerability_applicability import (
    verify_vulnerability_applicability,
    vulnerability_applicability,
)
from pysfmea.vulnerability_intelligence import import_vulnerability_intelligence
from pysfmea.vulnerability_workflow import (
    assess_vulnerability_workflow,
    verify_vulnerability_workflow,
    vulnerability_workflow_template,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "python_sfmea_corpus"


def _write_vulnerability_inputs(root: Path) -> tuple[Path, Path, Path, Path]:
    osv = root / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "vulns": [
                    {
                        "id": "PYSEC-2026-1",
                        "aliases": ["CVE-2026-12345"],
                        "published": "2026-08-01T00:00:00Z",
                        "modified": "2026-08-29T00:00:00Z",
                        "affected": [
                            {
                                "package": {
                                    "ecosystem": "PyPI",
                                    "name": "example",
                                    "purl": "pkg:pypi/example",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.0"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    kev = root / "kev.json"
    kev.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-12345",
                        "dateAdded": "2026-08-29",
                        "dueDate": "2026-09-10",
                        "knownRansomwareCampaignUse": "Unknown",
                        "requiredAction": "Apply remediation.",
                        "vendorProject": "Example",
                        "product": "example",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    epss = root / "epss.csv"
    epss.write_text(
        "#model_version:v5,score_date:2026-08-29\n"
        "cve,epss,percentile,date\n"
        "CVE-2026-12345,0.75,0.98,2026-08-29\n",
        encoding="utf-8",
    )
    sbom = root / "bom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
                "metadata": {"component": {"bom-ref": "root", "name": "app"}},
                "components": [
                    {
                        "bom-ref": "example-vulnerable",
                        "name": "example",
                        "version": "1.5",
                        "purl": "pkg:pypi/example@1.5",
                    },
                    {
                        "bom-ref": "example-fixed",
                        "name": "example",
                        "version": "2.1",
                        "purl": "pkg:pypi/example@2.1",
                    },
                ],
                "dependencies": [
                    {
                        "ref": "root",
                        "dependsOn": ["example-vulnerable", "example-fixed"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return osv, kev, epss, sbom


def test_direct_sfmea_benchmark_is_runnable_but_bundled_fixture_is_not_independent() -> (
    None
):
    value = run_sfmea_semantic_benchmark(
        CORPUS / "repository", CORPUS / "expected.json", authority="maintainer"
    )
    assert value["metrics"]["finding_precision"] == 1.0
    assert value["metrics"]["call_resolution_recall"] == 1.0
    assert value["metrics"]["control_precision"] == 1.0
    assert value["metrics"]["semantic_claim_recall"] == 1.0
    assert value["eligible_for_independent_claim"] is False
    assert (
        verify_sfmea_semantic_benchmark(
            value, repository=CORPUS / "repository", corpus=CORPUS / "expected.json"
        )["valid"]
        is True
    )
    Draft202012Validator(schema_document("sfmea-semantic-benchmark")).validate(value)


def test_version_applicability_and_lifecycle_are_distinct_governed_stages(
    tmp_path: Path,
) -> None:
    osv, kev, epss, sbom = _write_vulnerability_inputs(tmp_path)
    intelligence = import_vulnerability_intelligence(
        osv=osv,
        kev=kev,
        epss=epss,
        authority="feed-curator",
        observed_at="2026-08-30T00:00:00+00:00",
    )
    assert (
        intelligence["records"][0]["advisories"][0]["modified"]
        == "2026-08-29T00:00:00Z"
    )
    applicability = vulnerability_applicability(
        intelligence, sbom, authority="resolver-operator"
    )
    states = {
        item["component"]["bom_ref"]: item["state"] for item in applicability["results"]
    }
    assert states == {
        "example-fixed": "not_affected",
        "example-vulnerable": "affected",
    }
    assert verify_vulnerability_applicability(applicability)["valid"] is True
    Draft202012Validator(schema_document("vulnerability-applicability")).validate(
        applicability
    )

    template = vulnerability_workflow_template(
        applicability, authority="product-security"
    )
    decisions = template["decisions"]
    for decision in decisions:
        decision["owner"] = "security-owner"
        decision["reviewer"] = "independent-reviewer"
        decision["rationale"] = "Evidence-backed disposition."
        decision["evidence_refs"] = ["evidence:resolver"]
        if decision["bom_ref"] == "example-fixed":
            decision["vex_state"] = "not_affected"
        else:
            decision["reachability"] = "reachable"
            decision["exposure"] = "exposed"
            decision["safety_impact"] = "significant"
            decision["ssvc_decision"] = "Act"
            decision["remediation"] = "planned"
    workflow = assess_vulnerability_workflow(
        applicability, decisions, authority="product-security"
    )
    stages = {item["bom_ref"]: item["stage"] for item in workflow["records"]}
    assert stages["example-fixed"] == "version_not_affected"
    assert stages["example-vulnerable"] == "verification"
    assert workflow["summary"]["blocked"] == 1
    assert verify_vulnerability_workflow(workflow)["valid"] is True
    Draft202012Validator(schema_document("vulnerability-workflow")).validate(workflow)


def test_test_dossier_projects_every_active_obligation_with_techniques_and_keywords() -> (
    None
):
    analysis = scan_repository(CORPUS / "repository")
    value = generate_test_dossier(analysis, authority="test-authority")
    assert value["completion"]["planned"] == len(analysis["assurance"]["obligations"])
    assert value["test_cases"]
    first = value["test_cases"][0]
    assert first["techniques"]
    assert len(first["keyword_layer"]) == 5
    assert first["oracle_basis"]
    assert verify_test_dossier(value, analysis=analysis)["valid"] is True
    Draft202012Validator(schema_document("test-dossier")).validate(value)


def test_samate_assessment_reconciles_confusion_localization_and_uncertainty() -> None:
    source = samate_source_template(authority="protocol-owner")
    source.pop("content_sha256")
    source["capability_claim"]["weakness_classes"] = ["CWE-79"]
    source["capability_claim"]["environment"] = "controlled OCI runner"
    source["test_plan"].update(
        {
            "suite_id": "suite-1",
            "suite_revision": "revision-1",
            "suite_sha256": "1" * 64,
            "tool_version": "0.72.0",
            "tool_sha256": "2" * 64,
            "normalization_policy_ref": "evidence:normalization",
            "exclusion_policy": "no post-execution exclusions",
            "pre_registration_ref": "evidence:preregistration",
        }
    )
    source["governance"] = {
        "protocol_owner": "protocol-owner",
        "execution_operator": "operator",
        "label_authority": "labeler",
        "approval_authority": "approver",
        "independence_basis": "Separate organizational roles.",
    }
    common = {
        "weakness_id": "CWE-79",
        "expected_locations": ["app.py:10"],
        "reported_locations": ["app.py:10"],
        "excluded": False,
        "exclusion_rationale": "",
        "input_evidence_ref": "evidence:input",
        "label_evidence_ref": "evidence:label",
        "output_evidence_ref": "evidence:output",
    }
    source["cases"] = [
        {
            "id": "positive",
            "expected_label": "positive",
            "predicted_label": "positive",
            **common,
        },
        {
            "id": "negative",
            "expected_label": "negative",
            "predicted_label": "negative",
            **common,
        },
    ]
    assessment = samate_assessment(seal(source))
    assert assessment["metrics"]["true_positive"] == 1
    assert assessment["metrics"]["true_negative"] == 1
    assert assessment["metrics"]["positive_localization_rate"] == 1.0
    assert assessment["metrics"]["recall_95_percent_wilson"] is not None
    assert assessment["eligible_for_external_conclusion"] is True
    Draft202012Validator(schema_document("samate-assessment")).validate(assessment)


def test_testing_and_nasa_living_fmea_profiles_are_present() -> None:
    identifiers = {item["id"] for item in standards_catalog()["profiles"]}
    assert {
        "iso-29119-1-2022",
        "iso-29119-5-2024",
        "iso-29119-6-2021",
        "nasa-gsfc-hdbk-8004",
        "iso-29119-11-2020",
    } <= identifiers
    assert len(identifiers) == 144


def test_clusterfuzzlite_artifacts_are_exactly_inventoried_and_rebound(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    (artifact_root / "coverage").mkdir(parents=True)
    (artifact_root / "crashes").mkdir()
    (artifact_root / "coverage" / "index.html").write_text("coverage", encoding="utf-8")
    (artifact_root / "crashes" / "input-1").write_bytes(b"crash")
    (artifact_root / "results.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "crash"}]}]}),
        encoding="utf-8",
    )
    value = import_clusterfuzzlite_intake(
        artifact_root,
        authority="fuzz-evidence-owner",
        repository="owner/project-py-sfmea",
        revision="a" * 40,
        run_id="1234",
        run_attempt=1,
        workflow="ClusterFuzzLite",
        job="fuzz",
        event="pull_request",
        mode="code-change",
        sanitizer="address",
        action_sha="b" * 40,
        run_url="https://github.example/actions/runs/1234",
    )
    assert value["artifact_set"]["files"] == 3
    assert value["artifact_set"]["sarif_results"] == 1
    assert value["campaign_projection"]["requires_operator_completion"] is True
    assert (
        verify_clusterfuzzlite_intake(value, artifact_root=artifact_root)["valid"]
        is True
    )
    Draft202012Validator(schema_document("clusterfuzzlite-intake")).validate(value)
    (artifact_root / "crashes" / "input-1").write_bytes(b"changed")
    assert (
        verify_clusterfuzzlite_intake(value, artifact_root=artifact_root)["valid"]
        is False
    )

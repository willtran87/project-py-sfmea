from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.cli import main
from pysfmea.integrity import canonical_json_sha256
from pysfmea.test_generation_campaign_plan import (
    create_test_generation_campaign_plan,
    verify_test_generation_campaign_plan,
)


def _corpus() -> dict:
    return {
        "format": "pysfmea-test-generation-quality-corpus-3",
        "name": "pre-outcome campaign",
        "subject": {
            "provider": "recorded",
            "model": "offline",
            "prompt_version": "v1",
        },
        "governance": {
            "independent": True,
            "labeled_by": "lab",
            "reviewed_by": "reviewer",
            "review_date": "2026-08-26",
            "selection_method": "stratified",
            "representativeness_rationale": "representative claims require external review",
            "selection_frozen_at": "2020-01-01T00:00:00+00:00",
            "outcomes_observed_at": "2099-01-01T00:00:00+00:00",
        },
        "policy": {
            "min_samples": 1,
            "min_proposed_samples": 1,
            "min_refused_samples": 1,
            "min_decision_accuracy": 0.8,
            "min_valid_proposal_rate": 0.8,
            "min_execution_pass_rate": 0.8,
            "min_stimulus_observed_rate": 0.8,
            "min_criteria_pass_rate": 0.8,
            "min_fault_detection_rate": 0.8,
            "min_reviewer_acceptance_rate": 0.8,
            "max_unsafe_change_rate": 0.0,
            "min_repositories": 1,
            "min_frameworks": 1,
            "min_domains": 1,
            "min_fault_categories": 1,
            "min_samples_per_repository": 1,
            "min_samples_per_framework": 1,
            "min_samples_per_domain": 1,
            "require_decision_balance_per_repository": False,
            "max_single_repository_fraction": 1.0,
        },
        "samples": [
            {
                "id": "S-1",
                "expected_decision": "proposed",
                "repository_id": "repo-a",
                "frameworks": ["pytest"],
                "domains": ["workflow"],
                "fault_category": "timeout",
                "artifacts": {
                    "analysis": "analysis.json",
                    "proposal": "proposal.json",
                    "application_receipt": "receipt.json",
                    "fault_detection": "fault.json",
                },
            }
        ],
    }


class CampaignPlanTests(unittest.TestCase):
    def test_plan_binds_pre_outcome_design_and_reconciles_chronology(self) -> None:
        corpus = _corpus()
        plan = create_test_generation_campaign_plan(
            corpus, producer="qualification-runner"
        )
        result = verify_test_generation_campaign_plan(plan, corpus)
        self.assertTrue(result["valid"])
        self.assertNotIn("artifacts", plan["samples"][0])

    def test_design_and_content_tamper_are_detected(self) -> None:
        corpus = _corpus()
        plan = create_test_generation_campaign_plan(corpus, producer="runner")
        changed_corpus = copy.deepcopy(corpus)
        changed_corpus["samples"][0]["repository_id"] = "repo-b"
        self.assertFalse(
            verify_test_generation_campaign_plan(plan, changed_corpus)["valid"]
        )
        tampered = copy.deepcopy(plan)
        tampered["policy"]["min_repositories"] = 2
        result = verify_test_generation_campaign_plan(tampered)
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["content_integrity"])

        malformed = copy.deepcopy(plan)
        malformed["samples"][0]["expected_decision"] = "maybe"
        unsigned = {
            key: value for key, value in malformed.items() if key != "content_sha256"
        }
        malformed["content_sha256"] = canonical_json_sha256(unsigned)
        semantic = verify_test_generation_campaign_plan(malformed)
        self.assertFalse(semantic["valid"])
        self.assertTrue(semantic["checks"]["content_integrity"])
        self.assertFalse(semantic["checks"]["plan_contract"])

    def test_cli_seals_and_reconciles_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "corpus.json"
            plan_path = root / "plan.json"
            corpus_path.write_text(json.dumps(_corpus()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "assurance-test-campaign-plan",
                            str(corpus_path),
                            "--producer",
                            "qualification-runner",
                            "--output",
                            str(plan_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    main(
                        [
                            "assurance-test-campaign-plan-verify",
                            str(plan_path),
                            "--corpus",
                            str(corpus_path),
                            "--json",
                        ]
                    ),
                    0,
                )

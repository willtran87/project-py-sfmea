from __future__ import annotations

import copy
import unittest

from pysfmea.llm_quality import project_llm_quality_corpus


class LlmQualityMutationOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-3",
            "subject": {
                "provider": "approved-provider",
                "model": "model-1",
                "prompt_version": "discovery-v3",
            },
            "governance": {
                "independent": True,
                "labeled_by": "Benchmark Engineering Team",
                "reviewed_by": "Independent Assurance Team",
                "review_date": "2026-08-01",
                "selection_method": "Predeclared risk-stratified sample.",
                "representativeness_rationale": "Covers three risk and interface strata.",
            },
            "samples": [
                {
                    "id": "S-1",
                    "grounded": True,
                    "citations_correct": True,
                    "claim_count": 4,
                    "unsupported_claim_count": 0,
                },
                {
                    "id": "S-2",
                    "grounded": False,
                    "citations_correct": True,
                    "claim_count": 2,
                    "unsupported_claim_count": 1,
                },
            ],
        }

    def test_projection_recomputes_governed_counts_and_identity(self) -> None:
        result = project_llm_quality_corpus(
            self.corpus,
            expected_subject={
                **self.corpus["subject"],
                "producer": "Benchmark Engineering Team",
                "reviewer": "Independent Assurance Team",
            },
        )
        self.assertEqual(result.corpus_format, "pysfmea-llm-quality-corpus-3")
        self.assertTrue(result.subject_bound)
        self.assertTrue(result.review_governance_bound)
        self.assertTrue(result.independent_reviewed)
        self.assertEqual(result.sample_count, 2)
        self.assertEqual(result.grounded_sample_count, 1)
        self.assertEqual(result.citation_correct_sample_count, 2)
        self.assertEqual(result.claim_count, 6)
        self.assertEqual(result.unsupported_claim_count, 1)
        self.assertEqual(result.grounding, 0.5)
        self.assertEqual(result.citation_accuracy, 1.0)
        self.assertEqual(result.unsupported_claim_rate, 0.1667)
        self.assertEqual(len(result.evidence_fingerprint_sha256), 64)

    def test_governance_and_sample_contract_fail_closed(self) -> None:
        cases: list[tuple[str, object]] = []
        same_identity = copy.deepcopy(self.corpus)
        same_identity["governance"]["reviewed_by"] = "Benchmark Engineering Team"
        cases.append(("distinct", same_identity))
        future = copy.deepcopy(self.corpus)
        future["governance"]["review_date"] = "2999-01-01"
        cases.append(("future", future))
        placeholder = copy.deepcopy(self.corpus)
        placeholder["governance"]["selection_method"] = "Replace with method"
        cases.append(("placeholders", placeholder))
        duplicate = copy.deepcopy(self.corpus)
        duplicate["samples"][1]["id"] = " S-1 "
        cases.append(("unique", duplicate))
        invalid_count = copy.deepcopy(self.corpus)
        invalid_count["samples"][0]["unsupported_claim_count"] = 5
        cases.append(("claim counts", invalid_count))
        for message, corpus in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    project_llm_quality_corpus(corpus)


if __name__ == "__main__":
    unittest.main()

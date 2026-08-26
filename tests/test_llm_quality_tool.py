from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.llm_quality import project_llm_quality_corpus
from scripts.llm_quality_record import main, quality_record


class LlmQualityToolTests(unittest.TestCase):
    def test_semantic_projection_rejects_ambiguous_corpus_shapes(self) -> None:
        sample = {
            "id": "S-1",
            "grounded": True,
            "citations_correct": True,
            "claim_count": 1,
            "unsupported_claim_count": 0,
        }
        base = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "subject": {
                "provider": "provider",
                "model": "model",
                "prompt_version": "prompt",
            },
            "samples": [sample],
        }

        def mutated(change: object) -> object:
            corpus = copy.deepcopy(base)
            if callable(change):
                change(corpus)
                return corpus
            return change

        cases = (
            (None, "root must be an object"),
            (lambda value: value.update({"extra": True}), "unsupported fields"),
            (
                lambda value: value.update({"schema_version": "unknown"}),
                "schema_version",
            ),
            (lambda value: value.update({"subject": None}), "subject must exactly"),
            (lambda value: value.update({"samples": []}), "non-empty samples"),
            (
                lambda value: value["samples"][0].update({"extra": True}),
                "closed contract",
            ),
            (lambda value: value["samples"][0].update({"id": " "}), "bounded id"),
            (
                lambda value: value.update(
                    {
                        "samples": [
                            copy.deepcopy(sample),
                            {**copy.deepcopy(sample), "id": " S-1 "},
                        ]
                    }
                ),
                "unique after normalization",
            ),
            (
                lambda value: value["samples"][0].update({"grounded": 1}),
                "decisions must be booleans",
            ),
        )
        for mutation, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    project_llm_quality_corpus(mutated(mutation))

    def test_reviewed_samples_produce_program_compatible_metrics(self) -> None:
        corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "subject": {
                "provider": "approved-provider",
                "model": "model-1",
                "prompt_version": "pysfmea-discovery-v1",
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
        raw = json.dumps(corpus, separators=(",", ":")).encode()
        record = quality_record(
            corpus,
            raw=raw,
            evaluation_id="LLM-EVAL-1",
            provider="approved-provider",
            model="model-1",
            prompt_version="pysfmea-discovery-v1",
            producer="Model Evaluation Team",
            reviewer="Independent Assurance Team",
            artifact_path="evidence/llm-corpus.json",
        )
        self.assertEqual(record["sample_count"], 2)
        self.assertEqual(record["grounding"], 0.5)
        self.assertEqual(record["citation_accuracy"], 1.0)
        self.assertEqual(record["unsupported_claim_rate"], 0.1667)
        self.assertEqual(record["grounded_sample_count"], 1)
        self.assertEqual(record["citation_correct_sample_count"], 2)
        self.assertEqual(record["claim_count"], 6)
        self.assertEqual(record["unsupported_claim_count"], 1)
        self.assertEqual(record["corpus_format"], "pysfmea-llm-quality-corpus-2")
        self.assertTrue(record["subject_bound"])
        self.assertFalse(record["independent_reviewed"])
        self.assertEqual(len(record["corpus_sha256"]), 64)
        self.assertEqual(len(record["evidence_fingerprint_sha256"]), 64)
        self.assertEqual(record["corpus_artifact"]["sha256"], record["corpus_sha256"])

        repackaged = dict(corpus)
        repackaged["name"] = "Metadata does not create new evidence"
        repackaged["samples"] = list(reversed(corpus["samples"]))
        repackaged_record = quality_record(
            repackaged,
            raw=json.dumps(repackaged, indent=2).encode(),
            evaluation_id="LLM-EVAL-2",
            provider="approved-provider",
            model="model-1",
            prompt_version="pysfmea-discovery-v1",
            producer="Model Evaluation Team",
            reviewer="Independent Assurance Team",
        )
        self.assertNotEqual(
            record["corpus_sha256"], repackaged_record["corpus_sha256"]
        )
        self.assertEqual(
            record["evidence_fingerprint_sha256"],
            repackaged_record["evidence_fingerprint_sha256"],
        )

    def test_cli_binds_exact_labeled_corpus_artifact(self) -> None:
        corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "subject": {
                "provider": "provider",
                "model": "model",
                "prompt_version": "prompt",
            },
            "samples": [
                {
                    "id": "S-1",
                    "grounded": True,
                    "citations_correct": True,
                    "claim_count": 1,
                    "unsupported_claim_count": 0,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "corpus.json"
            output = root / "record.json"
            source.write_text(json.dumps(corpus) + "\n", encoding="utf-8")
            result = main(
                [
                    str(source),
                    "--id",
                    "LLM-CLI-1",
                    "--provider",
                    "provider",
                    "--model",
                    "model",
                    "--prompt-version",
                    "prompt",
                    "--producer",
                    "one",
                    "--reviewer",
                    "two",
                    "--artifact-path",
                    "evidence/corpus.json",
                    "-o",
                    str(output),
                ]
            )
            self.assertEqual(result, 0)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["corpus_artifact"]["path"], "evidence/corpus.json")
            self.assertEqual(
                record["corpus_artifact"]["sha256"], record["corpus_sha256"]
            )
            self.assertFalse(record["independent_reviewed"])

    def test_format_three_binds_review_governance_before_granting_credit(self) -> None:
        corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-3",
            "subject": {
                "provider": "provider",
                "model": "model",
                "prompt_version": "prompt",
            },
            "governance": {
                "independent": True,
                "labeled_by": "Model Evaluation Team",
                "reviewed_by": "Independent Assurance Team",
                "review_date": "2026-08-25",
                "selection_method": "Risk-stratified samples selected before model execution.",
                "representativeness_rationale": "Covers supported prompts and risk domains.",
            },
            "samples": [
                {
                    "id": "S-1",
                    "grounded": True,
                    "citations_correct": True,
                    "claim_count": 1,
                    "unsupported_claim_count": 0,
                }
            ],
        }
        record = quality_record(
            corpus,
            raw=json.dumps(corpus).encode(),
            evaluation_id="LLM-V3-1",
            provider="provider",
            model="model",
            prompt_version="prompt",
            producer="Model Evaluation Team",
            reviewer="Independent Assurance Team",
        )
        self.assertEqual(record["corpus_format"], "pysfmea-llm-quality-corpus-3")
        self.assertTrue(record["subject_bound"])
        self.assertTrue(record["independent_reviewed"])

        corpus["governance"]["reviewed_by"] = "Different Reviewer"
        with self.assertRaisesRegex(ValueError, "identities must match"):
            quality_record(
                corpus,
                raw=json.dumps(corpus).encode(),
                evaluation_id="LLM-V3-2",
                provider="provider",
                model="model",
                prompt_version="prompt",
                producer="Model Evaluation Team",
                reviewer="Independent Assurance Team",
            )

    def test_public_format_three_template_cannot_mint_review_credit(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        corpus = json.loads(
            (repository / "examples" / "llm-quality-corpus.template.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaisesRegex(ValueError, "placeholders must be replaced"):
            quality_record(
                corpus,
                raw=json.dumps(corpus).encode(),
                evaluation_id="LLM-TEMPLATE-1",
                provider="replace-provider",
                model="replace-model",
                prompt_version="replace-prompt-version",
                producer="Replace with labeling team identity",
                reviewer="Replace with independent review authority",
            )

    def test_invalid_claims_and_nonindependent_review_fail_closed(self) -> None:
        corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "subject": {
                "provider": "provider",
                "model": "model",
                "prompt_version": "prompt",
            },
            "samples": [
                {
                    "id": "S-1",
                    "grounded": True,
                    "citations_correct": True,
                    "claim_count": 1,
                    "unsupported_claim_count": 2,
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "claim counts"):
            quality_record(
                corpus,
                raw=b"{}",
                evaluation_id="LLM-1",
                provider="provider",
                model="model",
                prompt_version="prompt",
                producer="one",
                reviewer="two",
            )
        corpus["samples"][0]["unsupported_claim_count"] = 0
        with self.assertRaisesRegex(ValueError, "distinct producer"):
            quality_record(
                corpus,
                raw=b"{}",
                evaluation_id="LLM-1",
                provider="provider",
                model="model",
                prompt_version="prompt",
                producer="same",
                reviewer="Same",
            )

    def test_subject_mismatch_is_rejected_and_v1_remains_explicitly_legacy(
        self,
    ) -> None:
        corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "subject": {
                "provider": "different-provider",
                "model": "model",
                "prompt_version": "prompt",
            },
            "samples": [
                {
                    "id": "S-1",
                    "grounded": True,
                    "citations_correct": True,
                    "claim_count": 1,
                    "unsupported_claim_count": 0,
                }
            ],
        }
        raw = json.dumps(corpus).encode()
        with self.assertRaisesRegex(ValueError, "subject must exactly match"):
            quality_record(
                corpus,
                raw=raw,
                evaluation_id="LLM-SUBJECT-1",
                provider="provider",
                model="model",
                prompt_version="prompt",
                producer="one",
                reviewer="two",
            )

        corpus["schema_version"] = "pysfmea-llm-quality-corpus-1"
        corpus.pop("subject")
        legacy = quality_record(
            corpus,
            raw=json.dumps(corpus).encode(),
            evaluation_id="LLM-LEGACY-1",
            provider="provider",
            model="model",
            prompt_version="prompt",
            producer="one",
            reviewer="two",
        )
        self.assertEqual(legacy["corpus_format"], "pysfmea-llm-quality-corpus-1")
        self.assertFalse(legacy["subject_bound"])


if __name__ == "__main__":
    unittest.main()

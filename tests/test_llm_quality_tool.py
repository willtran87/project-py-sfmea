from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.llm_quality_record import main, quality_record


class LlmQualityToolTests(unittest.TestCase):
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
        self.assertEqual(len(record["corpus_sha256"]), 64)
        self.assertEqual(record["corpus_artifact"]["sha256"], record["corpus_sha256"])

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

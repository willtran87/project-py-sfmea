from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from os import stat_result
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea import discovery
from pysfmea.cli import main
from pysfmea.discovery import evaluate_candidates, load_evaluation_spec
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis


class EvaluationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def perform(value):\n    return value\n", encoding="utf-8"
        )
        self.analysis = scan_repository(self.root)
        first = self.analysis["items"][0]
        self.spec = {
            "schema_version": "pysfmea-golden-corpus-1",
            "name": "Boundary corpus",
            "purpose": "Exercise exact candidate matching.",
            "scope": ["service.py:*"],
            "cases": [
                {
                    "source": first["source"]["path"],
                    "component": first["component"]["qualname"],
                    "rule_id": first["scanner"]["rule_id"],
                }
            ],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_spec(self, name: str = "expected.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(self.spec), encoding="utf-8")
        return path

    def test_loaded_corpus_is_strict_content_addressed_and_reproducible(self) -> None:
        path = self._write_spec()
        loaded = load_evaluation_spec(path)
        first = evaluate_candidates(self.analysis, loaded)
        second = evaluate_candidates(self.analysis, copy.deepcopy(loaded))
        self.assertEqual(first, second)
        self.assertEqual(first["format"], "pysfmea-evaluation-result-1")
        self.assertEqual(first["corpus"]["format"], "pysfmea-golden-corpus-1")
        self.assertEqual(first["corpus"]["case_count"], 1)
        self.assertEqual(first["corpus"]["call_case_count"], 0)
        self.assertEqual(len(first["corpus"]["content_sha256"]), 64)
        self.assertEqual(first["matched"], 1)
        self.assertFalse(first["call_resolution"]["enabled"])

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["evaluate", str(analysis_path), str(path), "--json"])
        cli_result = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, int(bool(cli_result["unexpected"])))
        self.assertEqual(cli_result["corpus"], first["corpus"])

    def test_file_loader_rejects_unsafe_or_malformed_inputs(self) -> None:
        directory = self.root / "directory"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            load_evaluation_spec(directory)

        invalid_utf8 = self.root / "invalid.json"
        invalid_utf8.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
            load_evaluation_spec(invalid_utf8)

        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"cases":[],"cases":[]}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            load_evaluation_spec(duplicate)

        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text('{"cases":[],"score":NaN}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            load_evaluation_spec(nonfinite)

        valid = self._write_spec("oversized.json")
        with patch("pysfmea.discovery.MAX_EVALUATION_FILE_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                load_evaluation_spec(valid)

    def test_file_loader_rejects_links(self) -> None:
        target = self._write_spec("target.json")
        linked = self.root / "linked.json"
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            load_evaluation_spec(linked)

    def test_file_loader_rejects_opened_identity_changes(self) -> None:
        target = self._write_spec("target.json")
        original_fstat = discovery.os.fstat
        calls = 0

        def changed_fstat(descriptor: int) -> stat_result:
            nonlocal calls
            observed = original_fstat(descriptor)
            calls += 1
            if calls == 1:
                return observed
            values = list(observed)
            values[6] += 1
            return stat_result(values)

        with patch("pysfmea.discovery.os.fstat", side_effect=changed_fstat):
            with self.assertRaisesRegex(ValueError, "changed while"):
                load_evaluation_spec(target)

    def test_json_shape_and_contract_limits_fail_closed(self) -> None:
        deep: dict[str, object] = {"cases": []}
        cursor = deep
        for _ in range(25):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child
        deep_path = self.root / "deep.json"
        deep_path.write_text(json.dumps(deep), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "depth limit"):
            load_evaluation_spec(deep_path)

        valid = self._write_spec("nodes.json")
        with patch("pysfmea.discovery.MAX_EVALUATION_JSON_NODES", 5):
            with self.assertRaisesRegex(ValueError, "node limit"):
                load_evaluation_spec(valid)

        for invalid, message in (
            ({**self.spec, "decision": "pass"}, "unsupported fields"),
            (
                {**self.spec, "cases": [{**self.spec["cases"][0], "note": "x"}]},
                "case 1 contains unsupported fields",
            ),
            (
                {**self.spec, "cases": [{**self.spec["cases"][0], "rule_id": 1}]},
                "fields must be strings",
            ),
            ({**self.spec, "scope": ["service.py:*", "service.py:*"]}, "duplicate"),
            ({**self.spec, "call_cases": "invalid"}, "call_cases"),
            (
                {
                    **self.spec,
                    "call_cases": [
                        {
                            "source": "service.py",
                            "component": "perform",
                            "raw_reference": "value",
                            "reference": "value",
                            "resolution": "lexical_name",
                            "candidate_confidence": "certain",
                            "line": 1,
                            "order": 0,
                            "awaited": False,
                            "control_context": [],
                        }
                    ],
                },
                "candidate_confidence",
            ),
            (
                {
                    **self.spec,
                    "call_cases": [
                        {
                            "source": "service.py",
                            "component": "perform",
                            "raw_reference": "value",
                            "reference": "value",
                            "resolution": "lexical_name",
                            "candidate_confidence": "",
                            "line": -1,
                            "order": 0,
                            "awaited": False,
                            "control_context": [],
                        }
                    ],
                },
                "line must be a non-negative integer",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    evaluate_candidates(self.analysis, invalid)

        with patch("pysfmea.discovery.MAX_EVALUATION_CASES", 0):
            with self.assertRaisesRegex(ValueError, "record limit"):
                evaluate_candidates(self.analysis, self.spec)
        with patch("pysfmea.discovery.MAX_EVALUATION_CANDIDATES", 0):
            with self.assertRaisesRegex(ValueError, "active evaluation candidates"):
                evaluate_candidates(self.analysis, self.spec)


if __name__ == "__main__":
    unittest.main()

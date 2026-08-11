from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea import report
from pysfmea.assurance import export_assurance_register
from pysfmea.manifest import current_audit_manifest
from pysfmea.report import (
    MAX_ARCHIVE_FILE_BYTES,
    _portable_analysis_snapshot,
    _projection_snapshot,
    analysis_state_sha256,
    export_review_package,
)
from pysfmea.scanner import scan_repository
from pysfmea.sfta import build_sfta
from pysfmea.store import (
    MAX_ANALYSIS_BYTES,
    MAX_ANALYSIS_JSON_NODES,
    AnalysisRevisionConflictError,
    analysis_file_sha256,
    load_analysis,
    save_analysis,
    update_item_review,
)


class StoreTests(unittest.TestCase):
    def test_package_read_only_projections_do_not_mutate_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            original = copy.deepcopy(analysis)

            build_sfta(analysis)
            current_audit_manifest(analysis)

            self.assertEqual(analysis, original)

    def test_review_projection_snapshot_isolates_assurance_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            analysis["assurance"] = {"malformed": True}
            original = copy.deepcopy(analysis)

            snapshot = _projection_snapshot(analysis)
            export_assurance_register(snapshot, root / "assurance.csv", format="csv")

            self.assertEqual(analysis, original)

    def test_portable_snapshot_redacts_copy_on_write_branches(self) -> None:
        analysis = {
            "project": {
                "root": "C:/work/repository",
                "settings": {
                    "config_file": "C:/work/repository/sfmea.toml",
                    "coverage_json": "C:/work/repository/coverage.json",
                },
            },
            "run_manifest": {
                "repository": {"root": "C:/work/repository"},
                "manifest_sha256": "source-digest",
            },
            "context": {"analysis": {"guidance_packs": ["C:/packs/team.json"]}},
            "runtime_evidence": {
                "imports": [{"source": "C:/work/repository/trace.json"}]
            },
            "history": [
                {
                    "event": "runtime_trace_import",
                    "source": "C:/work/repository/history.json",
                }
            ],
            "summary": {"assurance": {"active_obligations": 1}},
            "assurance": {
                "executions": [
                    {
                        "id": "EX-1",
                        "repository": {"root": "C:/work/repository"},
                        "evidence_directory": "C:/evidence",
                        "sandbox": {"engine_path": "C:/tools/docker.exe"},
                        "command_argv": [
                            "C:/work/repository/run.py",
                            "C:/evidence/result.json",
                        ],
                    }
                ]
            },
        }
        original = copy.deepcopy(analysis)

        portable = _portable_analysis_snapshot(analysis)

        self.assertEqual(analysis, original)
        self.assertEqual(portable["project"]["root"], ".")
        self.assertEqual(portable["project"]["settings"]["config_file"], "sfmea.toml")
        self.assertEqual(portable["run_manifest"]["repository"]["root"], ".")
        self.assertEqual(
            portable["context"]["analysis"]["guidance_packs"], ["team.json"]
        )
        self.assertEqual(portable["runtime_evidence"]["imports"][0]["source"], "trace.json")
        self.assertEqual(portable["history"][0]["source"], "history.json")
        execution = portable["assurance"]["executions"][0]
        self.assertEqual(execution["repository"]["root"], ".")
        self.assertEqual(execution["evidence_directory"], "external-evidence/EX-1")
        self.assertEqual(execution["sandbox"]["engine_path"], "docker.exe")
        self.assertEqual(
            execution["command_argv"],
            ["./run.py", "external-evidence/EX-1/result.json"],
        )

    def test_analysis_size_contract_matches_package_verification(self) -> None:
        self.assertEqual(MAX_ANALYSIS_BYTES, MAX_ARCHIVE_FILE_BYTES)
        self.assertEqual(MAX_ANALYSIS_JSON_NODES, report.MAX_ANALYSIS_JSON_NODES)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            analysis["sfta"] = {"stale": "must not be packaged"}
            package = export_review_package(analysis, root / "package")
            raw = (package / "analysis.json").read_text(encoding="utf-8")
            snapshot = json.loads(raw)
            self.assertNotIn("stale", snapshot["sfta"])
            self.assertEqual(
                raw,
                json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n",
            )

    def test_portable_package_preserves_unchanged_sfta_provenance_for_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            source = root / "analysis.json"
            analysis = scan_repository(root)
            analysis["sfta"]["generated_at"] = "2000-01-01T00:00:00+00:00"
            save_analysis(source, analysis)
            persisted = load_analysis(source)

            package = export_review_package(persisted, root / "package", portable=True)
            manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(
                manifest["analysis_state_sha256"],
                analysis_state_sha256(load_analysis(source), portable=True),
            )
            self.assertEqual(
                json.loads((package / "analysis.json").read_text(encoding="utf-8"))["sfta"][
                    "generated_at"
                ],
                "2000-01-01T00:00:00+00:00",
            )

    def test_compressed_analysis_is_deterministic_bounded_and_transparent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            first = root / "analysis-a.json.gz"
            second = root / "analysis-b.json.gz"
            save_analysis(first, analysis, compact=True)
            save_analysis(second, analysis, compact=True)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(load_analysis(first), load_analysis(second))
            self.assertLess(first.stat().st_size, len(json.dumps(analysis).encode("utf-8")))

            first.write_bytes(b"\x1f\x8bnot-a-valid-stream")
            with self.assertRaisesRegex(ValueError, "valid gzip stream"):
                load_analysis(first)

    def test_analysis_ingestion_is_bounded_identity_safe_and_shape_limited(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))

            with mock.patch("pysfmea.store.MAX_ANALYSIS_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "10-byte import limit"):
                    load_analysis(path)
                with self.assertRaisesRegex(ValueError, "10-byte hash limit"):
                    analysis_file_sha256(path)

            path.write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 JSON"):
                load_analysis(path)
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 JSON"):
                load_analysis(path)
            path.write_text(
                '{"schema_version":"0.6","schema_version":"0.6"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate object key"):
                load_analysis(path)
            path.write_text(
                '{"schema_version":"0.6","value":NaN}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-finite number"):
                load_analysis(path)

            path.write_text('{"a":{"b":{"c":1}}}', encoding="utf-8")
            with mock.patch("pysfmea.store.MAX_ANALYSIS_JSON_DEPTH", 2):
                with self.assertRaisesRegex(ValueError, "2-level depth limit"):
                    load_analysis(path)
            path.write_text('{"a":[1,2]}', encoding="utf-8")
            with mock.patch("pysfmea.store.MAX_ANALYSIS_JSON_NODES", 2):
                with self.assertRaisesRegex(ValueError, "2-node limit"):
                    load_analysis(path)

            directory = root / "analysis-directory"
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
                load_analysis(directory)

            path.write_text('{"schema_version":"0.6"}', encoding="utf-8")
            with mock.patch("pysfmea.store.Path.is_symlink", return_value=True):
                with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
                    load_analysis(path)
            with mock.patch("pysfmea.store.os.path.samestat", return_value=False):
                with self.assertRaisesRegex(ValueError, "changed during safe open"):
                    load_analysis(path)
            with mock.patch(
                "pysfmea.store.os.open",
                side_effect=PermissionError("sensitive host detail"),
            ):
                with self.assertRaisesRegex(PermissionError, "could not be read safely") as error:
                    load_analysis(path)
            self.assertNotIn("sensitive host detail", str(error.exception))

    def test_analysis_publication_is_bounded_race_safe_and_prior_preserving(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            path = root / "analysis.json"
            save_analysis(path, analysis)
            prior = path.read_bytes()

            bounded_output = root / "bounded-output.json"
            with mock.patch("pysfmea.store.MAX_ANALYSIS_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "10-byte output limit"):
                    save_analysis(bounded_output, analysis)
            self.assertFalse(bounded_output.exists())
            self.assertEqual(
                list(root.glob(f".{bounded_output.name}.*.tmp")),
                [],
            )

            with mock.patch("pysfmea.store.MAX_ANALYSIS_JSON_NODES", 1):
                with self.assertRaisesRegex(ValueError, "1-node limit"):
                    save_analysis(path, analysis)
            self.assertEqual(path.read_bytes(), prior)

            analysis["invalid_nonfinite"] = float("nan")
            with self.assertRaisesRegex(ValueError, "Out of range float values"):
                save_analysis(path, analysis)
            analysis.pop("invalid_nonfinite")
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(root.glob(f".{path.name}.*.tmp")), [])

            directory = root / "destination-directory"
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, "regular file path"):
                save_analysis(directory, analysis)
            with mock.patch("pysfmea.store.Path.is_symlink", return_value=True):
                with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                    save_analysis(path, analysis)

            with mock.patch(
                "pysfmea.store.os.replace",
                side_effect=OSError("injected publication failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected publication failure"):
                    save_analysis(path, analysis)
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(root.glob(f".{path.name}.*.tmp")), [])

            with mock.patch(
                "pysfmea.store.os.path.samestat",
                side_effect=[True, True, True, False],
            ):
                with self.assertRaisesRegex(
                    AnalysisRevisionConflictError, "changed before atomic replacement"
                ):
                    save_analysis(path, analysis)
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(root.glob(f".{path.name}.*.tmp")), [])

    def test_atomic_save_refuses_to_replace_a_newer_disk_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            original = scan_repository(root)
            save_analysis(path, original)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()

            newer = load_analysis(path)
            newer["project"]["name"] = "newer external revision"
            save_analysis(path, newer)
            newer_bytes = path.read_bytes()

            original["project"]["name"] = "stale reviewer revision"
            with self.assertRaises(AnalysisRevisionConflictError):
                save_analysis(path, original, expected_sha256=expected)

            self.assertEqual(path.read_bytes(), newer_bytes)

    def test_loading_preserves_stored_sfta_and_canonical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            first_bytes = path.read_bytes()

            first = load_analysis(path)
            second = load_analysis(path)

            self.assertEqual(first["sfta"]["generated_at"], second["sfta"]["generated_at"])
            self.assertEqual(
                analysis_state_sha256(first),
                analysis_state_sha256(second),
            )
            with (
                mock.patch(
                    "pysfmea.assurance.utc_now", return_value="2099-01-01T00:00:00+00:00"
                ),
                mock.patch(
                    "pysfmea.sfta.utc_now", return_value="2099-01-01T00:00:00+00:00"
                ),
                mock.patch(
                    "pysfmea.store.utc_now", return_value="2099-01-01T00:00:00+00:00"
                ),
            ):
                save_analysis(path, first)
            self.assertEqual(path.read_bytes(), first_bytes)

            first["items"][0]["review"]["notes"] = "A substantive governed change."
            with mock.patch(
                "pysfmea.store.utc_now", return_value="2099-01-01T00:00:00+00:00"
            ):
                save_analysis(path, first)
            changed = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                changed["summary"]["last_saved_at"],
                "2099-01-01T00:00:00+00:00",
            )

    def test_atomic_round_trip_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act(value):\n    return value\n", encoding="utf-8")
            analysis = scan_repository(root)
            item_id = analysis["items"][0]["id"]
            path = root / "analysis.json"
            save_analysis(path, analysis)
            loaded = load_analysis(path)
            update_item_review(
                loaded,
                item_id,
                {
                    "severity": "7",
                    "causes": "First cause\nSecond cause",
                    "status": "in_review",
                },
            )
            self.assertEqual(loaded["items"][0]["review"]["severity"], 7)
            self.assertEqual(loaded["items"][0]["review"]["causes"], ["First cause", "Second cause"])
            update_item_review(
                loaded,
                item_id,
                {"reviewer": "Jordan", "end_effect": "Incorrect system output."},
            )
            history = loaded["items"][0]["review_history"]
            self.assertEqual(history[-1]["reviewer"], "Jordan")
            self.assertIn("end_effect", history[-1]["changes"])
            history_size = len(history)
            update_item_review(
                loaded,
                item_id,
                {"reviewer": "Jordan", "end_effect": "Incorrect system output."},
            )
            self.assertEqual(len(loaded["items"][0]["review_history"]), history_size)
            update_item_review(
                loaded,
                item_id,
                {
                    "status": "closed",
                    "approved_by": "Safety lead",
                    "approval_date": "2026-08-03",
                },
            )
            update_item_review(
                loaded,
                item_id,
                {"end_effect": "A revised system consequence."},
            )
            self.assertEqual(loaded["items"][0]["review"]["status"], "in_review")
            self.assertEqual(loaded["items"][0]["review"]["approved_by"], "")
            loaded["items"][0]["review"]["status"] = "closed"
            loaded["items"][0]["review"]["approved_by"] = "Safety lead"
            loaded["items"][0]["review"]["approval_date"] = "2026-08-03"
            update_item_review(
                loaded,
                item_id,
                {"post_action_severity_rationale": "Residual consequence reassessed."},
            )
            self.assertEqual(loaded["items"][0]["review"]["status"], "in_review")
            self.assertEqual(loaded["items"][0]["review"]["approved_by"], "")
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"severity": 11})
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"target_date": "tomorrow"})
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"scanner": "not editable"})

    def test_migrates_legacy_analysis_without_losing_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            analysis["schema_version"] = "0.1"
            analysis.pop("generator", None)
            analysis.pop("system_context", None)
            analysis.pop("repository_inventory", None)
            analysis.pop("adapter_runs", None)
            item = analysis["items"][0]
            item["review"] = {"disposition": "accepted", "severity": 6}
            item.pop("source_change", None)
            path = root / "legacy.json"
            path.write_text(__import__("json").dumps(analysis), encoding="utf-8")

            loaded = load_analysis(path)
            migrated = loaded["items"][0]
            self.assertEqual(loaded["schema_version"], "0.6")
            self.assertEqual(loaded["generator"]["version"], "unknown")
            self.assertEqual(migrated["review"]["disposition"], "accepted")
            self.assertEqual(migrated["review"]["severity"], 6)
            self.assertIn("post_action_severity", migrated["review"])
            self.assertIn("required_safe_state", migrated["review"])
            self.assertEqual(
                loaded["repository_inventory"]["summary"]["by_status"],
                {"unresolved": 1},
            )
            self.assertEqual(
                loaded["adapter_runs"]["schema_version"],
                "pysfmea-adapter-run-ledger-1",
            )
            self.assertEqual(migrated["source_change"], "legacy")

    def test_malformed_persisted_analysis_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "analysis.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "root must be a JSON object"):
                load_analysis(path)

            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            analysis["items"][0]["review"]["causes"] = "not a list"
            path.write_text(json.dumps(analysis), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "review.causes"):
                load_analysis(path)

            analysis = scan_repository(root)
            analysis["context"]["quality"]["unreviewed_level"] = "ignore"
            path.write_text(json.dumps(analysis), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "quality.unreviewed_level"):
                load_analysis(path)

    def test_fractional_rating_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            with self.assertRaisesRegex(ValueError, "ratings"):
                update_item_review(analysis, analysis["items"][0]["id"], {"severity": 1.5})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from pysfmea.scan_cache import load_fact_cache, save_fact_cache
from pysfmea.scanner import scan_repository


class ScanCacheTests(unittest.TestCase):
    def test_persistent_cache_round_trip_reuses_only_exact_source_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "service.py"
            source.write_text(
                "def run(value):\n"
                "    try:\n"
                "        raise ValueError('failed')\n"
                "    except ValueError:\n"
                "        if value:\n"
                "            raise\n"
                "    finally:\n"
                "        return None\n\n"
                "def choose():\n"
                "    if False:\n"
                "        return missing()\n"
                "    return 1\n",
                encoding="utf-8",
            )
            cache: dict[str, Any] = {}
            cold: dict[str, Any] = {}
            cold_analysis = scan_repository(root, fact_cache=cache, telemetry=cold)
            self.assertEqual(cold["fact_cache"]["hits"], 0)
            self.assertEqual(cold["fact_cache"]["misses"], 1)
            self.assertEqual(
                cold_analysis["exception_propagation"]["finalizers"][0][
                    "terminal_kind"
                ],
                "return",
            )
            self.assertEqual(
                cold_analysis["exception_propagation"]["handlers"][0]["outcome_kinds"],
                ["fallthrough", "reraise"],
            )
            self.assertEqual(
                cold_analysis["static_control_flow_model"]["summary"][
                    "decisions_discovered"
                ],
                1,
            )

            cache_path = root / ".artifacts" / "facts.json"
            _path, published = save_fact_cache(cache_path, cache)
            self.assertEqual(published["status"], "published")
            loaded, accepted = load_fact_cache(cache_path)
            self.assertEqual(accepted["status"], "accepted")

            warm: dict[str, Any] = {}
            warm_analysis = scan_repository(root, fact_cache=loaded, telemetry=warm)
            self.assertEqual(warm["fact_cache"]["hits"], 1)
            self.assertEqual(warm["fact_cache"]["misses"], 0)
            self.assertEqual(
                warm_analysis["exception_propagation"],
                cold_analysis["exception_propagation"],
            )
            self.assertEqual(
                warm_analysis["static_control_flow_model"],
                cold_analysis["static_control_flow_model"],
            )

            source.write_text(
                "def run(value):\n    return value + 1\n", encoding="utf-8"
            )
            changed: dict[str, Any] = {}
            analysis = scan_repository(root, fact_cache=loaded, telemetry=changed)
            self.assertEqual(changed["fact_cache"]["hits"], 0)
            self.assertEqual(changed["fact_cache"]["misses"], 1)
            self.assertEqual(len(loaded["entries"]), 1)
            self.assertEqual(analysis["components"][0]["qualname"], "run")

    def test_tampered_cache_is_rejected_completely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def run():\n    return 1\n", encoding="utf-8"
            )
            cache: dict[str, Any] = {}
            scan_repository(root, fact_cache=cache)
            cache_path = root / "facts.json"
            save_fact_cache(cache_path, cache)
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            first_entry = next(iter(payload["entries"].values()))
            first_entry[0]["qualname"] = "forged"
            cache_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "content integrity"):
                load_fact_cache(cache_path)


if __name__ == "__main__":
    unittest.main()

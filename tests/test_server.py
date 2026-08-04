from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.scanner import scan_repository
from pysfmea.server import _ReviewState, _handler
from pysfmea.store import load_analysis, save_analysis, update_item_review


class ServerTests(unittest.TestCase):
    def test_review_api_updates_local_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n",
                encoding="utf-8",
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            state = _ReviewState(path)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(base + "/api/analysis") as response:
                    self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
                    self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
                    analysis = json.load(response)
                with urllib.request.urlopen(base + "/api/validation") as response:
                    validation = json.load(response)
                self.assertIn("counts", validation)
                item_id = analysis["items"][0]["id"]
                request = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=json.dumps(
                        {
                            "disposition": "accepted",
                            "end_effect": "A valid user is denied access.",
                            "severity": 6,
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(request) as response:
                    updated = json.load(response)
                self.assertEqual(updated["review"]["severity"], 6)
                cross_origin = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 2}',
                    headers={
                        "Content-Type": "application/json",
                        "Origin": "https://malicious.example",
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(cross_origin)
                self.assertEqual(rejected.exception.code, 400)
                external = load_analysis(path)
                update_item_review(external, item_id, {"notes": "External CLI update"})
                save_analysis(path, external)
                stale_request = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 5}',
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as conflict:
                    urllib.request.urlopen(stale_request)
                self.assertEqual(conflict.exception.code, 409)
                persisted = load_analysis(path)
                persisted_item = next(item for item in persisted["items"] if item["id"] == item_id)
                self.assertEqual(persisted_item["review"]["disposition"], "accepted")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_suggestion_api_materializes_an_unreviewed_item(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            component = analysis["components"][0]
            analysis["suggestions"] = [
                {
                    "id": "SUG-TEST",
                    "component_id": component["id"],
                    "component_reference": "service.py:authorize",
                    "origin": "machine_suggestion",
                    "status": "proposed",
                    "content": {
                        "failure_class": "security",
                        "guideword": "Bypass",
                        "failure_mode": "Authorization is bypassed.",
                        "trigger": "A crafted request is received.",
                        "causes": ["Authorization occurs after the operation."],
                        "local_effect": "The operation runs without authorization.",
                        "next_higher_effect": "The service permits unauthorized use.",
                        "possible_end_effects": ["Protected capability is exposed."],
                        "prevention_controls": [],
                        "detection_controls": [],
                        "recommended_actions": [],
                    },
                    "evidence_ids": [component["id"]],
                    "uncertainties": [],
                    "questions": [],
                    "confidence": "medium",
                    "provenance": {"provider": "test", "model": "test"},
                    "reviewer": "",
                    "review_rationale": "",
                    "materialized_item_id": "",
                    "history": [],
                }
            ]
            path = root / "analysis.json"
            save_analysis(path, analysis)
            state = _ReviewState(path)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                request = urllib.request.Request(
                    base + "/api/suggestions/SUG-TEST",
                    data=json.dumps(
                        {
                            "decision": "accept",
                            "reviewer": "Jordan",
                            "rationale": "Credible boundary failure.",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(request) as response:
                    suggestion = json.load(response)
                self.assertEqual(suggestion["status"], "accepted")
                persisted = load_analysis(path)
                item = next(
                    value
                    for value in persisted["items"]
                    if value["id"] == suggestion["materialized_item_id"]
                )
                self.assertEqual(item["review"]["disposition"], "unreviewed")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

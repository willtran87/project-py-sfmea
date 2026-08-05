from __future__ import annotations

import gzip
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.scanner import scan_repository
from pysfmea.server import (
    REVIEW_HTML,
    _handler,
    _review_analysis_view,
    _review_workspace_view,
    _ReviewState,
    serve_review,
)
from pysfmea.store import load_analysis, save_analysis, update_item_review


class ServerTests(unittest.TestCase):
    def test_reviewer_projection_omits_package_only_collections(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            analysis["sfta"] = {"large_tree": ["unused by reviewer"]}
            view = _review_analysis_view(analysis)

        self.assertEqual(view["format"], "pysfmea-review-analysis-view-1")
        self.assertEqual(view["items"], analysis["items"])
        self.assertNotIn("assurance", view)
        self.assertNotIn("sfta", view)
        self.assertIn("assurance", view["projection"]["omitted_sections"])
        self.assertIn("sfta", view["projection"]["omitted_sections"])
        self.assertEqual(
            set(view["components"][0]),
            {"id", "requirement_ids", "interface_ids"},
        )
        self.assertTrue(view["projection"]["governed_source_unchanged"])

        workspace = _review_workspace_view(analysis)
        self.assertEqual(workspace["format"], "pysfmea-review-workspace-1")
        self.assertEqual(workspace["analysis"], view)
        self.assertIn("counts", workspace["validation"])
        self.assertEqual(
            workspace["assurance"]["format"],
            "pysfmea-assurance-review-view-1",
        )

    def test_review_state_avoids_rehashing_an_unchanged_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            state = _ReviewState(path)
            with mock.patch("pysfmea.store.MAX_ANALYSIS_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "10-byte hash limit"):
                    state._fingerprint()
            with mock.patch.object(
                state, "_fingerprint", wraps=state._fingerprint
            ) as fingerprint:
                self.assertFalse(state.reload_if_changed())
                fingerprint.assert_not_called()

                save_analysis(path, load_analysis(path))
                self.assertFalse(state.reload_if_changed())
                fingerprint.assert_called_once()

    def test_review_state_discards_in_memory_changes_when_save_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            state = _ReviewState(path)
            item_id = state.analysis["items"][0]["id"]
            original_severity = state.analysis["items"][0]["review"]["severity"]
            original_etag = state.etag
            update_item_review(state.analysis, item_id, {"severity": 9})

            with mock.patch(
                "pysfmea.server.save_analysis", side_effect=OSError("disk full")
            ):
                with self.assertRaisesRegex(RuntimeError, "changes were discarded"):
                    state.commit()

            restored = next(
                item for item in state.analysis["items"] if item["id"] == item_id
            )
            self.assertEqual(restored["review"]["severity"], original_severity)
            self.assertEqual(state.etag, original_etag)

    def test_review_state_refuses_an_external_change_during_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            state = _ReviewState(path)
            item_id = state.analysis["items"][0]["id"]
            update_item_review(state.analysis, item_id, {"notes": "browser edit"})

            external = load_analysis(path)
            external["project"]["name"] = "newer external revision"
            save_analysis(path, external)

            with self.assertRaisesRegex(RuntimeError, "changed while"):
                state.commit()

            self.assertEqual(
                state.analysis["project"]["name"], "newer external revision"
            )
            restored = next(
                item for item in state.analysis["items"] if item["id"] == item_id
            )
            self.assertNotEqual(restored["review"]["notes"], "browser edit")

    def test_embedded_reviewer_javascript_is_valid(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        scripts = re.findall(r"<script>(.*?)</script>", REVIEW_HTML, flags=re.DOTALL)
        self.assertEqual(len(scripts), 1)
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "reviewer.js"
            script.write_text(scripts[0], encoding="utf-8")
            result = subprocess.run(
                [node, "--check", str(script)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Assurance plan", REVIEW_HTML)
        self.assertIn("progress.work_queue?.implementation_ready", REVIEW_HTML)
        self.assertIn("work: ${work.state", REVIEW_HTML)
        self.assertIn("Control model questions", REVIEW_HTML)
        self.assertIn("Cascade observation paths", REVIEW_HTML)
        self.assertIn("saveAssurancePlan", REVIEW_HTML)
        self.assertIn("'If-Match':state.revision", REVIEW_HTML)
        self.assertIn("Discard unsaved assurance-plan changes?", REVIEW_HTML)
        self.assertIn("fetch('/api/workspace')", REVIEW_HTML)
        self.assertIn("Could not load the governed analysis", REVIEW_HTML)
        self.assertIn("findingsByItem:new Map()", REVIEW_HTML)
        self.assertIn("state.itemErrors.get(x.id)||0", REVIEW_HTML)
        self.assertNotIn("filter(x=>x.item_id===id)", REVIEW_HTML)
        self.assertIn("url.searchParams.set('item',id)", REVIEW_HTML)
        self.assertIn('class="skip-link"', REVIEW_HTML)
        self.assertIn('for="search"', REVIEW_HTML)
        self.assertIn('id="listStatus" role="status"', REVIEW_HTML)
        self.assertIn('label for="${id}"', REVIEW_HTML)
        self.assertIn('id="saveState" role="status"', REVIEW_HTML)
        self.assertIn('aria-current="${isSelected', REVIEW_HTML)
        self.assertIn("el.dataset.invert==='true'", REVIEW_HTML)
        self.assertIn("async function refreshDerived(expectedRevision)", REVIEW_HTML)
        self.assertIn("async function applyItemMutation(item,revision)", REVIEW_HTML)
        self.assertIn("revisions.some(value=>value!==expectedRevision)", REVIEW_HTML)
        self.assertIn("await applyItemMutation(result,response.headers.get('ETag'))", REVIEW_HTML)
        self.assertIn("if(state.saving)return", REVIEW_HTML)
        self.assertIn("if(state.assuranceSaving)return", REVIEW_HTML)
        self.assertIn("if(state.adding)return", REVIEW_HTML)
        self.assertIn("if(state.suggestionSaving)return", REVIEW_HTML)
        self.assertIn('id="assuranceSaveState" role="status"', REVIEW_HTML)
        self.assertIn("finally{setFindingSaving(false);}", REVIEW_HTML)

    def test_review_server_refuses_a_non_loopback_bind(self) -> None:
        with self.assertRaisesRegex(ValueError, "local-only"):
            serve_review(
                "analysis-does-not-need-to-exist.json",
                host="0.0.0.0",
                open_browser=False,
            )

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
                    self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                    self.assertEqual(
                        response.headers["Cross-Origin-Resource-Policy"],
                        "same-origin",
                    )
                    revision = response.headers["ETag"]
                    analysis = json.load(response)
                rebound = urllib.request.Request(
                    base + "/api/analysis",
                    headers={"Host": "reviewer.attacker.example"},
                )
                with self.assertRaises(urllib.error.HTTPError) as misdirected:
                    urllib.request.urlopen(rebound)
                self.assertEqual(misdirected.exception.code, 421)
                with urllib.request.urlopen(base + "/api/validation") as response:
                    self.assertEqual(response.headers["ETag"], revision)
                    validation = json.load(response)
                with urllib.request.urlopen(base + "/api/reviewer") as response:
                    self.assertEqual(response.headers["ETag"], revision)
                    reviewer = json.load(response)
                with urllib.request.urlopen(base + "/api/workspace") as response:
                    self.assertEqual(response.headers["ETag"], revision)
                    workspace = json.load(response)
                self.assertIn("counts", validation)
                self.assertNotIn("assurance", reviewer)
                self.assertEqual(reviewer["items"][0]["id"], analysis["items"][0]["id"])
                self.assertEqual(workspace["analysis"], reviewer)
                self.assertEqual(
                    workspace["validation"]["counts"], validation["counts"]
                )
                self.assertEqual(
                    workspace["validation"]["findings"], validation["findings"]
                )
                item_id = analysis["items"][0]["id"]
                missing_precondition = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 5}',
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as required:
                    urllib.request.urlopen(missing_precondition)
                self.assertEqual(required.exception.code, 428)
                request = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=json.dumps(
                        {
                            "disposition": "accepted",
                            "end_effect": "A valid user is denied access.",
                            "severity": 6,
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with urllib.request.urlopen(request) as response:
                    current_revision = response.headers["ETag"]
                    updated = json.load(response)
                self.assertEqual(updated["review"]["severity"], 6)
                stale_tab = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 2}',
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as tab_conflict:
                    urllib.request.urlopen(stale_tab)
                self.assertEqual(tab_conflict.exception.code, 409)

                manual = urllib.request.Request(
                    base + "/api/items",
                    data=json.dumps(
                        {"component_id": analysis["components"][0]["id"]}
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": current_revision,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(manual) as response:
                    self.assertEqual(response.status, 201)
                    current_revision = response.headers["ETag"]
                    self.assertTrue(json.load(response)["id"])
                cross_origin = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 2}',
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": current_revision,
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
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": current_revision,
                    },
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

    def test_large_json_transport_uses_negotiated_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            analysis["items"][0]["review"]["notes"] = "transport coverage " * 400
            path = root / "analysis.json"
            save_analysis(path, analysis)
            state = _ReviewState(path)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                compressed_request = urllib.request.Request(
                    base + "/api/reviewer",
                    headers={"Accept-Encoding": "br, gzip;q=1"},
                )
                with urllib.request.urlopen(compressed_request) as response:
                    self.assertEqual(response.headers["Content-Encoding"], "gzip")
                    self.assertEqual(response.headers["Vary"], "Accept-Encoding")
                    self.assertTrue(response.headers["ETag"])
                    payload = json.loads(gzip.decompress(response.read()))
                self.assertEqual(payload["format"], "pysfmea-review-analysis-view-1")

                identity_request = urllib.request.Request(
                    base + "/api/reviewer",
                    headers={"Accept-Encoding": "gzip;q=0"},
                )
                with urllib.request.urlopen(identity_request) as response:
                    self.assertIsNone(response.headers["Content-Encoding"])
                    identity_payload = json.load(response)
                self.assertEqual(identity_payload["items"], payload["items"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_workspace_reports_and_recovers_from_an_unreadable_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def authorize(user):\n    return bool(user)\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))
            state = _ReviewState(path)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                item_id = state.analysis["items"][0]["id"]
                revision = state.etag
                path.write_text("{not valid json", encoding="utf-8")
                with self.assertRaises(urllib.error.HTTPError) as unavailable:
                    urllib.request.urlopen(base + "/api/workspace")
                self.assertEqual(unavailable.exception.code, 503)
                error = json.load(unavailable.exception)
                self.assertIn("analysis snapshot is unavailable", error["error"])

                mutation = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=b'{"severity": 6}',
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as blocked:
                    urllib.request.urlopen(mutation)
                self.assertEqual(blocked.exception.code, 503)
                mutation_error = json.load(blocked.exception)
                self.assertIn("temporarily unreadable", mutation_error["error"])

                save_analysis(path, state.analysis)
                with urllib.request.urlopen(base + "/api/workspace") as response:
                    self.assertEqual(response.status, 200)
                    workspace = json.load(response)
                self.assertEqual(workspace["format"], "pysfmea-review-workspace-1")
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
                with urllib.request.urlopen(base + "/api/analysis") as response:
                    revision = response.headers["ETag"]
                request = urllib.request.Request(
                    base + "/api/suggestions/SUG-TEST",
                    data=json.dumps(
                        {
                            "decision": "accept",
                            "reviewer": "Jordan",
                            "rationale": "Credible boundary failure.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
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

    def test_assurance_api_reviews_planning_without_claiming_verification(self) -> None:
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
                    revision = response.headers["ETag"]
                    analysis = json.load(response)
                with urllib.request.urlopen(base + "/api/assurance") as response:
                    self.assertEqual(response.headers["ETag"], revision)
                    before = json.load(response)
                self.assertEqual(before["total"], 0)

                item_id = analysis["items"][0]["id"]
                obligation_id = analysis["assurance"]["obligations"][0]["id"]
                premature = urllib.request.Request(
                    base + "/api/assurance/" + obligation_id,
                    data=json.dumps(
                        {
                            "status": "confirmed",
                            "reviewer": "Assurance Planner",
                            "rationale": "The finding has not been accepted.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(premature)
                self.assertEqual(rejected.exception.code, 400)

                accept = urllib.request.Request(
                    base + "/api/items/" + item_id,
                    data=json.dumps(
                        {
                            "disposition": "accepted",
                            "reviewer": "Finding Reviewer",
                            "disposition_rationale": "Credible failure condition.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with urllib.request.urlopen(accept) as response:
                    revision = response.headers["ETag"]
                with urllib.request.urlopen(base + "/api/assurance") as response:
                    self.assertEqual(response.headers["ETag"], revision)
                    view = json.load(response)
                self.assertEqual(view["total"], 1)
                self.assertEqual(view["obligations"][0]["id"], obligation_id)

                plan = urllib.request.Request(
                    base + "/api/assurance/" + obligation_id,
                    data=json.dumps(
                        {
                            "status": "verification_planned",
                            "reviewer": "Assurance Planner",
                            "owner": "Test Owner",
                            "rationale": "The obligation needs an off-nominal test.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with urllib.request.urlopen(plan) as response:
                    revision = response.headers["ETag"]
                    planned = json.load(response)
                self.assertEqual(planned["assurance_status"], "verification_planned")
                self.assertEqual(planned["review"]["owner"], "Test Owner")

                privileged = urllib.request.Request(
                    base + "/api/assurance/" + obligation_id,
                    data=json.dumps(
                        {
                            "status": "verified",
                            "reviewer": "Assurance Planner",
                            "rationale": "A test allegedly passed.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(privileged)
                self.assertEqual(rejected.exception.code, 400)

                external = load_analysis(path)
                update_item_review(external, item_id, {"notes": "External update"})
                save_analysis(path, external)
                stale = urllib.request.Request(
                    base + "/api/assurance/" + obligation_id,
                    data=json.dumps(
                        {
                            "status": "confirmed",
                            "reviewer": "Assurance Planner",
                            "rationale": "This write is stale.",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "If-Match": revision,
                    },
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as conflict:
                    urllib.request.urlopen(stale)
                self.assertEqual(conflict.exception.code, 409)

                persisted = load_analysis(path)
                obligation = next(
                    value
                    for value in persisted["assurance"]["obligations"]
                    if value["id"] == obligation_id
                )
                self.assertEqual(
                    obligation["assurance_status"], "verification_planned"
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

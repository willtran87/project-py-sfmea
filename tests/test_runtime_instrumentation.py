from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from pysfmea.runtime import import_runtime_trace
from pysfmea.runtime_instrumentation import RuntimeTraceRecorder
from pysfmea.scanner import scan_repository


class RuntimeTraceRecorderTests(unittest.TestCase):
    def test_nested_spans_export_and_import_with_complete_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def parent():\n    return child()\n\ndef child():\n    return 1\n",
                encoding="utf-8",
            )
            analysis = scan_repository(root)
            recorder = RuntimeTraceRecorder(
                "integration",
                "pytest",
                expected_components=["parent", "child"],
                expected_relationships=[("parent", "child")],
            )
            with recorder.span("parent"):
                with recorder.span("child", callsite_line=2):
                    pass
            trace = recorder.export(root / "trace.json")
            imported = import_runtime_trace(analysis, trace)
            self.assertEqual(
                imported["instrumentation"]["status"], "complete_declared_and_observed"
            )
            self.assertEqual(imported["dynamic_call_site_candidate_count"], 0)
            self.assertEqual(recorder.captured_span_count, 2)

    def test_sync_async_and_exception_decorators_preserve_behavior(self) -> None:
        recorder = RuntimeTraceRecorder(
            "decorators", "unittest", expected_components=["sync", "async", "fails"]
        )

        @recorder.trace("sync")
        def sync(value: int) -> int:
            return value + 1

        @recorder.trace("async")
        async def asynchronous(value: int) -> int:
            return value * 2

        @recorder.trace("fails")
        def fails() -> None:
            raise RuntimeError("expected")

        self.assertEqual(sync(2), 3)
        self.assertEqual(asyncio.run(asynchronous(4)), 8)
        with self.assertRaisesRegex(RuntimeError, "expected"):
            fails()
        document = recorder.document(declared_complete=False)
        self.assertEqual(len(document["spans"]), 3)
        statuses = {span["name"]: span["status"] for span in document["spans"]}
        self.assertEqual(statuses, {"sync": "ok", "async": "ok", "fails": "error"})

    def test_bounds_and_dropped_spans_are_explicit(self) -> None:
        recorder = RuntimeTraceRecorder(
            "bounded", "unittest", expected_components=["one"], max_spans=1
        )
        with recorder.span("one"):
            pass
        with recorder.span("one"):
            pass
        document = recorder.document()
        self.assertEqual(len(document["spans"]), 1)
        self.assertEqual(document["sfmea_instrumentation"]["dropped_spans"], 1)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            with recorder.span("one", callsite_line=0):
                pass

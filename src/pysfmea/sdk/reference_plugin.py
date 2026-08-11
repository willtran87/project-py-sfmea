"""Packaged dependency-free reference implementation of the process-plugin protocol."""

from __future__ import annotations

import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    if request.get("format") != "pysfmea-plugin-request-1":
        raise ValueError("unsupported request format")
    analysis = request.get("analysis", {})
    components = analysis.get("components", [])
    json.dump(
        {
            "format": "pysfmea-plugin-response-1",
            "plugin_id": request["plugin_id"],
            "observations": [
                {
                    "id": "reference-component-count",
                    "kind": "inventory_summary",
                    "subject_id": "project",
                    "message": (
                        f"The bounded request contains {len(components)} components."
                    ),
                    "evidence_ids": [
                        value.get("id", "")
                        for value in components[:10]
                        if value.get("id")
                    ],
                    "confidence": "high",
                    "properties": {"component_count": len(components)},
                }
            ],
        },
        sys.stdout,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

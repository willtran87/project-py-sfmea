"""Fail CI when critical typed policy modules fall below their own coverage floors."""

from __future__ import annotations

import json
import sys
from pathlib import Path

THRESHOLDS = {
    "architecture.py": 90.0,
    "assurance_planning.py": 95.0,
    "diagrams.py": 85.0,
    "fault_injection.py": 85.0,
    "guidance.py": 75.0,
    "html_report.py": 90.0,
    "integrity.py": 95.0,
    "interfaces.py": 90.0,
    "llm_quality.py": 90.0,
    "runtime.py": 90.0,
    "sandbox_policy.py": 85.0,
    "scanner.py": 80.0,
    "visuals.py": 80.0,
}


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    observed = {
        Path(name.replace("\\", "/")).name: float(record["summary"]["percent_covered"])
        for name, record in document.get("files", {}).items()
    }
    failures = []
    for name, minimum in THRESHOLDS.items():
        actual = observed.get(name)
        if actual is None or actual < minimum:
            failures.append(f"{name}: {actual if actual is not None else 'missing'} < {minimum}")
        else:
            print(f"{name}: {actual:.2f}% >= {minimum:.2f}%")
    if failures:
        print("Critical coverage ratchets failed: " + "; ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

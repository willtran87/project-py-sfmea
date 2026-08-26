"""Generate a deterministic, non-qualifying Python repository for scale testing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text

FORMAT = "pysfmea-generated-scale-corpus-1"
MAX_MODULES = 1_000
MAX_FUNCTIONS_PER_MODULE = 100


def _module_source(module_index: int, modules: int, functions: int) -> str:
    next_module = (module_index + 1) % modules
    lines = [
        '"""Deterministic generated scale fixture; not production or qualification evidence."""',
        "",
        "from __future__ import annotations",
        "",
    ]
    if modules > 1:
        lines.extend(
            [
                f"from scale_app import module_{next_module:04d}",
                "",
            ]
        )
    for function_index in range(functions):
        name = f"process_{module_index:04d}_{function_index:03d}"
        lines.extend(
            [
                f"def {name}(payload: dict[str, int], timeout: float = 1.0) -> int:",
                '    """Exercise validation, retry, timing, and internal-call analysis."""',
                "    if timeout <= 0:",
                '        raise TimeoutError("deadline exhausted")',
                "    if \"value\" not in payload:",
                '        raise ValueError("missing value")',
                "    result = payload[\"value\"]",
                "    for attempt in range(3):",
                "        try:",
                "            result += attempt",
                "            break",
                "        except TimeoutError:",
                "            if attempt == 2:",
                "                raise",
            ]
        )
        if modules > 1 and function_index == functions - 1:
            lines.append(
                f"    return result + module_{next_module:04d}.process_{next_module:04d}_000({{'value': result}}, timeout)"
            )
        elif function_index + 1 < functions:
            lines.append(
                f"    return result + process_{module_index:04d}_{function_index + 1:03d}({{'value': result}}, timeout)"
            )
        else:
            lines.append("    return result")
        lines.append("")
    return "\n".join(lines)


def generate_scale_corpus(
    destination: str | Path,
    *,
    modules: int,
    functions_per_module: int,
) -> dict[str, Any]:
    """Create one new empty destination and return content-addressed scale metadata."""

    if (
        not isinstance(modules, int)
        or isinstance(modules, bool)
        or not 1 <= modules <= MAX_MODULES
    ):
        raise ValueError(f"modules must be between 1 and {MAX_MODULES}")
    if (
        not isinstance(functions_per_module, int)
        or isinstance(functions_per_module, bool)
        or not 1 <= functions_per_module <= MAX_FUNCTIONS_PER_MODULE
    ):
        raise ValueError(
            f"functions_per_module must be between 1 and {MAX_FUNCTIONS_PER_MODULE}"
        )
    root = Path(destination).expanduser().resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("scale corpus destination must be absent or an empty directory")
    package = root / "scale_app"
    package.mkdir(parents=True, exist_ok=True)
    files: list[dict[str, Any]] = []

    def publish(relative: str, content: str) -> None:
        encoded = content.encode("utf-8")
        atomic_publish_text(root / relative, content, label="generated scale corpus file")
        files.append(
            {
                "path": relative,
                "bytes": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )

    publish("pyproject.toml", '[project]\nname = "pysfmea-scale-fixture"\nversion = "0.0.0"\n')
    publish("scale_app/__init__.py", '"""Generated scale fixture package."""\n')
    for module_index in range(modules):
        publish(
            f"scale_app/module_{module_index:04d}.py",
            _module_source(module_index, modules, functions_per_module),
        )
    identity = {
        "format": FORMAT,
        "generator": {
            "modules": modules,
            "functions_per_module": functions_per_module,
        },
        "expected": {
            "python_files": modules + 1,
            "declared_functions": modules * functions_per_module,
        },
        "files": files,
    }
    identity["corpus_sha256"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    identity["authority"] = (
        "deterministic_synthetic_scale_fixture_not_accuracy_or_real_world_qualification"
    )
    atomic_publish_text(
        root / "scale-corpus.json",
        json.dumps(identity, indent=2) + "\n",
        label="generated scale corpus manifest",
    )
    return identity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination")
    parser.add_argument("--modules", type=int, default=100)
    parser.add_argument("--functions-per-module", type=int, default=10)
    args = parser.parse_args(argv)
    result = generate_scale_corpus(
        args.destination,
        modules=args.modules,
        functions_per_module=args.functions_per_module,
    )
    print(Path(args.destination).resolve() / "scale-corpus.json")
    print(
        f"generated python_files={result['expected']['python_files']} "
        f"declared_functions={result['expected']['declared_functions']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Exercise integration failures that are hidden by a full development install."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_base_cli_does_not_require_optional_extras(tmp_path: Path) -> None:
    # A fresh interpreter prevents imports cached by other tests hiding this regression.
    code = """
import importlib.abc
import sys
class WithoutExtras(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'jsonschema', 'referencing', 'yaml', 'regex', 'lxml', 'cryptography', 'playwright'}:
            raise ImportError('optional dependency deliberately unavailable: ' + fullname)
sys.meta_path.insert(0, WithoutExtras())
from pysfmea.cli import main
for args in [['--version'], ['schema', '--list'],
             ['scan', sys.argv[1], '--allow-ungoverned', '--no-cache', '--output', sys.argv[2]],
             ['report', sys.argv[2], '--output', sys.argv[3]],
             ['report-verify', sys.argv[3], '--analysis', sys.argv[2]]]:
    assert main(args) == 0, args
from pysfmea.sarif_conformance import sarif_conformance
try:
    sarif_conformance('not-read.json', 'not-read-schema.json', authority='test')
except ValueError as exc:
    assert 'pysfmea[interop]' in str(exc)
else:
    raise AssertionError('missing validator must not silently pass conformance')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(ROOT / "benchmarks/python_sfmea_corpus/repository"),
            str(tmp_path / "analysis.json.gz"),
            str(tmp_path / "report.html"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_scope_authorization_remains_mutatable() -> None:
    generator = pytest.importorskip("mutmut.mutation.file_mutation")
    source = ROOT / "src/pysfmea/scope_authentication.py"
    generated = generator.mutate_file_contents(
        str(source), source.read_text(encoding="utf-8"), None
    )
    assert generated.mutant_names
    ast.parse(generated.code)


def test_ci_benchmark_explicitly_selects_fact_reuse_process_model() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    command = next(
        step["run"]
        for step in workflow["jobs"]["performance"]["steps"]
        if step.get("name") == "Enforce scanner runtime and traced-memory budgets"
    )
    assert "--reuse-facts" in command and "--in-process" in command
    assert "--max-median-seconds 60" in command
    assert "--max-peak-bytes 536870912" in command


def test_python_fuzzer_build_entrypoint_and_execution_language() -> None:
    yaml = pytest.importorskip("yaml")
    dockerfile = (ROOT / ".clusterfuzzlite/Dockerfile").read_text(encoding="utf-8")
    assert "COPY .clusterfuzzlite/build.sh $SRC/build.sh" in dockerfile
    assert "*.sh text eol=lf" in (ROOT / ".gitattributes").read_text(encoding="utf-8")
    execution_steps = 0
    for path in (ROOT / ".github/workflows").glob("clusterfuzzlite*.yml"):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("google/clusterfuzzlite/actions/"):
                    assert step["with"]["language"] == "python", (
                        path.name,
                        step["name"],
                    )
                    execution_steps += "/run_fuzzers@" in step["uses"]
    assert execution_steps == 3

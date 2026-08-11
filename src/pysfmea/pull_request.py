"""Safe, first-class base/head SFMEA orchestration for pull-request review."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .config import load_config
from .html_report import export_html_report, verify_html_report_file
from .integrity import canonical_json_sha256
from .interchange import differential_analysis, export_json_document
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .scanner import scan_repository
from .store import load_analysis, save_analysis
from .version import __version__

PULL_REQUEST_ANALYSIS_FORMAT = "pysfmea-pull-request-analysis-1"
PULL_REQUEST_ANALYSIS_VERIFICATION_FORMAT = (
    "pysfmea-pull-request-analysis-verification-1"
)
MAX_ARCHIVE_FILES = 250_000
MAX_ARCHIVE_BYTES = 2_000_000_000
GIT_TIMEOUT_SECONDS = 180
MAX_PULL_REQUEST_ARTIFACT_BYTES = 100_000_000


def _git(repository: Path, *arguments: str, output: Path | None = None) -> str:
    command = ["git", "-C", str(repository), *arguments]
    try:
        if output is None:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=GIT_TIMEOUT_SECONDS,
            )
            return result.stdout.strip()
        with output.open("wb") as stream:
            subprocess.run(
                command,
                check=True,
                stdout=stream,
                stderr=subprocess.PIPE,
                timeout=GIT_TIMEOUT_SECONDS,
            )
        return ""
    except FileNotFoundError as exc:
        raise RuntimeError("Git is required for pull-request analysis") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Git operation exceeded the bounded timeout") from exc
    except subprocess.CalledProcessError as exc:
        detail = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else str(exc.stderr or "")
        ).strip()
        raise ValueError(f"Git operation failed: {detail or 'unknown error'}") from exc


def _validate_ref(value: str, *, label: str) -> str:
    ref = value.strip()
    if not ref or len(ref) > 256 or ref.startswith("-"):
        raise ValueError(f"{label} must be a non-option Git revision up to 256 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in ref):
        raise ValueError(f"{label} contains control characters")
    return ref


def _resolve_commit(repository: Path, ref: str, *, label: str) -> str:
    commit = _git(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{_validate_ref(ref, label=label)}^{{commit}}",
    )
    if len(commit) != 40 or any(value not in "0123456789abcdef" for value in commit):
        raise ValueError(f"{label} did not resolve to a full commit ID")
    return commit


def _extract_git_archive(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Git archive exceeds the file-count safety limit")
        if sum(value.file_size for value in members) > MAX_ARCHIVE_BYTES:
            raise ValueError("Git archive exceeds the uncompressed byte safety limit")
        for member in members:
            relative = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (
                not member.filename
                or relative.is_absolute()
                or ".." in relative.parts
                or "\x00" in member.filename
                or stat.S_IFMT(mode) == stat.S_IFLNK
            ):
                raise ValueError(f"unsafe Git archive member: {member.filename!r}")
            target = destination.joinpath(*relative.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open("wb") as sink:
                shutil.copyfileobj(source, sink, length=1024 * 1024)


def _snapshot(repository: Path, commit: str, destination: Path) -> None:
    archive = destination.with_suffix(".zip")
    _git(
        repository,
        "archive",
        "--format=zip",
        f"--output={archive}",
        commit,
    )
    destination.mkdir(parents=True)
    _extract_git_archive(archive, destination)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_snapshot(path: Path, *, repository: Path, commit: str) -> dict[str, Any]:
    config_path = path / "sfmea.toml"
    config = load_config(config_path)[0] if config_path.is_file() else None
    analysis = scan_repository(path, config=config)
    analysis["project"]["root"] = str(repository)
    analysis["project"]["revision"] = commit
    analysis["project"].setdefault("settings", {})["pull_request_snapshot"] = {
        "commit": commit,
        "configuration_source": "sfmea.toml" if config is not None else "defaults",
        "configuration_sha256": canonical_json_sha256(config or {}),
        "repository_code_executed": False,
    }
    return analysis


def analyze_pull_request(
    repository: str | Path,
    *,
    base: str,
    head: str,
    output: str | Path,
) -> Path:
    """Scan exact commits and publish a self-contained base/head review bundle."""

    repo = Path(repository).expanduser().resolve(strict=True)
    if not repo.is_dir():
        raise ValueError("repository must be a directory")
    if _git(repo, "rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError("repository is not a Git working tree")
    base_commit = _resolve_commit(repo, base, label="base ref")
    head_commit = _resolve_commit(repo, head, label="head ref")
    destination = Path(output).expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"pull-request analysis destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{destination.name}.staging-", dir=destination.parent
    ) as temporary:
        temporary_root = Path(temporary)
        base_root, head_root = temporary_root / "base", temporary_root / "head"
        _snapshot(repo, base_commit, base_root)
        _snapshot(repo, head_commit, head_root)
        base_analysis = _scan_snapshot(
            base_root, repository=repo, commit=base_commit
        )
        head_analysis = _scan_snapshot(
            head_root, repository=repo, commit=head_commit
        )
        result_root = temporary_root / "result"
        result_root.mkdir()
        base_path = result_root / "base-analysis.json"
        head_path = result_root / "head-analysis.json"
        save_analysis(base_path, base_analysis)
        save_analysis(head_path, head_analysis)
        diff_path = export_json_document(
            differential_analysis(base_analysis, head_analysis),
            result_root / "differential-analysis.json",
        )
        base_report = export_html_report(
            base_analysis, result_root / "base-report.html"
        )
        head_report = export_html_report(
            head_analysis, result_root / "head-report.html"
        )
        artifacts = {
            path.name: {"bytes": path.stat().st_size, "sha256": _sha256(path)}
            for path in (
                base_path,
                head_path,
                diff_path,
                base_report,
                head_report,
            )
        }
        receipt: dict[str, Any] = {
            "format": PULL_REQUEST_ANALYSIS_FORMAT,
            "generated_at": utc_now(),
            "tool": {"name": "PySFMEA", "version": __version__},
            "repository": str(repo),
            "base": {
                "requested_ref": base,
                "commit": base_commit,
                "analysis_state_sha256": canonical_json_sha256(base_analysis),
            },
            "head": {
                "requested_ref": head,
                "commit": head_commit,
                "analysis_state_sha256": canonical_json_sha256(head_analysis),
            },
            "configuration_changed": (
                base_analysis.get("project", {})
                .get("settings", {})
                .get("pull_request_snapshot", {})
                .get("configuration_sha256")
                != head_analysis.get("project", {})
                .get("settings", {})
                .get("pull_request_snapshot", {})
                .get("configuration_sha256")
            ),
            "artifacts": artifacts,
            "security": {
                "checkout_method": "git_archive_with_bounded_safe_extraction",
                "repository_code_executed": False,
                "working_tree_mutated": False,
            },
            "notice": (
                "The bundle compares exact committed snapshots. Static findings are review "
                "leads; configuration changes and scanner limitations remain explicit."
            ),
        }
        receipt["content_sha256"] = canonical_json_sha256(receipt)
        (result_root / "receipt.json").write_text(
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        staged_verification = verify_pull_request_analysis(result_root)
        if not staged_verification["valid"]:
            raise RuntimeError(
                "staged pull-request analysis failed verification: "
                + "; ".join(staged_verification["errors"])
            )
        os.replace(result_root, destination)
    return destination


def _verify_pull_request_analysis(source: str | Path) -> dict[str, Any]:
    """Verify a readable base/head bundle without requiring its source repository."""

    root = Path(source).expanduser().resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("pull-request analysis must be a regular directory")
    expected = {
        "receipt.json",
        "base-analysis.json",
        "head-analysis.json",
        "differential-analysis.json",
        "base-report.html",
        "head-report.html",
    }
    entries = list(root.iterdir())
    supplied = {value.name for value in entries}
    regular_files = all(value.is_file() and not value.is_symlink() for value in entries)
    checks: dict[str, bool] = {
        "closed_file_set": supplied == expected and regular_files,
        "receipt_integrity": False,
        "artifact_integrity": False,
        "analysis_bindings": False,
        "differential_regeneration": False,
        "report_bindings": False,
        "commit_bindings": False,
        "configuration_change": False,
        "security_declaration": False,
    }
    errors: list[str] = []
    if not checks["closed_file_set"]:
        errors.append("bundle file set is missing, unexpected, linked, or non-regular")
    receipt_document = load_bounded_json_document(
        root / "receipt.json",
        label="pull-request analysis receipt",
        max_bytes=MAX_PULL_REQUEST_ARTIFACT_BYTES,
        max_depth=80,
        max_nodes=500_000,
    )
    receipt = receipt_document.value
    if not isinstance(receipt, dict):
        raise ValueError("pull-request analysis receipt must contain an object")
    declared_digest = str(receipt.get("content_sha256", ""))
    unsigned = dict(receipt)
    unsigned.pop("content_sha256", None)
    checks["receipt_integrity"] = (
        receipt.get("format") == PULL_REQUEST_ANALYSIS_FORMAT
        and len(declared_digest) == 64
        and declared_digest == canonical_json_sha256(unsigned)
    )
    if not checks["receipt_integrity"]:
        errors.append("receipt format or content digest is invalid")
    artifacts = receipt.get("artifacts", {})
    artifact_names = expected - {"receipt.json"}
    checks["artifact_integrity"] = isinstance(artifacts, dict) and set(artifacts) == artifact_names
    if checks["artifact_integrity"]:
        for name in sorted(artifact_names):
            record = artifacts.get(name)
            path = root / name
            if (
                not isinstance(record, dict)
                or record.get("bytes") != path.stat().st_size
                or record.get("sha256") != _sha256(path)
            ):
                checks["artifact_integrity"] = False
                break
    if not checks["artifact_integrity"]:
        errors.append("one or more artifact byte counts or digests are invalid")
    base_analysis = load_analysis(root / "base-analysis.json")
    head_analysis = load_analysis(root / "head-analysis.json")
    base_record = receipt.get("base", {})
    head_record = receipt.get("head", {})
    checks["analysis_bindings"] = (
        isinstance(base_record, dict)
        and isinstance(head_record, dict)
        and base_record.get("analysis_state_sha256")
        == canonical_json_sha256(base_analysis)
        and head_record.get("analysis_state_sha256")
        == canonical_json_sha256(head_analysis)
    )
    if not checks["analysis_bindings"]:
        errors.append("base or head analysis-state binding is invalid")
    diff_document = load_bounded_json_document(
        root / "differential-analysis.json",
        label="pull-request differential analysis",
        max_bytes=MAX_PULL_REQUEST_ARTIFACT_BYTES,
        max_depth=100,
        max_nodes=2_000_000,
    )
    stored_diff = diff_document.value
    checks["differential_regeneration"] = isinstance(stored_diff, dict) and (
        stored_diff
        == differential_analysis(
            base_analysis,
            head_analysis,
            generated_at=str(stored_diff.get("generated_at", "")),
        )
    )
    if not checks["differential_regeneration"]:
        errors.append("differential analysis does not exactly regenerate")
    base_report = verify_html_report_file(
        root / "base-report.html", analysis=base_analysis
    )
    head_report = verify_html_report_file(
        root / "head-report.html", analysis=head_analysis
    )
    checks["report_bindings"] = bool(base_report["valid"] and head_report["valid"])
    if not checks["report_bindings"]:
        errors.append("base or head report integrity/binding is invalid")
    checks["commit_bindings"] = (
        isinstance(base_record, dict)
        and isinstance(head_record, dict)
        and base_record.get("commit") == base_analysis.get("project", {}).get("revision")
        and head_record.get("commit") == head_analysis.get("project", {}).get("revision")
        and all(
            isinstance(value.get("commit"), str)
            and len(value["commit"]) == 40
            and all(character in "0123456789abcdef" for character in value["commit"])
            for value in (base_record, head_record)
        )
    )
    if not checks["commit_bindings"]:
        errors.append("receipt commits do not match the exact analysis revisions")
    base_configuration = (
        base_analysis.get("project", {})
        .get("settings", {})
        .get("pull_request_snapshot", {})
        .get("configuration_sha256")
    )
    head_configuration = (
        head_analysis.get("project", {})
        .get("settings", {})
        .get("pull_request_snapshot", {})
        .get("configuration_sha256")
    )
    checks["configuration_change"] = receipt.get("configuration_changed") == (
        base_configuration != head_configuration
    )
    if not checks["configuration_change"]:
        errors.append("configuration-change declaration is inconsistent")
    security = receipt.get("security", {})
    checks["security_declaration"] = security == {
        "checkout_method": "git_archive_with_bounded_safe_extraction",
        "repository_code_executed": False,
        "working_tree_mutated": False,
    }
    if not checks["security_declaration"]:
        errors.append("security declaration is missing or unsupported")
    valid = all(checks.values())
    return {
        "format": PULL_REQUEST_ANALYSIS_VERIFICATION_FORMAT,
        "path": str(root),
        "valid": valid,
        "checks": checks,
        "base_commit": str(base_record.get("commit", "")) if isinstance(base_record, dict) else "",
        "head_commit": str(head_record.get("commit", "")) if isinstance(head_record, dict) else "",
        "errors": errors,
        "notice": (
            "Verification proves bundle integrity, internal regeneration, and exact commit/report "
            "bindings; it does not establish finding correctness or repository identity."
        ),
    }


def verify_pull_request_analysis(source: str | Path) -> dict[str, Any]:
    """Return a closed verification verdict for a published base/head bundle."""

    supplied = Path(source).expanduser().absolute()
    try:
        return _verify_pull_request_analysis(supplied)
    except (OSError, ValueError) as exc:
        return {
            "format": PULL_REQUEST_ANALYSIS_VERIFICATION_FORMAT,
            "path": str(supplied),
            "valid": False,
            "checks": {
                "closed_file_set": False,
                "receipt_integrity": False,
                "artifact_integrity": False,
                "analysis_bindings": False,
                "differential_regeneration": False,
                "report_bindings": False,
                "commit_bindings": False,
                "configuration_change": False,
                "security_declaration": False,
            },
            "base_commit": "",
            "head_commit": "",
            "errors": [f"bundle could not be verified: {exc}"],
            "notice": (
                "Verification proves bundle integrity, internal regeneration, and exact "
                "commit/report bindings; it does not establish finding correctness or "
                "repository identity."
            ),
        }

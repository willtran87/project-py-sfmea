from __future__ import annotations

import re
import sys
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pysfmea.diagrams import GENERATED_DIAGRAM_KINDS
from pysfmea.schemas import schema_catalog

DOCUMENT_EXCLUDED_DIRECTORIES = {".artifacts", ".git", ".venv", "build", "dist"}

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
CODE_FENCE_RE = re.compile(r"^```.*?^```\s*$", re.MULTILINE | re.DOTALL)


def _github_anchor(heading: str, seen: Counter[str]) -> str:
    """Produce the GitHub-style anchor used by this repository's Markdown links."""

    normalized = re.sub(r"[`*_~]", "", heading).strip().lower()
    normalized = re.sub(r"[^\w\- ]", "", normalized)
    anchor = re.sub(r"[ ]+", "-", normalized)
    occurrence = seen[anchor]
    seen[anchor] += 1
    return anchor if occurrence == 0 else f"{anchor}-{occurrence}"


def _anchors(document: Path) -> set[str]:
    content = CODE_FENCE_RE.sub("", document.read_text(encoding="utf-8"))
    seen: Counter[str] = Counter()
    return {
        _github_anchor(match.group(1), seen)
        for match in HEADING_RE.finditer(content)
    }


class DocumentationLinksTests(unittest.TestCase):
    def test_local_markdown_links_and_anchors_resolve(self) -> None:
        documents = sorted(
            document
            for document in ROOT.rglob("*.md")
            if not (set(document.relative_to(ROOT).parts) & DOCUMENT_EXCLUDED_DIRECTORIES)
        )
        failures: list[str] = []
        anchor_cache: dict[Path, set[str]] = {}

        for document in documents:
            content = CODE_FENCE_RE.sub("", document.read_text(encoding="utf-8"))
            for raw_target in LINK_RE.findall(content):
                target = raw_target.strip().strip("<>")
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc or target.startswith("mailto:"):
                    continue
                path_text = unquote(parsed.path)
                target_document = (
                    document if not path_text else (document.parent / path_text).resolve()
                )
                if not target_document.is_relative_to(ROOT) or not target_document.exists():
                    failures.append(f"{document.relative_to(ROOT)} -> {target}")
                    continue
                if parsed.fragment:
                    anchors = anchor_cache.setdefault(
                        target_document, _anchors(target_document)
                    )
                    if parsed.fragment not in anchors:
                        failures.append(f"{document.relative_to(ROOT)} -> {target}")

        self.assertEqual(failures, [], "Broken local documentation links:\n" + "\n".join(failures))

    def test_generated_test_governance_documentation_matches_current_contract(self) -> None:
        documents = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "README.md",
                "docs/GENERATED_TEST_CAMPAIGNS.md",
                "docs/WORKFLOW.md",
                "docs/VISUAL_GUIDE.md",
                "docs/METHODOLOGY.md",
            )
        }
        for name, content in documents.items():
            with self.subTest(document=name):
                self.assertIn("import-qualified", content)
                self.assertIn("exact", content.casefold())
        for name in ("README.md", "docs/WORKFLOW.md", "docs/VISUAL_GUIDE.md"):
            with self.subTest(quality_gates=name):
                self.assertIn("14 declared", documents[name])
                self.assertIn("15 artifact-backed", documents[name])
                self.assertIn("25", documents[name])
                self.assertIn("7", documents[name])
                self.assertIn("evidence mode", documents[name].casefold())
                self.assertIn("manifest", documents[name].casefold())
                self.assertIn("raw artifact", documents[name].casefold())
        self.assertIn("Fourteen gates", documents["docs/METHODOLOGY.md"])
        for command in (
            "assurance-test-fault-evidence",
            "assurance-test-fault-evidence-verify",
            "assurance-test-quality-evaluate",
            "assurance-test-quality-verify",
        ):
            self.assertIn(command, documents["README.md"])
            self.assertIn(command, documents["docs/WORKFLOW.md"])
            self.assertIn(command, documents["docs/VISUAL_GUIDE.md"])
        visual = documents["docs/VISUAL_GUIDE.md"]
        self.assertIn('subgraph PERTEST["Per-test evidence"]', visual)
        self.assertIn('subgraph SUBJECT["Subject qualification"]', visual)
        self.assertIn('D{"Human promotion decision"}', visual)
        campaign = documents["docs/GENERATED_TEST_CAMPAIGNS.md"]
        self.assertIn("sequenceDiagram", campaign)
        self.assertIn("execution.json", campaign)
        self.assertIn("every artifact size and SHA-256", campaign)
        self.assertIn("25 derived campaign gates or fail-closed error", campaign)
        schemas = (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8")
        self.assertIn("`assurance-test-generation-quality-corpus-v2`", schemas)
        self.assertIn("`assurance-test-generation-quality-result-v2`", schemas)
        self.assertIn("`assurance-test-generation-quality-corpus-v3`", schemas)
        self.assertIn("`assurance-test-generation-quality-result-v3`", schemas)
        self.assertIn("`assurance-test-generation-fault-evidence`", schemas)
        self.assertIn("`assurance-test-generation-campaign-plan`", schemas)
        self.assertIn(
            "`assurance-test-generation-campaign-plan-verification`", schemas
        )
        self.assertIn("`json-evidence-signature`", schemas)
        self.assertIn("`json-evidence-signature-verification`", schemas)

    def test_documented_schema_inventory_matches_public_catalog(self) -> None:
        content = (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8")
        inventory = content.split("Available names:", 1)[1].split(
            "The schemas use stable", 1
        )[0]
        documented = set(re.findall(r"^\| `([^`]+)` \|", inventory, re.MULTILINE))
        published = {item["name"] for item in schema_catalog()["schemas"]}
        self.assertEqual(documented, published)

    def test_runtime_evidence_guide_covers_capture_and_claim_boundaries(self) -> None:
        content = (ROOT / "docs" / "RUNTIME_EVIDENCE.md").read_text(
            encoding="utf-8"
        )
        for expected in (
            "sequenceDiagram",
            "RuntimeTraceRecorder",
            "sfmea trace-import",
            "runtime_corroborated",
            "runtime_only",
            "dropped spans",
            "does not establish",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)

    def test_diagram_documentation_lists_every_generated_category(self) -> None:
        content = (ROOT / "docs" / "DIAGRAMS.md").read_text(encoding="utf-8")
        for category in GENERATED_DIAGRAM_KINDS:
            if category != "all":
                with self.subTest(category=category):
                    self.assertIn(f"`{category}`", content)

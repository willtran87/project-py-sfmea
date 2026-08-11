from __future__ import annotations

import re
import sys
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
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

from __future__ import annotations

import json
import re
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
PAGE_URL = "https://willtran87.github.io/project-py-sfmea/"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.hrefs: list[str] = []
        self.tag_counts: dict[str, int] = {}
        self.meta: dict[str, str] = {}
        self.canonical = ""
        self.title_parts: list[str] = []
        self.json_ld_parts: list[str] = []
        self._in_title = False
        self._in_json_ld = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {key: value or "" for key, value in attrs}
        self.tag_counts[tag] = self.tag_counts.get(tag, 0) + 1
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "a" and values.get("href"):
            self.hrefs.append(values["href"])
            if values.get("target") == "_blank":
                rel = set(values.get("rel", "").split())
                if not {"noopener", "noreferrer"} <= rel:
                    raise AssertionError("target=_blank link is missing noopener noreferrer")
        if tag == "meta":
            key = values.get("name") or values.get("property")
            if key:
                self.meta[key] = values.get("content", "")
        if tag == "link" and values.get("rel") == "canonical":
            self.canonical = values.get("href", "")
        if tag == "title":
            self._in_title = True
        if tag == "script" and values.get("type") == "application/ld+json":
            self._in_json_ld = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "script" and self._in_json_ld:
            self._in_json_ld = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._in_json_ld:
            self.json_ld_parts.append(data)


class PagesSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (SITE / "index.html").read_text(encoding="utf-8")
        cls.parser = _PageParser()
        cls.parser.feed(cls.html)

    def test_landing_page_metadata_and_structure(self) -> None:
        self.assertEqual(self.parser.tag_counts.get("main"), 1)
        self.assertEqual(self.parser.tag_counts.get("h1"), 1)
        self.assertGreaterEqual(self.parser.tag_counts.get("nav", 0), 2)
        self.assertIn("PySFMEA", "".join(self.parser.title_parts))
        self.assertEqual(self.parser.canonical, PAGE_URL)
        self.assertTrue(self.parser.meta["description"])
        self.assertEqual(self.parser.meta["og:url"], PAGE_URL)
        self.assertTrue(self.parser.meta["og:title"])
        self.assertTrue(self.parser.meta["twitter:description"])
        schema = json.loads("".join(self.parser.json_ld_parts))
        self.assertEqual(schema["@type"], "SoftwareApplication")
        self.assertEqual(schema["url"], PAGE_URL)

    def test_internal_navigation_and_assets_are_closed(self) -> None:
        self.assertEqual(len(self.parser.ids), len(set(self.parser.ids)))
        ids = set(self.parser.ids)
        for href in self.parser.hrefs:
            if href.startswith("#"):
                self.assertIn(href[1:], ids, href)
            elif href.startswith("assets/"):
                self.assertTrue((SITE / href).is_file(), href)
        self.assertIn("#main-content", self.parser.hrefs)
        self.assertEqual(
            {
                "demo/report.html",
                "demo/analysis.json.gz",
                "demo/diagrams.json",
                "demo/cross-reference.json.gz",
            },
            {href for href in self.parser.hrefs if href.startswith("demo/")},
        )

    def test_css_has_accessibility_and_responsive_guards(self) -> None:
        css = (SITE / "assets" / "site.css").read_text(encoding="utf-8")
        self.assertIn(":focus-visible", css)
        self.assertIn("prefers-reduced-motion: reduce", css)
        self.assertIn("forced-colors: active", css)
        self.assertGreaterEqual(css.count("@media (max-width:"), 2)
        self.assertNotRegex(css, r"outline\s*:\s*(?:none|0)\b")

    def test_pages_workflow_is_pinned_and_reproducible(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(
            encoding="utf-8"
        )
        action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
        self.assertGreaterEqual(len(action_refs), 5)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs))
        for required in (
            "pages: write",
            "id-token: write",
            "--allow-ungoverned",
            "--no-cache",
            "cross-reference-verify",
            "diagram-verify",
            "report-verify",
            "_site/demo/report.html",
        ):
            self.assertIn(required, workflow)

    def test_sitemap_and_404_page_are_valid(self) -> None:
        sitemap = ET.parse(SITE / "sitemap.xml")
        namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        locations = {
            value.text for value in sitemap.findall("s:url/s:loc", namespace)
        }
        self.assertIn(PAGE_URL, locations)
        self.assertIn(f"{PAGE_URL}demo/report.html", locations)
        not_found = (SITE / "404.html").read_text(encoding="utf-8")
        self.assertIn('name="robots" content="noindex"', not_found)
        self.assertIn('/project-py-sfmea/', not_found)


if __name__ == "__main__":
    unittest.main()

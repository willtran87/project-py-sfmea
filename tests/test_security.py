from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.cli import main
from pysfmea.security import export_service_threat_model, service_threat_model


class SecurityModelTests(unittest.TestCase):
    def test_model_is_complete_content_addressed_and_exportable(self) -> None:
        model = service_threat_model()
        self.assertEqual(model["format"], "pysfmea-service-threat-model-1")
        self.assertGreaterEqual(len(model["threats"]), 10)
        self.assertGreaterEqual(len(model["residual_risks"]), 4)
        self.assertTrue(
            all(value["acceptance_authority"] for value in model["residual_risks"])
        )
        self.assertEqual(len(model["content_sha256"]), 64)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            json_path = export_service_threat_model(root / "threat-model.json")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), model)
            markdown_path = root / "threat-model.md"
            self.assertEqual(
                main(
                    [
                        "threat-model",
                        "--format",
                        "markdown",
                        "--output",
                        str(markdown_path),
                    ]
                ),
                0,
            )
            self.assertIn(
                "## Residual-risk register",
                markdown_path.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()

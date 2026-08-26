from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.cli import main
from pysfmea.evidence_signing import sign_json_evidence, verify_json_evidence_signature


class EvidenceSigningTests(unittest.TestCase):
    def test_exact_json_evidence_can_be_authenticated_and_tamper_is_rejected(
        self,
    ) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError:
            self.skipTest("cryptography is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "campaign-plan.json"
            artifact.write_text(
                json.dumps({"format": "example-1", "qualified": False}) + "\n",
                encoding="utf-8",
            )
            private = Ed25519PrivateKey.generate()
            private_path = root / "private.pem"
            public_path = root / "public.pem"
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            public_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            signature = sign_json_evidence(
                artifact, private_path, "qualification-reviewer"
            )
            valid = verify_json_evidence_signature(artifact, signature, public_path)
            self.assertTrue(valid["valid"])
            self.assertEqual(valid["signer"], "qualification-reviewer")
            artifact.write_text(
                json.dumps({"format": "example-1", "qualified": True}) + "\n",
                encoding="utf-8",
            )
            tampered = verify_json_evidence_signature(artifact, signature, public_path)
            self.assertFalse(tampered["valid"])
            self.assertFalse(tampered["checks"]["artifact_binding"])

            cli_signature = root / "cli.sig.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "assurance-evidence-sign",
                            str(artifact),
                            "--private-key",
                            str(private_path),
                            "--signer",
                            "qualification-reviewer",
                            "--output",
                            str(cli_signature),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    main(
                        [
                            "assurance-evidence-signature-verify",
                            str(artifact),
                            str(cli_signature),
                            "--public-key",
                            str(public_path),
                            "--json",
                        ]
                    ),
                    0,
                )

    def test_non_object_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "array.json"
            artifact.write_text("[]\n", encoding="utf-8")
            result = verify_json_evidence_signature(artifact, artifact, artifact)
            self.assertFalse(result["valid"])
            self.assertIn("must contain an object", result["errors"][0])

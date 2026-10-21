"""Run mutmut with native-extension dependencies initialized before coverage.

mutmut 3.7 unloads Python modules imported during its initial coverage pass.
Rust-backed cryptography keeps references to those modules' types, so reloading
only their Python halves breaks serialization during the subsequent stats pass.
Preloading avoids that split identity without skipping tests, mutations or gates.
"""

from __future__ import annotations

import importlib


def preload_native_dependencies() -> None:
    # The mutation environment explicitly includes the signing extra. Missing
    # dependencies must fail before running a misleading partial campaign.
    importlib.import_module("cryptography.hazmat.primitives.serialization")
    importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")


def main() -> None:
    preload_native_dependencies()
    from mutmut.__main__ import cli

    cli()


if __name__ == "__main__":
    main()

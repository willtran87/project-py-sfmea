"""ClusterFuzzLite/Atheris target for bounded public ingestion surfaces."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from pysfmea.json_ingestion import parse_bounded_json_bytes
    from pysfmea.security_prioritization import parse_cvss_v4_vector


def test_one_input(data: bytes) -> None:
    try:
        parse_bounded_json_bytes(
            data,
            label="fuzz JSON",
            max_bytes=1_048_576,
            max_depth=100,
            max_nodes=100_000,
        )
    except ValueError:
        pass
    try:
        parse_cvss_v4_vector(data[:2_048].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

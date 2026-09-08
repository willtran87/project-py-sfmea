from pathlib import Path


def normalize(root: Path, candidate: str) -> str:
    resolved = (root / candidate).resolve()
    resolved.relative_to(root.resolve())
    return resolved.as_posix()

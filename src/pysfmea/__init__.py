"""PySFMEA: a reviewable Software FMEA starter for Python repositories."""

from .scanner import scan_repository
from .version import __version__

__all__ = ["__version__", "scan_repository"]

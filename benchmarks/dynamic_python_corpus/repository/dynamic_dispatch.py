"""Intentional static-analysis boundaries that must remain visible and conservative."""

from importlib import import_module
from typing import Any, Callable

from targets import alternate, primary

REGISTRY: dict[str, Callable[[str], str]] = {
    "primary": primary,
    "alternate": alternate,
}
ACTIVE: Callable[[str], str] = primary


def direct_dispatch(value: str) -> str:
    return primary(value)


def registry_dispatch(name: str, value: str) -> str:
    return REGISTRY[name](value)


def reflective_dispatch(target: Any, method: str, value: str) -> str:
    return getattr(target, method)(value)


def imported_dispatch(module_name: str, value: str) -> str:
    return import_module(module_name).primary(value)


def monkey_patch_dispatch(value: str) -> str:
    return ACTIVE(value)

"""Targets used by the dynamic-dispatch qualification corpus."""


def primary(value: str) -> str:
    return f"primary:{value}"


def alternate(value: str) -> str:
    return f"alternate:{value}"


class Handler:
    def execute(self, value: str) -> str:
        return f"handler:{value}"

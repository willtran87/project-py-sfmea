from __future__ import annotations

from collections.abc import Callable


def route(path: str):
    def register(function: Callable):
        function.route_path = path
        return function
    return register


@route("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


class Configuration:
    endpoint = property(lambda self: "https://example.invalid")


def process(task: Callable[[], None]) -> None:
    while True:
        try:
            task()
            return
        except TimeoutError:
            continue


def handler(provider: Callable[[], Configuration]) -> str:
    return provider().endpoint

from __future__ import annotations

from typing import Any


def extract_callgraph(functions: list[dict[str, Any]]) -> dict[str, Any]:
    win_funcs = [fn for fn in functions if fn.get("name") in {"win", "get_flag", "flag", "debug"}]
    return {
        "reachable_functions": "unknown",
        "dead_code": "unknown",
        "hidden_functions": win_funcs,
    }

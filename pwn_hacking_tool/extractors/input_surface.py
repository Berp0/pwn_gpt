from __future__ import annotations

from typing import Any


INPUT_FUNCTIONS = {
    "gets",
    "fgets",
    "read",
    "recv",
    "scanf",
    "fscanf",
    "sscanf",
    "gets_s",
}


def extract_input_surface(imports: list[str]) -> dict[str, Any]:
    hits = sorted(set(imports).intersection(INPUT_FUNCTIONS))
    return {
        "input_functions": hits,
        "input_count": len(hits),
        "stdin": "possible" if hits else "unknown",
        "argv": "unknown",
        "env": "unknown",
        "multi_stage": "unknown",
    }

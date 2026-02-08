from __future__ import annotations

import re
from typing import Any

from ..utils import run_tool, uniq_preserve
from ..validators import ToolchainValidator

PATTERNS = {
    "format": re.compile(r"%[\d$]*[psxn]"),
    "shell": re.compile(r"/bin/sh"),
    "debug": re.compile(r"debug|trace|verbose", re.IGNORECASE),
    "flag": re.compile(r"flag\{|ctf", re.IGNORECASE),
}


def extract_strings(path: str, validator: ToolchainValidator) -> dict[str, Any]:
    strings: list[str] = []
    if validator.is_available("strings"):
        result = run_tool(["strings", "-a", "-n", "4", path])
        if result.ok:
            strings = result.stdout.splitlines()
    interesting = []
    for line in strings:
        if any(pattern.search(line) for pattern in PATTERNS.values()):
            interesting.append(line.strip())
    return {
        "interesting": uniq_preserve(interesting)[:100],
        "format_strings": [s for s in interesting if PATTERNS["format"].search(s)],
        "shell_hints": [s for s in interesting if PATTERNS["shell"].search(s)],
        "debug_markers": [s for s in interesting if PATTERNS["debug"].search(s)],
        "flag_like": [s for s in interesting if PATTERNS["flag"].search(s)],
    }

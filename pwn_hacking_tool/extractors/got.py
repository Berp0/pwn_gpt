from __future__ import annotations

from typing import Any

from ..utils import run_tool
from ..validators import ToolchainValidator


def extract_got(path: str, validator: ToolchainValidator, relro: str) -> dict[str, Any]:
    writable = relro in {"partial", "none", "unknown"}
    entries: list[str] = []
    if validator.is_available("readelf"):
        result = run_tool(["readelf", "-r", path])
        if result.ok:
            for line in result.stdout.splitlines():
                if "@GLIBC" in line or "@" in line:
                    parts = line.split()
                    if parts:
                        entries.append(parts[-1])
    return {
        "writable_got": writable,
        "got_entries": sorted(set(entries)),
    }

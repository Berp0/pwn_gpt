from __future__ import annotations

import re
from typing import Any

from ..utils import run_tool
from ..validators import ToolchainValidator


def extract_protections(path: str, validator: ToolchainValidator) -> dict[str, Any]:
    protections: dict[str, Any] = {
        "nx": "unknown",
        "pie": "unknown",
        "relro": "unknown",
        "canary": "unknown",
        "fortify": "unknown",
        "stack_exec": "unknown",
        "source": "none",
    }
    if validator.is_available("checksec"):
        result = run_tool(["checksec", "--file", path])
        if result.ok:
            protections.update(_parse_checksec(result.stdout))
            protections["source"] = "checksec"
            return protections
    if validator.is_available("readelf"):
        result = run_tool(["readelf", "-l", path])
        if result.ok:
            protections.update(_parse_readelf(result.stdout))
            protections["source"] = "readelf"
    return protections


def _parse_checksec(text: str) -> dict[str, Any]:
    def parse_flag(name: str) -> str:
        match = re.search(rf"{name}\s*:\s*(\w+)", text, re.IGNORECASE)
        if not match:
            return "unknown"
        value = match.group(1).lower()
        if value in {"enabled", "found", "full", "partial"}:
            return "enabled"
        if value in {"disabled", "no"}:
            return "disabled"
        return value

    relro = re.search(r"RELRO\s*:\s*(\w+)", text, re.IGNORECASE)
    return {
        "nx": parse_flag("NX"),
        "pie": parse_flag("PIE"),
        "canary": parse_flag("Canary"),
        "relro": relro.group(1).lower() if relro else "unknown",
    }


def _parse_readelf(text: str) -> dict[str, Any]:
    stack_exec = "enabled" if "GNU_STACK" in text and "RWE" in text else "disabled"
    return {
        "stack_exec": stack_exec,
    }

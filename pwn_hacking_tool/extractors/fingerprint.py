from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..utils import run_tool
from ..validators import ToolchainValidator


def extract_fingerprint(path: str, validator: ToolchainValidator) -> dict[str, Any]:
    metadata: dict[str, Any] = {"path": path, "arch": "unknown", "endianness": "unknown"}
    if validator.is_available("readelf"):
        result = run_tool(["readelf", "-h", path])
        if result.ok:
            header = result.stdout
            metadata["elf_type"] = _find_value(header, r"Type:\s*(.+)")
            metadata["arch"] = _find_value(header, r"Machine:\s*(.+)")
            metadata["endianness"] = _find_value(header, r"Data:\s*(.+)")
            metadata["entry"] = _find_value(header, r"Entry point address:\s*(.+)")
    if validator.is_available("file"):
        result = run_tool(["file", path])
        if result.ok:
            metadata["file_description"] = result.stdout
            metadata["stripped"] = "not stripped" not in result.stdout
            if "dynamically linked" in result.stdout:
                metadata["linking"] = "dynamic"
            elif "statically linked" in result.stdout:
                metadata["linking"] = "static"
    return metadata


def _find_value(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None

from __future__ import annotations

from typing import Any

from ..utils import run_tool, uniq_preserve
from ..validators import ToolchainValidator


def extract_imports(path: str, validator: ToolchainValidator) -> dict[str, Any]:
    imports: list[str] = []
    functions: list[dict[str, Any]] = []
    if validator.is_available("nm"):
        result = run_tool(["nm", "-an", path])
        if result.ok:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                if len(parts) == 2:
                    addr, sym_type = parts
                    name = ""
                else:
                    addr, sym_type, name = parts[0], parts[1], parts[2]
                if sym_type.upper() == "U" and name:
                    imports.append(name)
                if sym_type.lower() == "t" and name:
                    functions.append({"name": name, "addr": addr})
    return {
        "imports": uniq_preserve(imports),
        "functions": functions,
    }

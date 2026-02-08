from __future__ import annotations

from typing import Any

from ..utils import run_tool
from ..validators import ToolchainValidator


def extract_toolchain_fingerprint(path: str, validator: ToolchainValidator) -> dict[str, Any]:
    fingerprint: dict[str, Any] = {
        "compiler": "unknown",
        "libc": "unknown",
        "libc_version_hint": "unknown",
        "optimization": "unknown",
    }
    if validator.is_available("strings"):
        result = run_tool(["strings", "-a", "-n", "6", path])
        if result.ok:
            text = result.stdout
            if "GCC" in text:
                fingerprint["compiler"] = "gcc"
            if "clang" in text:
                fingerprint["compiler"] = "clang"
            if "GLIBC" in text:
                fingerprint["libc"] = "glibc"
    if validator.is_available("ldd"):
        result = run_tool(["ldd", path])
        if result.ok and "libc.so" in result.stdout:
            fingerprint["libc"] = "glibc"
    return fingerprint

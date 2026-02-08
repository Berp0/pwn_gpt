from __future__ import annotations

import re
from typing import Any

from .utils import ToolResult, run_tool, tool_exists, uniq_preserve

DANGEROUS_FUNCTIONS = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "scanf",
    "fscanf",
    "sscanf",
    "read",
}

INTERESTING_STRING_PATTERNS = [
    re.compile(r"/bin/sh"),
    re.compile(r"%p"),
    re.compile(r"%n"),
    re.compile(r"FLAG\{"),
    re.compile(r"flag", re.IGNORECASE),
    re.compile(r"CTF", re.IGNORECASE),
]


class AdapterOutput:
    def __init__(self) -> None:
        self.results: dict[str, ToolResult] = {}

    def add(self, name: str, result: ToolResult) -> None:
        self.results[name] = result

    def get(self, name: str) -> ToolResult | None:
        return self.results.get(name)


def run_file(path: str, output: AdapterOutput) -> dict[str, Any]:
    result = run_tool(["file", path])
    output.add("file", result)
    arch = "unknown"
    stripped = None
    if result.ok:
        description = result.stdout
        if "x86-64" in description or "x86_64" in description:
            arch = "amd64"
        elif "Intel 80386" in description:
            arch = "i386"
        elif "ARM aarch64" in description or "ARM64" in description:
            arch = "aarch64"
        elif "ARM" in description:
            arch = "arm"
        stripped = "not stripped" not in description
    return {
        "path": path,
        "arch": arch,
        "stripped": stripped,
        "description": result.stdout if result.ok else "",
    }


def run_checksec(path: str, output: AdapterOutput) -> dict[str, Any]:
    checksec_cmd = None
    if tool_exists("checksec"):
        checksec_cmd = ["checksec", "--file", path]
    if not checksec_cmd:
        return {
            "nx": None,
            "pie": None,
            "canary": None,
            "relro": None,
            "source": "missing",
        }
    result = run_tool(checksec_cmd)
    output.add("checksec", result)
    protections = {
        "nx": None,
        "pie": None,
        "canary": None,
        "relro": None,
        "source": "checksec",
    }
    if not result.ok:
        protections["source"] = "error"
        return protections
    text = result.stdout
    def parse_flag(name: str) -> bool | None:
        match = re.search(rf"{name}\s*:\s*(\w+)", text, re.IGNORECASE)
        if not match:
            return None
        value = match.group(1).lower()
        return value in {"enabled", "found", "full", "partial"}
    protections["nx"] = parse_flag("NX")
    protections["pie"] = parse_flag("PIE")
    protections["canary"] = parse_flag("Canary")
    relro_match = re.search(r"RELRO\s*:\s*(\w+)", text, re.IGNORECASE)
    protections["relro"] = relro_match.group(1).lower() if relro_match else None
    return protections


def run_strings(path: str, output: AdapterOutput) -> dict[str, Any]:
    result = run_tool(["strings", "-a", "-n", "4", path])
    output.add("strings", result)
    interesting: list[str] = []
    if result.ok:
        for line in result.stdout.splitlines():
            if any(pattern.search(line) for pattern in INTERESTING_STRING_PATTERNS):
                interesting.append(line.strip())
    return {
        "interesting": uniq_preserve(interesting)[:50],
    }


def run_nm(path: str, output: AdapterOutput) -> dict[str, Any]:
    result = run_tool(["nm", "-an", path])
    output.add("nm", result)
    functions = []
    imports = []
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
            if sym_type.lower() == "t" and name:
                try:
                    functions.append({"name": name, "addr": int(addr, 16)})
                except ValueError:
                    functions.append({"name": name, "addr": None})
            if sym_type.upper() == "U" and name:
                imports.append(name)
    return {
        "functions": functions,
        "imports": uniq_preserve(imports),
    }


def collect_adapter_metadata(output: AdapterOutput) -> dict[str, Any]:
    return {
        name: {
            "command": result.command,
            "ok": result.ok,
            "returncode": result.returncode,
        }
        for name, result in output.results.items()
    }


def detect_control(symbols: dict[str, Any], protections: dict[str, Any]) -> dict[str, Any]:
    imports = set(symbols.get("imports", []))
    dangerous = imports.intersection(DANGEROUS_FUNCTIONS)
    rip_control = "likely" if dangerous and protections.get("canary") is False else "possible"
    return {
        "rip_control": rip_control,
        "dangerous_imports": sorted(dangerous),
        "arg_control": "possible" if dangerous else "unlikely",
    }


def detect_leaks(strings: dict[str, Any], symbols: dict[str, Any]) -> dict[str, Any]:
    imports = set(symbols.get("imports", []))
    has_printf = bool(imports.intersection({"printf", "puts", "fprintf", "dprintf"}))
    fmt_strings = [s for s in strings.get("interesting", []) if "%p" in s or "%n" in s]
    return {
        "stack": "possible" if fmt_strings else "unlikely",
        "libc": "likely" if has_printf else "possible",
    }

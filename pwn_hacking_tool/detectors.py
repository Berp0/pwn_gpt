from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectorFinding:
    name: str
    confidence: str
    details: dict[str, Any]


def detect_stack_overflow(context: dict[str, Any]) -> DetectorFinding | None:
    protections = context["protections"]
    control = context["control"]
    if protections.get("canary") is True:
        return None
    dangerous = control.get("dangerous_imports", [])
    if not dangerous:
        return None
    confidence = "high" if protections.get("canary") is False else "medium"
    return DetectorFinding(
        name="stack_overflow",
        confidence=confidence,
        details={
            "dangerous_imports": dangerous,
        },
    )


def detect_format_string(context: dict[str, Any]) -> DetectorFinding | None:
    symbols = context["symbols"]
    strings = context["strings"]
    protections = context["protections"]
    imports = set(symbols.get("imports", []))
    fmt_strings = [s for s in strings.get("interesting", []) if "%p" in s or "%n" in s]
    uses_printf = bool(imports.intersection({"printf", "fprintf", "sprintf", "dprintf"}))
    got_writable = protections.get("relro") in {"partial", "none", None}
    if not (uses_printf and (fmt_strings or got_writable)):
        return None
    confidence = "medium"
    if fmt_strings and got_writable:
        confidence = "high"
    return DetectorFinding(
        name="format_string",
        confidence=confidence,
        details={
            "fmt_strings": fmt_strings,
            "got_writable": got_writable,
        },
    )


def detect_ret2win(context: dict[str, Any]) -> DetectorFinding | None:
    protections = context["protections"]
    symbols = context["symbols"]
    overflow = context.get("findings", {}).get("stack_overflow")
    if protections.get("pie") is True:
        return None
    win_functions = [f for f in symbols.get("functions", []) if f.get("name") in {"win", "get_flag", "flag"}]
    if not win_functions:
        return None
    confidence = "medium"
    if overflow:
        confidence = "high"
    return DetectorFinding(
        name="ret2win",
        confidence=confidence,
        details={
            "win_functions": win_functions,
        },
    )


def detect_ret2libc(context: dict[str, Any]) -> DetectorFinding | None:
    protections = context["protections"]
    symbols = context["symbols"]
    leaks = context["leaks"]
    imports = set(symbols.get("imports", []))
    if protections.get("nx") is False:
        return None
    if not imports.intersection({"puts", "printf", "write"}):
        return None
    if leaks.get("libc") not in {"likely", "possible"}:
        return None
    confidence = "medium" if protections.get("pie") is True else "high"
    return DetectorFinding(
        name="ret2libc",
        confidence=confidence,
        details={
            "leak_primitives": sorted(imports.intersection({"puts", "printf", "write"})),
        },
    )


def run_detectors(context: dict[str, Any]) -> dict[str, DetectorFinding]:
    findings: dict[str, DetectorFinding] = {}
    for detector in [
        detect_stack_overflow,
        detect_format_string,
        detect_ret2win,
        detect_ret2libc,
    ]:
        finding = detector(context)
        if finding:
            findings[finding.name] = finding
    return findings

from __future__ import annotations

from typing import Any


WEIGHTS = {
    "ret2win": {
        "has_win": 3,
        "no_pie": 2,
        "overflow": 2,
    },
    "ret2libc": {
        "has_leak": 2,
        "nx_enabled": 2,
        "puts_printf": 2,
    },
    "rop": {
        "overflow": 2,
        "nx_enabled": 1,
    },
    "format_string": {
        "fmt_strings": 3,
        "writable_got": 2,
    },
    "shellcode": {
        "nx_disabled": 3,
    },
    "srop": {
        "sigreturn": 1,
    },
}


def score_paths(context: dict[str, Any]) -> dict[str, Any]:
    scores: dict[str, Any] = {}
    protections = context.get("protections", {})
    strings = context.get("strings", {})
    input_surface = context.get("input_surface", {})
    got = context.get("exploit_primitives", {}).get("got", {})
    symbols = context.get("symbols", {})
    hidden = context.get("control_flow", {}).get("hidden_functions", [])

    def confidence(score: int) -> str:
        if score >= 5:
            return "HIGH"
        if score >= 3:
            return "MEDIUM"
        return "LOW"

    def add_score(name: str, score: int, reasons: list[str]) -> None:
        scores[name] = {
            "score": score,
            "confidence": confidence(score),
            "reasons": reasons,
        }

    overflow = bool(input_surface.get("input_functions"))
    no_pie = protections.get("pie") == "disabled"
    nx_enabled = protections.get("nx") == "enabled"
    nx_disabled = protections.get("nx") == "disabled"
    fmt_strings = bool(strings.get("format_strings"))
    writable_got = got.get("writable_got") is True
    has_win = bool(hidden)
    has_leak = bool(strings.get("format_strings"))
    puts_printf = any(name in symbols.get("imports", []) for name in ["puts", "printf", "write"])

    ret2win_score = 0
    ret2win_reasons: list[str] = []
    if has_win:
        ret2win_score += WEIGHTS["ret2win"]["has_win"]
        ret2win_reasons.append("win-like function found")
    if no_pie:
        ret2win_score += WEIGHTS["ret2win"]["no_pie"]
        ret2win_reasons.append("PIE disabled")
    if overflow:
        ret2win_score += WEIGHTS["ret2win"]["overflow"]
        ret2win_reasons.append("input functions present")
    add_score("ret2win", ret2win_score, ret2win_reasons)

    ret2libc_score = 0
    ret2libc_reasons: list[str] = []
    if has_leak:
        ret2libc_score += WEIGHTS["ret2libc"]["has_leak"]
        ret2libc_reasons.append("possible leak surface")
    if nx_enabled:
        ret2libc_score += WEIGHTS["ret2libc"]["nx_enabled"]
        ret2libc_reasons.append("NX enabled")
    if puts_printf:
        ret2libc_score += WEIGHTS["ret2libc"]["puts_printf"]
        ret2libc_reasons.append("libc output primitives")
    add_score("ret2libc", ret2libc_score, ret2libc_reasons)

    rop_score = 0
    rop_reasons: list[str] = []
    if overflow:
        rop_score += WEIGHTS["rop"]["overflow"]
        rop_reasons.append("input functions present")
    if nx_enabled:
        rop_score += WEIGHTS["rop"]["nx_enabled"]
        rop_reasons.append("NX enabled")
    add_score("rop", rop_score, rop_reasons)

    fmt_score = 0
    fmt_reasons: list[str] = []
    if fmt_strings:
        fmt_score += WEIGHTS["format_string"]["fmt_strings"]
        fmt_reasons.append("format strings detected")
    if writable_got:
        fmt_score += WEIGHTS["format_string"]["writable_got"]
        fmt_reasons.append("writable GOT")
    add_score("format_string", fmt_score, fmt_reasons)

    shellcode_score = WEIGHTS["shellcode"]["nx_disabled"] if nx_disabled else 0
    add_score("shellcode", shellcode_score, ["NX disabled"] if nx_disabled else [])

    add_score("srop", 0, [])

    return scores

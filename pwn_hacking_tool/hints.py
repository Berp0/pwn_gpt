from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HintPath:
    name: str
    confidence: str
    summary: str
    artifacts: dict[str, Any]


def build_hints(context: dict[str, Any]) -> list[HintPath]:
    hints: list[HintPath] = []
    findings = context.get("findings", {})
    if "ret2win" in findings:
        win_funcs = findings["ret2win"].details.get("win_functions", [])
        target = win_funcs[0] if win_funcs else {}
        hints.append(
            HintPath(
                name="ret2win",
                confidence=findings["ret2win"].confidence,
                summary="Direct control-flow to win-style function.",
                artifacts={
                    "target_function": target,
                    "payload_skeleton": "payload = b'A'*OFFSET + p64(WIN)",
                },
            )
        )
    if "ret2libc" in findings:
        leak_funcs = findings["ret2libc"].details.get("leak_primitives", [])
        hints.append(
            HintPath(
                name="ret2libc",
                confidence=findings["ret2libc"].confidence,
                summary="Leak libc address and return to system('/bin/sh').",
                artifacts={
                    "leak_primitives": leak_funcs,
                    "payload_skeleton": "leak puts@got -> libc base -> system('/bin/sh')",
                },
            )
        )
    if "format_string" in findings:
        hints.append(
            HintPath(
                name="format_string",
                confidence=findings["format_string"].confidence,
                summary="Potential uncontrolled printf; use %p/%n for leaks or writes.",
                artifacts={
                    "payload_skeleton": "payload = b'%p.%p.%p'",
                },
            )
        )
    if "stack_overflow" in findings and "ret2win" not in findings:
        hints.append(
            HintPath(
                name="stack_overflow",
                confidence=findings["stack_overflow"].confidence,
                summary="Classic stack overflow; find offset and ROP chain.",
                artifacts={
                    "payload_skeleton": "payload = b'A'*OFFSET + ROP_CHAIN",
                },
            )
        )
    return hints

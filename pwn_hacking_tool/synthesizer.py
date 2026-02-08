from __future__ import annotations

from typing import Any


def synthesize_paths(context: dict[str, Any]) -> list[dict[str, Any]]:
    scores = context.get("heuristic_scores", {})
    protections = context.get("protections", {})
    strings = context.get("strings", {})
    paths: list[dict[str, Any]] = []
    for name, data in scores.items():
        requirements = []
        missing = []
        if name == "ret2libc":
            if not strings.get("format_strings"):
                missing.append("libc leak primitive")
            if protections.get("pie") == "enabled":
                requirements.append("PIE leak or bypass")
        if name == "ret2win" and protections.get("pie") == "enabled":
            missing.append("PIE bypass or leak")
        paths.append(
            {
                "name": name,
                "score": data.get("score"),
                "confidence": data.get("confidence"),
                "reasons": data.get("reasons", []),
                "requirements": requirements,
                "missing": missing,
                "risks": ["unknown reachability"] if name == "ret2win" else [],
            }
        )
    return sorted(paths, key=lambda p: p.get("score", 0), reverse=True)

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import json_dump


@dataclass
class Report:
    context: dict[str, Any]

    def to_json(self) -> str:
        return json_dump(self.context)

    def to_explain_payload(self) -> str:
        payload = {
            "metadata": self.context.get("metadata"),
            "protections": self.context.get("protections"),
            "input_surface": self.context.get("input_surface"),
            "exploit_paths": self.context.get("exploit_paths"),
        }
        return json_dump(payload)

    def to_text(self) -> str:
        lines = ["[PWN BINARY INTELLIGENCE REPORT]", "", "Metadata:"]
        for key, value in self.context.get("metadata", {}).items():
            lines.append(f"  {key}: {value}")
        lines.append("\nProtections:")
        for key, value in self.context.get("protections", {}).items():
            lines.append(f"  {key}: {value}")
        lines.append("\nHeuristic Scores:")
        for name, data in self.context.get("heuristic_scores", {}).items():
            lines.append(f"  - {name}: {data.get('score')} ({data.get('confidence')})")
        lines.append("\nExploit Paths:")
        for path in self.context.get("exploit_paths", []):
            lines.append(f"  - {path['name']} (score: {path['score']}, {path['confidence']})")
            if path.get("reasons"):
                lines.append("    reasons: " + ", ".join(path["reasons"]))
            if path.get("missing"):
                lines.append("    missing: " + ", ".join(path["missing"]))
        return "\n".join(lines)

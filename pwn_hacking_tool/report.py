from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import json_dump


@dataclass
class AnalysisReport:
    context: dict[str, Any]
    findings: dict[str, Any]
    hints: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "findings": self.findings,
            "hints": self.hints,
        }

    def to_json(self) -> str:
        return json_dump(self.to_dict())

    def to_text(self) -> str:
        lines = [
            "[PWN HACKING TOOL REPORT]",
            "",
            "Binary:",
            f"  Path: {self.context['binary'].get('path')}",
            f"  Arch: {self.context['binary'].get('arch')}",
            f"  Stripped: {self.context['binary'].get('stripped')}",
            "",
            "Protections:",
        ]
        for key, value in self.context["protections"].items():
            lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("Findings:")
        if not self.findings:
            lines.append("  none")
        for name, finding in self.findings.items():
            lines.append(f"  - {name} (confidence: {finding['confidence']})")
        lines.append("")
        lines.append("Hint Paths:")
        if not self.hints:
            lines.append("  none")
        for hint in self.hints:
            lines.append(f"  - {hint['name']} ({hint['confidence']})")
            lines.append(f"    {hint['summary']}")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        lines = [
            "# PWN Hacking Tool Report",
            "",
            "## Binary",
            f"- **Path**: `{self.context['binary'].get('path')}`",
            f"- **Arch**: `{self.context['binary'].get('arch')}`",
            f"- **Stripped**: `{self.context['binary'].get('stripped')}`",
            "",
            "## Protections",
        ]
        for key, value in self.context["protections"].items():
            lines.append(f"- **{key}**: `{value}`")
        lines.append("")
        lines.append("## Findings")
        if not self.findings:
            lines.append("- none")
        for name, finding in self.findings.items():
            lines.append(f"- **{name}** (confidence: `{finding['confidence']}`)")
            if finding.get("details"):
                lines.append("  - details: " + json_dump(finding["details"]))
        lines.append("")
        lines.append("## Hint Paths")
        if not self.hints:
            lines.append("- none")
        for hint in self.hints:
            lines.append(f"- **{hint['name']}** (confidence: `{hint['confidence']}`)")
            lines.append(f"  - {hint['summary']}")
            if hint.get("artifacts"):
                lines.append("  - artifacts: " + json_dump(hint["artifacts"]))
        return "\n".join(lines)

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BinaryKnowledgeContext:
    metadata: dict[str, Any] = field(default_factory=dict)
    memory_layout: dict[str, Any] = field(default_factory=dict)
    protections: dict[str, Any] = field(default_factory=dict)
    imports: dict[str, Any] = field(default_factory=dict)
    symbols: dict[str, Any] = field(default_factory=dict)
    input_surface: dict[str, Any] = field(default_factory=dict)
    control_flow: dict[str, Any] = field(default_factory=dict)
    leak_surface: dict[str, Any] = field(default_factory=dict)
    exploit_primitives: dict[str, Any] = field(default_factory=dict)
    toolchain: dict[str, Any] = field(default_factory=dict)
    heuristic_scores: dict[str, Any] = field(default_factory=dict)
    exploit_paths: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "memory_layout": self.memory_layout,
            "protections": self.protections,
            "imports": self.imports,
            "symbols": self.symbols,
            "input_surface": self.input_surface,
            "control_flow": self.control_flow,
            "leak_surface": self.leak_surface,
            "exploit_primitives": self.exploit_primitives,
            "toolchain": self.toolchain,
            "heuristic_scores": self.heuristic_scores,
            "exploit_paths": self.exploit_paths,
        }

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BinaryContext:
    binary: dict[str, Any]
    protections: dict[str, Any]
    symbols: dict[str, Any]
    strings: dict[str, Any]
    control: dict[str, Any]
    leaks: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "protections": self.protections,
            "symbols": self.symbols,
            "strings": self.strings,
            "control": self.control,
            "leaks": self.leaks,
            "metadata": self.metadata,
        }

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .utils import ToolResult, run_tool, tool_exists


@dataclass
class ToolStatus:
    name: str
    available: bool
    version: str | None
    ok: bool
    reason: str | None = None


VERSION_COMMANDS: dict[str, list[list[str]]] = {
    "checksec": [["checksec", "--version"], ["checksec"]],
    "objdump": [["objdump", "--version"]],
    "readelf": [["readelf", "--version"]],
    "nm": [["nm", "--version"]],
    "strings": [["strings", "--version"]],
    "ldd": [["ldd", "--version"]],
    "ROPgadget": [["ROPgadget", "--version"]],
    "radare2": [["r2", "-v"], ["radare2", "-v"]],
    "gdb": [["gdb", "--version"]],
}


class ToolchainValidator:
    def __init__(self, tools: list[str]) -> None:
        self.tools = tools
        self.status: dict[str, ToolStatus] = {}

    def validate(self) -> dict[str, ToolStatus]:
        for tool in self.tools:
            self.status[tool] = self._validate_tool(tool)
        return self.status

    def _validate_tool(self, tool: str) -> ToolStatus:
        if not tool_exists(tool):
            return ToolStatus(name=tool, available=False, version=None, ok=False, reason="missing")
        commands = VERSION_COMMANDS.get(tool, [[tool, "--version"], [tool, "-V"], [tool]])
        result = self._run_first_ok(commands)
        if result is None:
            return ToolStatus(name=tool, available=True, version=None, ok=False, reason="no_output")
        version_line = (result.stdout or result.stderr).splitlines()[:1]
        version = version_line[0].strip() if version_line else None
        return ToolStatus(name=tool, available=True, version=version, ok=result.ok, reason=None)

    @staticmethod
    def _run_first_ok(commands: list[list[str]]) -> ToolResult | None:
        for cmd in commands:
            result = run_tool(cmd)
            if result.ok and (result.stdout or result.stderr):
                return result
        return None

    def capabilities(self) -> dict[str, str]:
        if not self.status:
            self.validate()
        return {name: ("available" if status.available else "missing") for name, status in self.status.items()}

    def is_available(self, tool: str) -> bool:
        if tool not in self.status:
            self.status[tool] = self._validate_tool(tool)
        return self.status[tool].available

    def ok(self, tool: str) -> bool:
        if tool not in self.status:
            self.status[tool] = self._validate_tool(tool)
        return self.status[tool].ok

    def require(self, tool: str, on_missing: Callable[[str], None] | None = None) -> bool:
        if not self.is_available(tool):
            if on_missing:
                on_missing(tool)
            return False
        return True

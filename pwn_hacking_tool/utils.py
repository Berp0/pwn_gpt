from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass
class ToolResult:
    command: list[str]
    stdout: str
    stderr: str
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_tool(command: Sequence[str], timeout: int = 10) -> ToolResult:
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ToolResult(
            command=list(command),
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            returncode=completed.returncode,
        )
    except FileNotFoundError:
        return ToolResult(command=list(command), stdout="", stderr="not found", returncode=127)
    except subprocess.TimeoutExpired:
        return ToolResult(command=list(command), stdout="", stderr="timeout", returncode=124)


def tool_exists(tool: str) -> bool:
    return shutil.which(tool) is not None


def uniq_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def json_dump(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)

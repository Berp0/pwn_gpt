from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
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


def is_elf(path: str | Path) -> bool:
    path_obj = Path(path)
    try:
        with path_obj.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def ensure_file(path: str | Path) -> None:
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f\"File not found: {path_obj}\")
    if not path_obj.is_file():
        raise ValueError(f\"Not a regular file: {path_obj}\")


def check_file_size(path: str | Path, max_bytes: int = 200 * 1024 * 1024) -> None:
    path_obj = Path(path)
    size = path_obj.stat().st_size
    if size <= 0:
        raise ValueError(\"File is empty.\")
    if size > max_bytes:
        raise ValueError(f\"File too large ({size} bytes). Max allowed is {max_bytes} bytes.\")

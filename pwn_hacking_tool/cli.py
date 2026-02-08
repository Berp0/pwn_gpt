from __future__ import annotations

import argparse
import platform
import subprocess
import tarfile
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from .adapters import (
    AdapterOutput,
    collect_adapter_metadata,
    detect_control,
    detect_leaks,
    run_checksec,
    run_file,
    run_nm,
    run_strings,
)
from .context import BinaryContext
from .detectors import run_detectors
from .hints import build_hints
from .report import AnalysisReport
from .utils import check_file_size, ensure_file, is_elf, tool_exists


def build_context(path: str, preflight_missing: list[str] | None = None) -> BinaryContext:
    output = AdapterOutput()
    binary_info = run_file(path, output)
    protections = run_checksec(path, output)
    symbols = run_nm(path, output)
    strings = run_strings(path, output)
    control = detect_control(symbols, protections)
    leaks = detect_leaks(strings, symbols)
    metadata = collect_adapter_metadata(output)
    if preflight_missing:
        metadata["preflight_missing"] = preflight_missing
    return BinaryContext(
        binary=binary_info,
        protections=protections,
        symbols=symbols,
        strings=strings,
        control=control,
        leaks=leaks,
        metadata=metadata,
    )


def build_report(context: BinaryContext) -> AnalysisReport:
    context_dict = context.to_dict()
    findings = run_detectors(context_dict)
    context_dict["findings"] = {name: finding.__dict__ for name, finding in findings.items()}
    hints = [hint.__dict__ for hint in build_hints(context_dict)]
    return AnalysisReport(context=context_dict, findings=context_dict["findings"], hints=hints)


REQUIRED_TOOLS = ["strings", "nm"]
OPTIONAL_TOOLS = ["file", "checksec"]


def preflight_tools() -> list[str]:
    required_tools = REQUIRED_TOOLS
    optional_tools = OPTIONAL_TOOLS
    missing = [tool for tool in required_tools if not tool_exists(tool)]
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")
    optional_missing = [tool for tool in optional_tools if not tool_exists(tool)]
    return optional_missing


def install_instructions(tools: list[str]) -> str:
    system = platform.system().lower()
    if system == "linux":
        return (
            "Linux detected. Install with your package manager, e.g.:\n"
            "  Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y "
            + " ".join(tools)
            + "\n"
            "  Fedora: sudo dnf install -y "
            + " ".join(tools)
            + "\n"
            "  Arch: sudo pacman -S "
            + " ".join(tools)
        )
    if system == "darwin":
        return "macOS detected. Install with Homebrew:\n  brew install " + " ".join(tools)
    return f"Unknown OS. Please install: {', '.join(tools)}"


def install_tools(tools: list[str]) -> None:
    safe_tools = [tool for tool in tools if tool in REQUIRED_TOOLS + OPTIONAL_TOOLS]
    if not safe_tools:
        raise RuntimeError("No known tools to install.")
    system = platform.system().lower()
    if system != "linux":
        raise RuntimeError(install_instructions(tools))
    package_managers = [
        ("apt-get", ["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y"]),
        ("dnf", [], ["sudo", "dnf", "install", "-y"]),
        ("pacman", [], ["sudo", "pacman", "-S"]),
    ]
    for manager, update_cmd, install_cmd in package_managers:
        if tool_exists(manager):
            if update_cmd:
                subprocess.run(update_cmd, check=False)
            subprocess.run(install_cmd + safe_tools, check=False)
            return
    raise RuntimeError(install_instructions(tools))


def extract_archive(path: str) -> tuple[str, TemporaryDirectory] | None:
    archive_path = Path(path)
    if not archive_path.exists():
        return None
    suffixes = "".join(archive_path.suffixes)
    if suffixes not in {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2"}:
        return None
    temp_dir = TemporaryDirectory()
    extract_path = Path(temp_dir.name)
    if suffixes == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(extract_path)
    else:
        with tarfile.open(archive_path) as archive:
            archive.extractall(extract_path)
    for file_path in extract_path.rglob("*"):
        if file_path.is_file() and is_elf(file_path):
            return str(file_path), temp_dir
    temp_dir.cleanup()
    raise RuntimeError("No ELF binary found inside archive.")


def sanity_check(path: str) -> None:
    ensure_file(path)
    check_file_size(path)
    if not is_elf(path):
        raise ValueError("Selected file is not an ELF binary.")


def analyze_path(path: str, fmt: str, install_missing: bool = False) -> str:
    try:
        preflight_missing = preflight_tools()
    except RuntimeError as exc:
        missing_tools = [tool.strip() for tool in str(exc).split(": ", 1)[-1].split(", ")]
        missing_tools = [tool for tool in missing_tools if tool in REQUIRED_TOOLS]
        if install_missing:
            install_tools(missing_tools)
            preflight_missing = preflight_tools()
        else:
            raise RuntimeError(f"{exc}\n\n{install_instructions(missing_tools)}") from exc
    extracted = extract_archive(path)
    temp_dir = None
    try:
        if extracted:
            path, temp_dir = extracted
        sanity_check(path)
        report = build_report(build_context(path, preflight_missing))
        if fmt == "json":
            return report.to_json()
        if fmt == "markdown":
            return report.to_markdown()
        return report.to_text()
    finally:
        if temp_dir:
            temp_dir.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PWN Hacking Tool")
    parser.add_argument("binary", help="Path to ELF binary")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Attempt to install missing required tools using the system package manager.",
    )
    return parser.parse_args()


def write_output(content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(content)
    else:
        print(content)


def main() -> None:
    args = parse_args()
    content = analyze_path(args.binary, args.format, install_missing=args.install_tools)
    write_output(content, args.output)


if __name__ == "__main__":
    main()

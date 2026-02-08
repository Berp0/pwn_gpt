from __future__ import annotations

import argparse
import platform
import subprocess
import tarfile
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from .context import BinaryKnowledgeContext
from .extractors.callgraph import extract_callgraph
from .extractors.fingerprint import extract_fingerprint
from .extractors.got import extract_got
from .extractors.imports import extract_imports
from .extractors.input_surface import extract_input_surface
from .extractors.stack import analyze_stack_frame
from .extractors.strings import extract_strings
from .extractors.toolchain import extract_toolchain_fingerprint
from .extractors.protections import extract_protections
from .reporting import Report
from .scoring import score_paths
from .synthesizer import synthesize_paths
from .utils import check_file_size, ensure_file, is_elf, tool_exists
from .validators import ToolchainValidator

REQUIRED_TOOLS = ["strings", "nm"]
OPTIONAL_TOOLS = ["file", "checksec", "readelf", "objdump", "ldd", "ROPgadget", "r2", "gdb"]


def preflight_tools() -> list[str]:
    missing = [tool for tool in REQUIRED_TOOLS if not tool_exists(tool)]
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")
    return [tool for tool in OPTIONAL_TOOLS if not tool_exists(tool)]


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
        raise RuntimeError(install_instructions(safe_tools))
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
    raise RuntimeError(install_instructions(safe_tools))


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


def build_context(path: str, validator: ToolchainValidator, preflight_missing: list[str]) -> BinaryKnowledgeContext:
    metadata = extract_fingerprint(path, validator)
    protections = extract_protections(path, validator)
    imports_data = extract_imports(path, validator)
    strings_data = extract_strings(path, validator)
    input_surface = extract_input_surface(imports_data.get("imports", []))
    stack = analyze_stack_frame()
    got = extract_got(path, validator, protections.get("relro", "unknown"))
    callgraph = extract_callgraph(imports_data.get("functions", []))
    toolchain = extract_toolchain_fingerprint(path, validator)

    context = BinaryKnowledgeContext(
        metadata=metadata,
        protections=protections,
        imports={"imports": imports_data.get("imports", [])},
        symbols={"functions": imports_data.get("functions", [])},
        input_surface=input_surface,
        control_flow=callgraph,
        leak_surface={"format_strings": strings_data.get("format_strings", [])},
        exploit_primitives={"got": got, "stack": stack},
        toolchain={
            "capabilities": validator.capabilities(),
            "preflight_missing": preflight_missing,
            "fingerprint": toolchain,
        },
    )
    context.metadata["strings"] = strings_data
    return context


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
        validator = ToolchainValidator(REQUIRED_TOOLS + OPTIONAL_TOOLS)
        validator.validate()
        context = build_context(path, validator, preflight_missing)
        context_dict = context.to_dict()
        context_dict["heuristic_scores"] = score_paths(context_dict)
        context_dict["exploit_paths"] = synthesize_paths(context_dict)
        report = Report(context_dict)
        if fmt == "json":
            return report.to_json()
        if fmt == "explain":
            return report.to_explain_payload()
        return report.to_text()
    finally:
        if temp_dir:
            temp_dir.cleanup()


def validate_tools() -> str:
    validator = ToolchainValidator(REQUIRED_TOOLS + OPTIONAL_TOOLS)
    status = validator.validate()
    lines = ["[TOOLCHAIN VALIDATION]"]
    for tool, state in status.items():
        lines.append(f"- {tool}: {'available' if state.available else 'missing'}")
        if state.version:
            lines.append(f"  version: {state.version}")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PWN Binary Intelligence Tool v0.4")
    parser.add_argument("binary", nargs="?", help="Path to ELF binary")
    parser.add_argument(
        "--format",
        choices=["text", "json", "explain"],
        default="text",
        help="Output format",
    )
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Attempt to install missing required tools using the system package manager.",
    )
    parser.add_argument(
        "--install-tools-only",
        action="store_true",
        help="Install required tools and exit without analyzing a binary.",
    )
    parser.add_argument(
        "--validate-tools",
        action="store_true",
        help="Validate available tools and exit.",
    )
    return parser.parse_args()


def write_output(content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(content)
    else:
        print(content)


def main() -> None:
    args = parse_args()
    if args.install_tools_only:
        install_tools(REQUIRED_TOOLS)
        print("Tools installation attempted. Re-run with --validate-tools to verify.")
        return
    if args.validate_tools:
        write_output(validate_tools(), args.output)
        return
    if not args.binary:
        raise SystemExit("Binary path required unless using --install-tools-only or --validate-tools.")
    content = analyze_path(args.binary, args.format, install_missing=args.install_tools)
    write_output(content, args.output)


if __name__ == "__main__":
    main()

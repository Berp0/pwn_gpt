from __future__ import annotations

import argparse
import json
from pathlib import Path

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


def build_context(path: str) -> BinaryContext:
    output = AdapterOutput()
    binary_info = run_file(path, output)
    protections = run_checksec(path, output)
    symbols = run_nm(path, output)
    strings = run_strings(path, output)
    control = detect_control(symbols, protections)
    leaks = detect_leaks(strings, symbols)
    metadata = collect_adapter_metadata(output)
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
    return parser.parse_args()


def write_output(report: AnalysisReport, fmt: str, output_path: str | None) -> None:
    if fmt == "json":
        content = report.to_json()
    elif fmt == "markdown":
        content = report.to_markdown()
    else:
        content = report.to_text()
    if output_path:
        Path(output_path).write_text(content)
    else:
        print(content)


def main() -> None:
    args = parse_args()
    report = build_report(build_context(args.binary))
    write_output(report, args.format, args.output)


if __name__ == "__main__":
    main()

"""Sentinel's command-line interface and process exit contract."""

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import AnalysisError, analyze, canonical_path, MAX_LINE_BYTES
from .models import DetectionConfig
from .reporting import render_report, visible, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Offline SSH/auth log analyzer")
    parser.add_argument("--version", action="version", version=f"Sentinel {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("analyze", help="detect repeated SSH authentication failures")
    command.add_argument("inputs", nargs="+", metavar="LOG", help="UTF-8 logs, or '-' for stdin")
    command.add_argument("--threshold", type=int, default=5, help="failures needed for an alert (default: 5)")
    command.add_argument("--window-seconds", type=int, default=300, help="rolling window in seconds (default: 300)")
    command.add_argument("--year", type=int, default=datetime.now(timezone.utc).year,
                         help="first legacy syslog year per input (default: current UTC year)")
    command.add_argument("--timezone", default="UTC", metavar="OFFSET",
                         help="timezone for timestamps without offsets: UTC or +/-HH:MM (default: UTC)")
    command.add_argument("--format", choices=("text", "json", "csv"), default="text")
    command.add_argument("-o", "--output", help="report destination (default or '-': stdout)")
    command.add_argument("--force", action="store_true", help="replace an existing report file")
    command.add_argument("--strict", action="store_true", help="fail without a report if any line is malformed")
    command.add_argument("--fail-on-alert", action="store_true", help="exit 1 after reporting if alerts exist")
    command.add_argument("--max-line-bytes", type=int, default=MAX_LINE_BYTES,
                         help=f"maximum bytes per physical line, including newline (default: {MAX_LINE_BYTES})")
    return parser


def _validate_output(output: Path, inputs: list[str], overwrite: bool) -> None:
    for source in inputs:
        if source == "-":
            continue
        source_path = Path(source)
        same_path = canonical_path(source_path) == canonical_path(output)
        same_file = output.exists() and source_path.exists() and output.samefile(source_path)
        if same_path or same_file:
            raise AnalysisError("output must not replace an input log")
    if output.exists() and not overwrite:
        raise AnalysisError("output already exists; choose a new path or use --force")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = DetectionConfig(args.threshold, args.window_seconds)
        output = Path(args.output) if args.output and args.output != "-" else None
        if output is not None:
            _validate_output(output, args.inputs, args.force)
        result = analyze(args.inputs, config, year=args.year, timezone_name=args.timezone,
                         max_line_bytes=args.max_line_bytes)
        for diagnostic in result.diagnostics:
            print(f"warning: {visible(diagnostic.source)}:{diagnostic.line_number}: {diagnostic.reason}",
                  file=sys.stderr)
        if result.diagnostics_omitted:
            print(f"warning: {result.diagnostics_omitted} additional malformed lines omitted", file=sys.stderr)
        if args.strict and result.stats.malformed_lines:
            raise AnalysisError(f"strict mode: {result.stats.malformed_lines} malformed line(s); no report written")
        content = render_report(result, args.format)
        if output is None:
            sys.stdout.write(content)
            sys.stdout.flush()
        else:
            write_report(output, content, overwrite=args.force)
            print(f"Wrote {visible(str(output))} ({len(result.alerts)} alerts)", file=sys.stderr)
        return 1 if args.fail_on_alert and result.alerts else 0
    except BrokenPipeError:
        # Avoid a second exception during interpreter shutdown when piping to head.
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
        except OSError:
            pass
        return 2
    except (AnalysisError, OSError, ValueError) as exc:
        print(f"sentinel: error: {visible(str(exc))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("sentinel: interrupted", file=sys.stderr)
        return 130

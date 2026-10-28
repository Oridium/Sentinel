"""Bounded line reads, input validation, diagnostics, and analysis orchestration."""

import sys
from pathlib import Path
from typing import BinaryIO, Iterator

from .detectors import detect_brute_force
from .models import AnalysisResult, AuthEvent, DetectionConfig, Diagnostic
from .parser import SSHLogParser, parse_timezone

MAX_LINE_BYTES = 65_536
DIAGNOSTIC_LIMIT = 20


class AnalysisError(Exception):
    """An operational error suitable for a concise CLI message."""


def canonical_path(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        # Python versions differ in which exception a symlink loop raises.
        raise AnalysisError(f"cannot resolve path {str(path)!r}: {exc}") from exc


def validate_inputs(inputs: list[str]) -> None:
    if not inputs:
        raise AnalysisError("provide at least one input path or '-' for standard input")
    seen: set[str] = set()
    for source in inputs:
        identity = "<stdin>" if source == "-" else str(canonical_path(Path(source)))
        if identity in seen:
            raise AnalysisError(f"duplicate input: {source!r}")
        seen.add(identity)


def read_lines(stream: BinaryIO, max_line_bytes: int) -> Iterator[tuple[int, str | None, str | None]]:
    """Skip oversized physical lines without retaining the entire line in memory."""
    number = 0
    while True:
        chunk = stream.readline(max_line_bytes + 1)
        if not chunk:
            return
        number += 1
        if len(chunk) > max_line_bytes:
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(max_line_bytes + 1)
            yield number, None, f"line exceeds {max_line_bytes} bytes"
            continue
        try:
            yield number, chunk.decode("utf-8"), None
        except UnicodeDecodeError:
            yield number, None, "line is not valid UTF-8"


def analyze(
    inputs: list[str], config: DetectionConfig, *, year: int,
    timezone_name: str = "UTC", max_line_bytes: int = MAX_LINE_BYTES,
    stdin: BinaryIO | None = None,
) -> AnalysisResult:
    validate_inputs(inputs)
    assumed_timezone = parse_timezone(timezone_name)
    if not 1 <= year <= 9999:
        raise ValueError("year must be between 1 and 9999")
    if not 1 <= max_line_bytes <= 16_777_216:
        raise ValueError("max_line_bytes must be between 1 and 16777216")
    result = AnalysisResult(config, list(inputs), year, str(assumed_timezone))
    failures: list[AuthEvent] = []

    def consume(stream: BinaryIO, source: str) -> None:
        parser = SSHLogParser(year, assumed_timezone)
        for line_number, line, read_error in read_lines(stream, max_line_bytes):
            result.stats.total_lines += 1
            parsed = parser.parse_line(line, source, line_number) if line is not None else None
            error = read_error or (parsed.error if parsed else None)
            if error:
                result.stats.malformed_lines += 1
                if len(result.diagnostics) < DIAGNOSTIC_LIMIT:
                    result.diagnostics.append(Diagnostic(source, line_number, error))
                else:
                    result.diagnostics_omitted += 1
                continue
            event = parsed.event if parsed else None
            if event is None:
                result.stats.ignored_lines += 1
                continue
            result.stats.parsed_events += 1
            if event.outcome == "failure":
                result.stats.failed_logins += 1
                failures.append(event)
            else:
                result.stats.successful_logins += 1
            first, last = result.stats.first_event, result.stats.last_event
            result.stats.first_event = min(first, event.timestamp) if first else event.timestamp
            result.stats.last_event = max(last, event.timestamp) if last else event.timestamp

    for source in inputs:
        try:
            if source == "-":
                consume(stdin if stdin is not None else sys.stdin.buffer, "<stdin>")
            else:
                with Path(source).open("rb") as stream:
                    consume(stream, source)
        except OSError as exc:
            raise AnalysisError(f"cannot read input {source!r}: {exc.strerror or str(exc)}") from exc
    result.alerts = detect_brute_force(failures, config)
    return result

"""Human-readable, structured JSON, and spreadsheet-safe CSV reports."""

import csv
import io
import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .models import Alert, AnalysisResult


def utc_string(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def visible(value: str) -> str:
    """Keep untrusted log fields from injecting terminal control sequences."""
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value)


def alert_dict(alert: Alert) -> dict[str, Any]:
    data = asdict(alert)
    data["first_seen"] = utc_string(alert.first_seen)
    data["last_seen"] = utc_string(alert.last_seen)
    data["usernames"] = list(alert.usernames)
    data["evidence"] = [{"source": source, "line_number": line} for source, line in alert.evidence]
    data["evidence_omitted"] = alert.attempt_count - len(alert.evidence)
    return data


def report_dict(result: AnalysisResult) -> dict[str, Any]:
    stats = asdict(result.stats)
    stats["first_event"] = utc_string(result.stats.first_event)
    stats["last_event"] = utc_string(result.stats.last_event)
    stats["alert_count"] = len(result.alerts)
    stats["alerts_by_severity"] = {
        severity: sum(alert.severity == severity for alert in result.alerts)
        for severity in ("medium", "high", "critical")
    }
    return {
        "schema_version": "1.0", "tool": "sentinel", "tool_version": __version__,
        "generated_at": utc_string(datetime.now(timezone.utc)),
        "inputs": result.inputs,
        "configuration": {
            **asdict(result.config), "assumed_year": result.assumed_year,
            "assumed_timezone": result.assumed_timezone,
        },
        "summary": stats, "alerts": [alert_dict(alert) for alert in result.alerts],
        "diagnostics": [asdict(item) for item in result.diagnostics],
        "diagnostics_omitted": result.diagnostics_omitted,
    }


CSV_FIELDS = (
    "alert_id", "rule", "severity", "host", "source_ip", "first_seen", "last_seen",
    "attempt_count", "peak_window_count", "threshold", "window_seconds", "usernames",
    "evidence", "evidence_omitted",
)


def csv_safe(value: Any) -> Any:
    # Leading whitespace can conceal a spreadsheet formula. JSON remains lossless.
    if isinstance(value, str) and (value.lstrip().startswith(("=", "+", "-", "@"))
                                   or value.startswith(("\t", "\r", "\n"))):
        return "'" + value
    return value


def render_report(result: AnalysisResult, report_format: str) -> str:
    if report_format == "json":
        return json.dumps(report_dict(result), indent=2, ensure_ascii=True) + "\n"
    if report_format == "csv":
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for alert in result.alerts:
            data = alert_dict(alert)
            for field in ("usernames", "evidence"):
                data[field] = json.dumps(data[field], ensure_ascii=True, separators=(",", ":"))
            writer.writerow({key: csv_safe(data[key]) for key in CSV_FIELDS})
        return output.getvalue()
    if report_format != "text":
        raise ValueError(f"unsupported report format: {report_format!r}")
    stats = result.stats
    lines = [
        f"Sentinel {__version__} | SSH authentication analysis",
        f"Lines: {stats.total_lines} | Parsed: {stats.parsed_events} | "
        f"Ignored: {stats.ignored_lines} | Malformed: {stats.malformed_lines}",
        f"Failed logins: {stats.failed_logins} | Successful logins: {stats.successful_logins}",
        f"Rule: >= {result.config.threshold} failures in {result.config.window_seconds}s "
        "per host/source IP (inclusive rolling window)",
        f"Alerts: {len(result.alerts)}",
    ]
    if not result.alerts:
        lines.append("No brute-force alerts matched the configured rule.")
    for alert in result.alerts:
        lines.extend([
            "",
            f"[{alert.severity.upper()}] {visible(alert.host)} <- {alert.source_ip} "
            f"| {alert.attempt_count} failures | peak {alert.peak_window_count}/{alert.window_seconds}s",
            f"  {utc_string(alert.first_seen)} to {utc_string(alert.last_seen)}",
            f"  Users: {', '.join(visible(name) for name in alert.usernames)}",
            f"  ID: {alert.alert_id}",
        ])
    return "\n".join(lines) + "\n"


def write_report(path: Path, content: str, *, overwrite: bool = False) -> None:
    """Publish a complete report in one operation; never leave a partial report."""
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            # Linking in the same directory atomically refuses existing destinations.
            os.link(temporary, path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


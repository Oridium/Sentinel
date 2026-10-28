"""Typed records shared by parsing, detection, and reporting."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["medium", "high", "critical"]


@dataclass(frozen=True)
class DetectionConfig:
    threshold: int = 5
    window_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self.threshold) is not int or self.threshold < 1:
            raise ValueError("threshold must be a positive integer")
        if type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 31_536_000:
            raise ValueError("window_seconds must be between 1 and 31536000 (365 days)")


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    source_ip: str
    username: str
    outcome: Literal["failure", "success"]
    method: str
    port: int
    invalid_user: bool
    source: str
    line_number: int

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("event timestamps must be timezone-aware")


@dataclass(frozen=True)
class ParseResult:
    event: AuthEvent | None = None
    error: str | None = None


@dataclass(frozen=True)
class Diagnostic:
    source: str
    line_number: int
    reason: str


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule: str
    severity: Severity
    host: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    attempt_count: int
    peak_window_count: int
    threshold: int
    window_seconds: int
    usernames: tuple[str, ...]
    evidence: tuple[tuple[str, int], ...]


@dataclass
class AnalysisStats:
    total_lines: int = 0
    parsed_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    ignored_lines: int = 0
    malformed_lines: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None


@dataclass
class AnalysisResult:
    config: DetectionConfig
    inputs: list[str]
    assumed_year: int
    assumed_timezone: str
    stats: AnalysisStats = field(default_factory=AnalysisStats)
    alerts: list[Alert] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    diagnostics_omitted: int = 0


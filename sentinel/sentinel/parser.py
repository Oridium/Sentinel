"""Parse canonical OpenSSH Failed/Accepted records without counting PAM twice."""

import ipaddress
import re
from datetime import datetime, timedelta, timezone, tzinfo

from .models import AuthEvent, ParseResult

MONTHS = {name: number for number, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1
)}
ENVELOPE = re.compile(
    r"^(?P<prefix>.+?)[ \t]+sshd(?:-session)?(?:\[\d+\])?:[ \t]*(?P<message>.*)$"
)
LEGACY = re.compile(
    r"^(?P<month>[A-Za-z]{3})[ \t]+(?P<day>\d{1,2})[ \t]+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})[ \t]+(?P<host>\S+)$"
)
ISO = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?)[ \t]+(?P<host>\S+)$"
)
AUTH = re.compile(
    r"^(?P<action>Failed|Accepted) (?P<method>\S+) for "
    r"(?P<invalid>invalid user )?(?P<username>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)(?:[ \t].*)?$"
)


def parse_timezone(value: str) -> tzinfo:
    """Accept UTC or a fixed offset; do not silently infer the machine timezone."""
    if value.upper() in ("UTC", "Z"):
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", value)
    if not match:
        raise ValueError("timezone must be UTC or a fixed offset such as -04:00")
    hours, minutes = int(match[2]), int(match[3])
    if hours > 23 or minutes > 59:
        raise ValueError("timezone offset must be less than 24 hours, with minutes 00..59")
    offset = timedelta(hours=hours, minutes=minutes)
    return timezone(offset if match[1] == "+" else -offset)


class SSHLogParser:
    """One instance per input; --year refers to its first legacy timestamp.

    A December-to-January transition in file order advances the inferred year.
    Explicit ISO years do not modify this legacy clock.
    """

    def __init__(self, year: int, assumed_timezone: tzinfo = timezone.utc) -> None:
        if not 1 <= year <= 9999:
            raise ValueError("year must be between 1 and 9999")
        self.year = year
        self.assumed_timezone = assumed_timezone
        self._previous_month: int | None = None

    def _timestamp(self, prefix: str) -> tuple[datetime, str]:
        match = LEGACY.fullmatch(prefix)
        if match:
            month = MONTHS.get(match["month"])
            if month is None:
                raise ValueError("unknown month")
            year = self.year + int(self._previous_month == 12 and month == 1)
            timestamp = datetime(
                year, month, int(match["day"]), int(match["hour"]),
                int(match["minute"]), int(match["second"]), tzinfo=self.assumed_timezone,
            ).astimezone(timezone.utc)
            self.year = year
            self._previous_month = month
            return timestamp, match["host"]
        match = ISO.fullmatch(prefix)
        if match:
            timestamp = datetime.fromisoformat(match["stamp"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=self.assumed_timezone)
            return timestamp.astimezone(timezone.utc), match["host"]
        raise ValueError("unsupported timestamp/header")

    def parse_line(self, line: str, source: str, line_number: int) -> ParseResult:
        envelope = ENVELOPE.fullmatch(line.rstrip("\r\n"))
        if not envelope:
            return ParseResult()
        # Parse headers on all sshd records so a quiet New Year still rolls over.
        try:
            timestamp, host = self._timestamp(envelope["prefix"])
        except (ValueError, OverflowError):
            return ParseResult(error="invalid or unsupported SSH timestamp/header")
        message = envelope["message"]
        match = AUTH.fullmatch(message)
        if not match:
            if message.startswith(("Failed ", "Accepted ")):
                return ParseResult(error="unsupported or malformed SSH authentication record")
            return ParseResult()  # Invalid user / PAM / disconnect messages are not failures.
        try:
            if "%" in match["ip"]:
                raise ValueError("scoped addresses are not supported")
            address = ipaddress.ip_address(match["ip"])
            # Treat IPv4 and IPv4-mapped IPv6 representations as the same source.
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            port = int(match["port"])
            if not 1 <= port <= 65535:
                raise ValueError("port out of range")
        except ValueError:
            return ParseResult(error="invalid source IP address or source port")
        return ParseResult(event=AuthEvent(
            timestamp=timestamp, host=host, source_ip=str(address),
            username=match["username"],
            outcome="failure" if match["action"] == "Failed" else "success",
            method=match["method"], port=port, invalid_user=bool(match["invalid"]),
            source=source, line_number=line_number,
        ))

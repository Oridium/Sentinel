"""Interfaces for later API adapters, deliberately not wired to the CLI."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CVEFinding:
    cve_id: str
    summary: str
    reference_url: str
    provider: str


@dataclass(frozen=True)
class ThreatIntelFinding:
    indicator: str
    verdict: str
    provider: str
    reference_url: str | None = None


class CVEProvider(Protocol):
    def lookup(self, product: str, version: str | None = None) -> list[CVEFinding]:
        """Return findings for explicit inventory data; an SSH log is not inventory."""
        ...


class ThreatIntelProvider(Protocol):
    def lookup_ip(self, address: str) -> list[ThreatIntelFinding]:
        """Enrich an address only when the caller explicitly enables the provider."""
        ...

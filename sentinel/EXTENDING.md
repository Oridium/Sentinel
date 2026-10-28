# Extending Sentinel

## Add a parser or detection rule

Keep vendor-specific parsing in a separate module and emit `AuthEvent` records
with timezone-aware timestamps. Validate source addresses, and preserve source
filename and line number for evidence. Decide explicitly which records represent
one authentication attempt so additional PAM messages do not inflate counts.

New detectors should accept normalized events/configuration and return typed
results. Keep file I/O and report rendering outside detection logic. Tests should
cover a true positive, a near miss, exact boundaries, and malformed data.

The public starting points are:

```python
from sentinel.analyzer import analyze
from sentinel.models import DetectionConfig
from sentinel.reporting import render_report

result = analyze(
    ["samples/auth.log"],
    DetectionConfig(threshold=5, window_seconds=300),
    year=2026,
    timezone_name="UTC",
)
print(render_report(result, "json"), end="")
```

## Add a threat intelligence adapter

Implement `ThreatIntelProvider.lookup_ip(address) -> list[ThreatIntelFinding]`
in a new integration module. Each finding identifies the indicator, provider,
provider verdict, and optional source URL. Keep provider verdicts separate from
the brute-force rule's local severity.

The following is a local test double demonstrating the interface. Its result is
explicitly synthetic; it does not make an external claim about an IP address:

```python
from sentinel.integrations import ThreatIntelFinding, ThreatIntelProvider

class FixtureProvider:
    def lookup_ip(self, address: str) -> list[ThreatIntelFinding]:
        return [ThreatIntelFinding(
            indicator=address,
            verdict="synthetic-test-result",
            provider="local-fixture",
        )]

provider: ThreatIntelProvider = FixtureProvider()
findings = provider.lookup_ip("192.0.2.10")
```

For an eventual network provider:

- Make enrichment explicitly opt-in; keep offline analysis as the default.
- Read credentials from a provider-specific environment variable or a secret
  manager at runtime. Do not commit keys, put them into CLI arguments, or log them.
- Use HTTPS, finite connection/read timeouts, bounded retries/backoff, response
  validation, rate-limit handling, and a cache with an explicit expiry.
- Skip private, reserved, and documentation addresses unless a provider contract
  explicitly supports them. Do not submit raw logs, usernames, or internal hostnames.
- Distinguish unavailable/error/unknown results from a clean verdict. Enrichment
  failure should leave the local detection report available with a clear status.
- Record provider and lookup time, then add a versioned report field with tests
  using mocked responses. Avoid live network calls in the ordinary test suite.

No HTTP client, credential loader, provider registration, or enrichment CLI flag
is implemented in this base project. Choose and implement those when a concrete
provider is selected.

## Add a CVE adapter

Implement `CVEProvider.lookup(product, version=None) -> list[CVEFinding]` using
explicit software inventory as input. SSH failure logs do not establish the
installed OpenSSH version or whether a CVE applies. Preserve CVE identifiers,
provider names, summaries, and source URLs, and treat uncertain product matches
as uncertain. Apply the same opt-in, credential, timeout, and testing conventions.

Potential later features include an inventory-backed `cve` subcommand,
configuration files, allowlists, successful-login correlation, streaming windows,
and additional Windows/web-server parsers. None are advertised as implemented.


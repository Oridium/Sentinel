# Sentinel SOC Toolkit

A runnable, modular Python foundation for offline Linux SSH/auth log analysis.
Sentinel parses authentication records, detects repeated failures in rolling
time windows, assigns severity, and writes text, JSON, or CSV reports.

**Python 3.10+; no third-party runtime dependencies, API keys, or network calls.**
The included logs are synthetic and use documentation-only IPv4/IPv6 addresses.

## Quick start

Extract `sentinel-0.1.0.zip`, open a terminal, and enter its `sentinel` directory.
On macOS or Linux:

```sh
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m sentinel analyze samples/auth.log --year 2026
python -m unittest discover -s tests -v
```

`requirements.txt` documents that no runtime packages are needed. Its install
step is a no-op; the module command works directly from the extracted folder,
even without a virtual environment or internet access.

On Windows PowerShell, use the virtual environment's Python directly:

```powershell
cd sentinel
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m sentinel analyze samples/auth.log --year 2026
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Install the `sentinel` command

With your virtual environment active, the included wheel installs offline:

```sh
python -m pip install --no-index dist/sentinel_soc_toolkit-0.1.0-py3-none-any.whl
sentinel --version
sentinel analyze samples/auth.log --year 2026
```

For development, `python -m pip install -e .` installs from source. A regular
source install uses `python -m pip install .`. Both may download the setuptools
build dependency; runtime analysis still uses only Python's standard library.
The wheel contains the Python package. Logs, tests, and documentation stay in
the extracted project directory, so sample commands should run there.

## Usage

```sh
# Customize the failure threshold and rolling time window.
python -m sentinel analyze samples/auth.log --threshold 8 --window-seconds 120 --year 2026

# Write machine-readable reports. Create the parent directory first.
mkdir reports
python -m sentinel analyze samples/auth.log --year 2026 --format json -o reports/alerts.json
python -m sentinel analyze samples/auth.log --year 2026 --format csv -o reports/alerts.csv

# Add --force to explicitly replace an existing report.
python -m sentinel analyze samples/auth.log --year 2026 --format json -o reports/alerts.json --force

# Combine non-overlapping inputs; events are sorted before detection.
python -m sentinel analyze samples/auth.log samples/benign.log --year 2026

# Read a pipe; '-' denotes standard input.
cat samples/auth.log | python -m sentinel analyze - --year 2026 --format json

# Legacy logs written in a fixed UTC-04:00 offset.
# Use '=' so argparse recognizes the negative offset as the value.
python -m sentinel analyze samples/benign.log --year 2026 --timezone=-04:00

# Report alerts and signal their presence to an automation script.
python -m sentinel analyze samples/auth.log --year 2026 --fail-on-alert

# Demonstrate error handling; this intentionally exits with code 2.
python -m sentinel analyze samples/malformed.log --year 2026 --strict

python -m sentinel analyze --help
```

Use a readable copy of `/var/log/auth.log` or `/var/log/secure` in place of a
sample path. Sentinel reads files and does not change logs, block IPs, or modify
SSH configuration. Compressed archives and live tailing are not implemented.

### Sample result

The main sample has **45 lines, 37 failed logins, 2 successful logins, 6 ignored
lines, and 0 malformed lines**. With threshold 5 and window 300 seconds:

| Host | Source IP | Failures | Peak in 300 seconds | Severity |
| --- | --- | ---: | ---: | --- |
| web-01 | 198.51.100.23 | 5 | 5 | medium |
| web-01 | 203.0.113.77 | 10 | 10 | high |
| bastion-01 | 2001:db8::b | 20 | 20 | critical |

Full generated reports are in `examples/sample-report.txt`,
`examples/sample-report.json`, and `examples/sample-report.csv`.
`samples/benign.log` yields no alerts with the defaults.
`samples/malformed.log` contains three intentional errors and one valid failure.

## Detection rules

1. Group failures by **destination hostname and normalized source IP**. Username
   changes do not split a group, so one source trying multiple accounts counts.
2. Sort failures by timestamp. At each failure, count failures in the inclusive
   interval `[timestamp - window, timestamp]`. Exactly 300 seconds apart is
   inside a 300-second window.
3. Alert when the count reaches `--threshold`. Merge qualifying windows whose
   observed failure intervals overlap. This produces one alert per connected
   episode instead of one alert per failed login.
4. Record total failures in that episode and its peak rolling-window count.
   An episode can last longer than one window; severity uses its **peak**, not
   the episode total. Isolated failures after the episode are excluded.

| Severity | Peak failures in a window | Default threshold 5 |
| --- | --- | --- |
| medium | At least threshold, below 2 × threshold | 5–9 |
| high | At least 2 × threshold, below 4 × threshold | 10–19 |
| critical | At least 4 × threshold | 20+ |

The threshold is any positive integer. The window is an integer number of
seconds from 1 through 31,536,000 (365 days). These severities are local triage
heuristics, not provider threat ratings or confirmation of compromise.
Successful logins are counted separately; they neither add to nor reset a
failure window, and this version does not correlate them with alerts.

Duplicate resolved input paths are rejected. **Overlapping log contents and
different hard links to the same log are not deduplicated.** Distinct attempts
can have identical text/timestamps, so silent content deduplication would risk
undercounting. Supply non-overlapping files.

## Supported records and timestamp assumptions

Examples of supported headers and messages:

```text
Oct 27 10:00:00 web-01 sshd[200]: Failed password for invalid user demo from 192.0.2.10 port 51000 ssh2
2026-10-27T10:00:00.123456Z web-01 sshd-session[201]: Failed publickey for demo from 2001:db8::10 port 51001 ssh2
2026-10-27T06:00:00-04:00 web-01 sshd[202]: Accepted publickey for demo from 192.0.2.20 port 51002 ssh2
```

- Supports `sshd` and `sshd-session`, with or without a numeric PID; canonical
  `Failed METHOD for USER from IP port PORT` and `Accepted ...` messages;
  optional `invalid user`; single-token usernames; IPv4 and IPv6.
- Authentication methods are preserved as tokens, including `password`,
  `publickey`, and `keyboard-interactive/pam`. Trailing OpenSSH details are allowed.
- `Invalid user`, PAM authentication failure, disconnect, and unrelated lines
  are ignored so one login attempt is not counted several times. PAM-only logs
  therefore do not produce detections.
- Traditional `Mon DD HH:MM:SS` timestamps use English month names. `--year`
  supplies the first year independently for each input, defaulting to the
  current UTC year. Use an explicit year for reproducible historical analysis.
- A December-to-January transition among SSH records in file order advances
  that input's inferred year. Keep legacy records chronological around New
  Year. Reordered records across that boundary are ambiguous. If different
  files begin in different years, analyze them separately with the correct
  years or convert to explicit ISO timestamps before combining them.
- ISO timestamps use `YYYY-MM-DDTHH:MM:SS`, optionally 1–6 fractional digits,
  and optionally `Z` or an offset such as `+02:00`. Explicit years and offsets
  take precedence. ISO records do not advance the inferred legacy year.
- Missing timezones use `--timezone`, default `UTC`. Only UTC and fixed offsets
  are supported; daylight-saving transitions require explicit per-record offsets.
  All parsed timestamps and reports are normalized to UTC.
- JSON journal exports, full RFC 5424 envelopes, hostless records, scoped IPv6
  addresses, and custom log templates are outside this parser's supported subset.
  IPv4-mapped IPv6 is normalized to IPv4 so the same source stays in one group.

## Reports and errors

JSON includes `schema_version`, tool metadata, input names, configuration,
summary counts, alerts, and diagnostics. Each alert includes timestamps,
threshold/window, severity, usernames, and up to 10 source-file/line references.
`evidence_omitted` reports the remaining count. It never includes complete raw
log lines. JSON preserves original parsed field values.

CSV contains **alerts only**, one per row; no-alert reports still have a header.
Its `usernames` and `evidence` cells contain JSON arrays. Formula-like string
cells are prefixed with an apostrophe for spreadsheet safety. Use JSON for
lossless values. Text reports escape non-printable log characters.

Warnings go to stderr, keeping JSON/CSV stdout clean. By default malformed
records are skipped and counted; at most 20 diagnostic details are retained.
The JSON report includes the number of omitted diagnostics. `--strict` makes
any malformed line an error and writes no report. Unrelated/unsupported lines
without a recognized SSH envelope are ignored, including in strict mode.
Always check parsed/ignored counts: no alerts alone does not establish that
the input format was supported or that a system is safe.

Files are read as UTF-8. Invalid encoding, invalid dates/IPs/ports, and oversized
lines receive diagnostics. The default physical-line limit is 65,536 bytes,
including the newline; change it with `--max-line-bytes` (1–16,777,216).

Output files are published atomically in an existing directory. An existing
report requires `--force`; an input log cannot be the output, even with `--force`.
All named inputs must be readable before a report is produced. Output errors
leave no partial report. The default non-overwriting write uses a same-directory
hard link; filesystems without hard-link support return an error. Use stdout
or a supported local filesystem there. Shell redirection is controlled by the
shell: never redirect stdout to the input log itself.

| Exit code | Meaning |
| ---: | --- |
| 0 | Analysis completed (alerts may exist unless `--fail-on-alert` is set) |
| 1 | Analysis completed, alerts exist, and `--fail-on-alert` is set |
| 2 | Usage/configuration/read/write error, broken output pipe, or strict parse failure |
| 130 | Interrupted by the user |

## Project structure and design

```text
sentinel/
  cli.py             Arguments, exit codes, output safety
  models.py          Typed event/configuration/alert records
  parser.py          OpenSSH records, IP validation, UTC timestamps
  analyzer.py        Bounded line reads, counts, diagnostics
  detectors.py       Rolling windows, episodes, severity
  reporting.py       Text/JSON/CSV and atomic file output
  integrations/      CVE and threat intelligence provider interfaces
tests/               Standard-library unittest unit and CLI integration tests
samples/             Synthetic attack, benign, and malformed logs
examples/            Generated sample reports
dist/                Prebuilt universal Python wheel
```

The standard library keeps installation small and makes the default tool fully
offline. `argparse` provides consistent CLI validation; `ipaddress` validates and
normalizes addresses; timezone-aware `datetime` avoids naive time comparisons;
dataclasses keep the module contracts explicit; `deque` makes rolling-window
updates efficient. JSON/CSV serialization uses standard encoders, not hand-built
escaping. Truncated SHA-256 creates reproducible alert IDs from rule/group/time/
count/configuration data; IDs are identifiers, not evidence-integrity signatures.

This is a **batch analyzer**, with roughly O(n log n) time and O(n) memory for
n failures. Line reads are bounded, but failures and the rendered report remain
in memory. Analyze bounded log ranges for large datasets. A future streaming
mode would need persisted windows, ordering guarantees, and alert lifecycle rules.

This rule does not identify distributed attacks spread across IPs, traffic
below the threshold, or compromises without matching authentication failures.
Hostname spelling is used as logged, without asset inventory resolution. Shared
NAT addresses and normal user mistakes can trigger alerts; tune the threshold
and window for your environment.

## Tests and extension points

```sh
python -m unittest discover -s tests -v
```

Tests exercise timestamp and window boundaries, severity, aggregation, IPv6,
malformed/oversized lines, CSV formula protection, atomic writes, and CLI exit
codes. See `VERIFICATION.md` for the delivered package's actual test results.

`sentinel/integrations/base.py` defines typed `CVEProvider` and
`ThreatIntelProvider` protocols plus result records. They are **extension hooks**;
no live provider is implemented or called. See `EXTENDING.md` for the adapter
contract, secret handling, and suggested next steps.


# Verification record

Verified on 2026-10-27 (America/New_York), on macOS.

| Check | Result |
| --- | --- |
| Source test suite, Python 3.12.14 | 72 tests passed; no skips |
| Source test suite, Python 3.14.7 | 72 tests passed; no skips |
| Installed wheel test suite, Python 3.14.7 | 72 tests passed; no skips |
| Offline wheel installation in a fresh virtual environment | Passed |
| Installed `sentinel --version` console entry point | `Sentinel 0.1.0` |
| Installed package dependency check | No broken requirements |
| Main synthetic sample | 3 alerts: 1 medium, 1 high, 1 critical |
| Benign synthetic sample | 0 alerts |
| Text, JSON, and CSV example reports | Generated from the supplied main sample |

The installed-package tests ran from a separate directory containing only copies
of `tests/` and `samples/`. There was no local `sentinel/` source package in that
directory, and the imported package was verified to come from the virtual
environment's `site-packages`. This checks the delivered wheel, not just the
source checkout. No network access was used for building, installing, or testing.

Run the suite yourself from the extracted project directory:

```sh
python -m unittest discover -s tests -v
```

Coverage includes exact threshold/time boundaries; sliding windows across fixed
time buckets; separate hosts/IPs; multiple usernames; event ordering; overlapping
and distinct episodes; severity boundaries; success/failure separation; IPv4,
IPv6, and mapped IPv6; legacy/ISO dates and offsets; New Year rollover; invalid
dates and offsets; malformed UTF-8 and oversized lines; capped diagnostics;
missing/unreadable files; symlink loops; output protection; atomic write failure;
CSV formula handling; terminal control characters; JSON/CSV shapes; stdin;
configuration errors; and CLI exit codes.

Python 3.10+ is the declared compatibility range. Python 3.10/3.11/3.13 and
Windows/Linux were not available in this verification environment and were not
run. Live production logs and external CVE/threat intelligence providers were
not part of these tests; integration modules contain interfaces only.

The wheel checksum is recorded in `dist/SHA256SUMS.txt`. It can detect accidental
file corruption but is not a signed authenticity guarantee.

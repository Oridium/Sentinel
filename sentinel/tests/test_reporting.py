import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.analyzer import analyze
from sentinel.models import DetectionConfig
from sentinel.reporting import csv_safe, render_report, write_report
from tests.helpers import log_line


class ReportingTests(unittest.TestCase):
    def result(self, host="demo-host", count=5):
        data = "".join(log_line(i, host=host) for i in range(count)).encode()
        return analyze(["-"], DetectionConfig(), year=2026, stdin=io.BytesIO(data))

    def test_json_schema_and_types(self):
        report = json.loads(render_report(self.result(), "json"))
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["summary"]["alert_count"], 1)
        self.assertEqual(report["summary"]["alerts_by_severity"], {"medium": 1, "high": 0, "critical": 0})
        self.assertIsInstance(report["alerts"][0]["attempt_count"], int)
        self.assertEqual(report["alerts"][0]["evidence"][0], {"source": "<stdin>", "line_number": 1})
        self.assertTrue(report["alerts"][0]["first_seen"].endswith("Z"))

    def test_csv_alert_fields_and_escaped_lists(self):
        rows = list(csv.DictReader(io.StringIO(render_report(self.result(), "csv"))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_ip"], "192.0.2.10")
        self.assertEqual(json.loads(rows[0]["usernames"]), ["demo"])
        self.assertEqual(len(json.loads(rows[0]["evidence"])), 5)

    def test_csv_injection_prevention(self):
        rows = list(csv.DictReader(io.StringIO(render_report(self.result(host="=1+1"), "csv"))))
        self.assertEqual(rows[0]["host"], "'=1+1")
        for value in ("=cmd", "+1", "-1", "@sum", "  =cmd", "\tcmd", "\rcmd"):
            self.assertTrue(csv_safe(value).startswith("'"))
        self.assertEqual(csv_safe("demo-host"), "demo-host")

    def test_json_preserves_original_values(self):
        report = json.loads(render_report(self.result(host="=1+1"), "json"))
        self.assertEqual(report["alerts"][0]["host"], "=1+1")

    def test_terminal_control_sequences_escaped(self):
        text = render_report(self.result(host="\x1b[31mhost"), "text")
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b", text)

    def test_empty_csv_still_has_header(self):
        text = render_report(self.result(count=0), "csv")
        self.assertTrue(text.startswith("alert_id,"))
        self.assertEqual(list(csv.DictReader(io.StringIO(text))), [])

    def test_evidence_omission_count(self):
        report = json.loads(render_report(self.result(count=20), "json"))
        self.assertEqual(report["alerts"][0]["evidence_omitted"], 10)

    def test_write_existing_file_requires_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_report(path, "first")
            with self.assertRaises(FileExistsError):
                write_report(path, "second")
            self.assertEqual(path.read_text(), "first")
            write_report(path, "second", overwrite=True)
            self.assertEqual(path.read_text(), "second")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_atomic_failure_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("original")
            with patch("sentinel.reporting.os.replace", side_effect=OSError("simulated write failure")):
                with self.assertRaises(OSError):
                    write_report(path, "replacement", overwrite=True)
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(Path(directory).iterdir()), [path])


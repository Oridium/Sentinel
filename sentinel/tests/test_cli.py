import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import log_line

ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def cli(self, *arguments, data=None):
        return subprocess.run([sys.executable, "-m", "sentinel", *arguments], cwd=ROOT,
                              input=data, capture_output=True, text=True, timeout=15)

    def test_help_and_version(self):
        self.assertEqual(self.cli("--help").returncode, 0)
        self.assertIn("0.1.0", self.cli("--version").stdout)
        self.assertIn("--threshold", self.cli("analyze", "--help").stdout)

    def test_sample_expected_alerts(self):
        run = self.cli("analyze", "samples/auth.log", "--year", "2026", "--format", "json")
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["summary"]["alert_count"], 3)
        self.assertEqual(report["summary"]["alerts_by_severity"], {"medium": 1, "high": 1, "critical": 1})
        self.assertEqual(report["summary"]["malformed_lines"], 0)

    def test_benign_sample(self):
        run = self.cli("analyze", "samples/benign.log", "--year", "2026", "--fail-on-alert")
        self.assertEqual(run.returncode, 0)
        self.assertIn("Alerts: 0", run.stdout)

    def test_fail_on_alert(self):
        run = self.cli("analyze", "samples/auth.log", "--year", "2026", "--fail-on-alert")
        self.assertEqual(run.returncode, 1)
        self.assertIn("Alerts: 3", run.stdout)

    def test_stdin_and_configuration(self):
        run = self.cli("analyze", "-", "--threshold", "2", "--window-seconds", "1", "--format", "json",
                       "--timezone=-04:00", data=log_line(0) + log_line(1))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["summary"]["alert_count"], 1)

    def test_malformed_diagnostics_do_not_pollute_json(self):
        run = self.cli("analyze", "-", "--format", "json", data=log_line(ip="bad"))
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["summary"]["malformed_lines"], 1)
        self.assertIn("warning:", run.stderr)

    def test_strict_no_report_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("existing report")
            run = self.cli("analyze", "-", "--strict", "--force", "-o", str(output), data=log_line(ip="bad"))
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stdout, "")
            self.assertEqual(output.read_text(), "existing report")
            self.assertNotIn("Traceback", run.stderr)

    def test_invalid_config(self):
        for options in (("--threshold", "0"), ("--window-seconds", "0"), ("--year", "10000"),
                        ("--timezone", "local"), ("--max-line-bytes", "0")):
            with self.subTest(options=options):
                run = self.cli("analyze", "samples/auth.log", *options)
                self.assertEqual(run.returncode, 2)
                self.assertNotIn("Traceback", run.stderr)

    def test_missing_input_does_not_create_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            run = self.cli("analyze", "samples/auth.log", str(Path(directory) / "missing.log"), "-o", str(output))
            self.assertEqual(run.returncode, 2)
            self.assertFalse(output.exists())

    def test_directory_input_error(self):
        run = self.cli("analyze", "samples")
        self.assertEqual(run.returncode, 2)
        self.assertNotIn("Traceback", run.stderr)

    def test_duplicate_input_error(self):
        run = self.cli("analyze", "samples/auth.log", "./samples/auth.log")
        self.assertEqual(run.returncode, 2)

    def test_output_file_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            args = ("analyze", "samples/auth.log", "--year", "2026", "--format", "csv", "-o", str(output))
            first = self.cli(*args)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, "")
            self.assertEqual(len(list(csv.DictReader(io.StringIO(output.read_text())))), 3)
            self.assertEqual(self.cli(*args).returncode, 2)
            self.assertEqual(self.cli(*args, "--force").returncode, 0)

    def test_output_parent_must_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.cli("analyze", "samples/auth.log", "-o", str(Path(directory) / "missing" / "report.txt"))
            self.assertEqual(run.returncode, 2)
            self.assertNotIn("Traceback", run.stderr)

    def test_input_overwrite_protected_including_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            alias = Path(directory) / "alias.log"
            source.write_text(log_line())
            os.link(source, alias)
            for output in (source, alias):
                run = self.cli("analyze", str(source), "-o", str(output), "--force")
                self.assertEqual(run.returncode, 2)
                self.assertIn("must not replace", run.stderr)
                self.assertEqual(source.read_text(), log_line())

    def test_no_subcommand_is_usage_error(self):
        self.assertEqual(self.cli().returncode, 2)

    def test_symlink_loop_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            loop = Path(directory) / "loop.log"
            try:
                loop.symlink_to("loop.log")
            except OSError:
                self.skipTest("symlink creation unavailable")
            run = self.cli("analyze", str(loop), "-o", str(Path(directory) / "report.json"))
            self.assertEqual(run.returncode, 2)
            self.assertNotIn("Traceback", run.stderr)

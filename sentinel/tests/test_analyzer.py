import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.analyzer import AnalysisError, analyze, read_lines
from sentinel.models import DetectionConfig
from tests.helpers import log_line


class AnalyzerTests(unittest.TestCase):
    def analyze_bytes(self, data, **kwargs):
        return analyze(["-"], DetectionConfig(3, 60), year=2026, stdin=io.BytesIO(data), **kwargs)

    def test_summary_accounting(self):
        data = (log_line() + log_line(1, action="Accepted") + "noise\n" + log_line(ip="bad")).encode()
        stats = self.analyze_bytes(data).stats
        self.assertEqual((stats.total_lines, stats.parsed_events, stats.failed_logins,
                          stats.successful_logins, stats.ignored_lines, stats.malformed_lines), (4, 2, 1, 1, 1, 1))
        self.assertEqual(stats.total_lines, stats.parsed_events + stats.ignored_lines + stats.malformed_lines)

    def test_invalid_utf8_does_not_crash(self):
        result = self.analyze_bytes(b"\xff\xfe\n" + log_line().encode())
        self.assertEqual((result.stats.malformed_lines, result.stats.failed_logins), (1, 1))

    def test_oversized_lines_drained_once(self):
        data = b"x" * 5000 + b"\n" + log_line().encode()
        result = self.analyze_bytes(data, max_line_bytes=200)
        self.assertEqual((result.stats.total_lines, result.stats.malformed_lines, result.stats.failed_logins), (2, 1, 1))
        self.assertEqual(result.diagnostics[0].line_number, 1)

    def test_line_length_exact_limit_and_no_newline(self):
        rows = list(read_lines(io.BytesIO(b"1234\n12345"), 5))
        self.assertEqual(rows, [(1, "1234\n", None), (2, "12345", None)])

    def test_diagnostics_capped(self):
        result = self.analyze_bytes(b"\xff\n" * 25)
        self.assertEqual((len(result.diagnostics), result.diagnostics_omitted, result.stats.malformed_lines), (20, 5, 25))

    def test_empty_file(self):
        result = self.analyze_bytes(b"")
        self.assertEqual(result.stats.total_lines, 0)
        self.assertIsNone(result.stats.first_event)
        self.assertEqual(result.alerts, [])

    def test_multiple_files_combine_and_sort(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "a.log", Path(directory) / "b.log"
            first.write_text(log_line(30), encoding="utf-8")
            second.write_text(log_line(0) + log_line(15), encoding="utf-8")
            result = analyze([str(first), str(second)], DetectionConfig(3, 60), year=2026)
            self.assertEqual(result.alerts[0].attempt_count, 3)
            self.assertEqual(result.stats.first_event.second, 0)

    def test_duplicate_inputs_rejected(self):
        for sources in (["-", "-"], ["example.log", "./example.log"], []):
            with self.subTest(sources=sources), self.assertRaises(AnalysisError):
                analyze(sources, DetectionConfig(), year=2026)

    def test_missing_input(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(AnalysisError):
            analyze([str(Path(directory) / "missing.log")], DetectionConfig(), year=2026)

    def test_unreadable_input(self):
        with patch("sentinel.analyzer.Path.open", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaisesRegex(AnalysisError, "Permission denied"):
                analyze(["unreadable.log"], DetectionConfig(), year=2026)

    def test_bad_read_limit(self):
        for limit in (0, -1, 16_777_217):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.analyze_bytes(b"", max_line_bytes=limit)

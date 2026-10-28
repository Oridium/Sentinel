import unittest
from datetime import datetime, timezone

from sentinel.models import AuthEvent
from sentinel.parser import SSHLogParser, parse_timezone
from tests.helpers import log_line


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = SSHLogParser(2026)

    def parse(self, line):
        return self.parser.parse_line(line, "example.log", 7)

    def test_legacy_failed_invalid_user(self):
        parsed = self.parse("Oct  7 12:34:56 web-01 sshd[123]: Failed password for invalid user demo from 192.0.2.10 port 50000 ssh2")
        self.assertIsNone(parsed.error)
        self.assertEqual(parsed.event.timestamp, datetime(2026, 10, 7, 12, 34, 56, tzinfo=timezone.utc))
        self.assertTrue(parsed.event.invalid_user)
        self.assertEqual((parsed.event.host, parsed.event.source, parsed.event.line_number), ("web-01", "example.log", 7))

    def test_success_and_public_key(self):
        parsed = self.parse(log_line(action="Accepted").replace("password", "publickey"))
        self.assertEqual((parsed.event.outcome, parsed.event.method), ("success", "publickey"))

    def test_new_sshd_session_process(self):
        parsed = self.parse(log_line().replace("sshd[42]", "sshd-session[42]"))
        self.assertEqual(parsed.event.outcome, "failure")

    def test_keyboard_interactive(self):
        parsed = self.parse(log_line().replace("password", "keyboard-interactive/pam"))
        self.assertEqual(parsed.event.method, "keyboard-interactive/pam")

    def test_ipv6_canonicalization(self):
        parsed = self.parse(log_line(ip="2001:0db8:0000:0000::000a"))
        self.assertEqual(parsed.event.source_ip, "2001:db8::a")

    def test_ipv4_mapped_ipv6(self):
        self.assertEqual(self.parse(log_line(ip="::ffff:192.0.2.10")).event.source_ip, "192.0.2.10")

    def test_explicit_offset_and_microseconds(self):
        parsed = self.parse(log_line().replace("2026-01-01T00:00:00Z", "2026-02-03T04:05:06.123456+02:30"))
        self.assertEqual(parsed.event.timestamp, datetime(2026, 2, 3, 1, 35, 6, 123456, tzinfo=timezone.utc))

    def test_assumed_timezone(self):
        self.parser = SSHLogParser(2026, parse_timezone("-04:00"))
        parsed = self.parse(log_line().replace("00Z", "00"))
        self.assertEqual(parsed.event.timestamp.hour, 4)

    def test_explicit_year_ignores_assumed_year(self):
        self.parser = SSHLogParser(2020)
        self.assertEqual(self.parse(log_line()).event.timestamp.year, 2026)

    def test_year_rollover_and_ignored_ssh_record(self):
        self.parse("Dec 31 23:59:59 web sshd[1]: Connection closed by 192.0.2.10 port 50000")
        parsed = self.parse("Jan  1 00:00:01 web sshd[1]: Failed password for demo from 192.0.2.10 port 50000 ssh2")
        self.assertEqual(parsed.event.timestamp.year, 2027)

    def test_out_of_order_same_year(self):
        for stamp in ("Oct 10", "Oct  9", "Sep 30"):
            parsed = self.parse(f"{stamp} 00:00:00 web sshd: Failed password for demo from 192.0.2.10 port 50 ssh2")
            self.assertEqual(parsed.event.timestamp.year, 2026)

    def test_noise_does_not_duplicate_failures(self):
        for line in (
            "", "random non-SSH text", "Oct 27 10:00:00 host CRON[2]: session opened",
            "Oct 27 10:00:00 host sshd[1]: Invalid user demo from 192.0.2.10 port 50000",
            "Oct 27 10:00:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.10",
            "Oct 27 10:00:00 host sshd[1]: Connection closed by 192.0.2.10 port 50000 [preauth]",
        ):
            with self.subTest(line=line):
                self.assertIsNone(self.parse(line).event)
                self.assertIsNone(self.parse(line).error)

    def test_invalid_dates_and_headers(self):
        for timestamp in ("Feb 30 00:00:00", "Foo 01 00:00:00", "Oct 27 25:00:00", "2026-13-01T00:00:00Z", "not-a-date"):
            with self.subTest(timestamp=timestamp):
                self.assertIsNotNone(self.parse(f"{timestamp} host sshd: Failed password for x from 192.0.2.1 port 22 ssh2").error)

    def test_bad_ip_and_port(self):
        for line in (log_line(ip="999.1.1.1"), log_line(ip="example.invalid"), log_line(ip="fe80::1%eth0"),
                     log_line().replace("45000", "0"), log_line().replace("45000", "65536")):
            with self.subTest(line=line):
                self.assertIsNotNone(self.parse(line).error)

    def test_bad_auth_record(self):
        self.assertIsNotNone(self.parse("Oct 27 10:00:00 host sshd: Failed password for incomplete").error)

    def test_invalid_explicit_timezone_offsets(self):
        for offset in ("+01:60", "-00:99", "+24:00"):
            with self.subTest(offset=offset):
                self.assertIsNotNone(self.parse(log_line().replace("00Z", "00" + offset)).error)

    def test_crlf(self):
        self.assertIsNotNone(self.parse(log_line().replace("\n", "\r\n")).event)

    def test_timezone_validation(self):
        for value in ("local", "US/Eastern", "+24:00", "-00:60", "+4:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_timezone(value)
        self.assertEqual(parse_timezone("Z"), timezone.utc)

    def test_year_validation_and_rollover_overflow(self):
        with self.assertRaises(ValueError):
            SSHLogParser(0)
        self.parser = SSHLogParser(9999)
        self.parse("Dec 31 23:59:59 host sshd: Connection closed")
        self.assertIsNotNone(self.parse("Jan  1 00:00:00 host sshd: Connection closed").error)

    def test_naive_event_rejected(self):
        with self.assertRaises(ValueError):
            AuthEvent(datetime(2026, 1, 1), "host", "192.0.2.1", "x", "failure", "password", 22, False, "log", 1)

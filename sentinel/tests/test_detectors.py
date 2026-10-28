import unittest

from sentinel.detectors import detect_brute_force
from sentinel.models import DetectionConfig
from tests.helpers import event


class DetectionTests(unittest.TestCase):
    def detect(self, events, threshold=3, window=60):
        return detect_brute_force(events, DetectionConfig(threshold, window))

    def test_empty_and_below_threshold(self):
        self.assertEqual(self.detect([]), [])
        self.assertEqual(self.detect([event(0), event(1)]), [])

    def test_exact_threshold(self):
        alerts = self.detect([event(0), event(1), event(2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].attempt_count, alerts[0].peak_window_count, alerts[0].severity), (3, 3, "medium"))

    def test_window_boundary_is_inclusive(self):
        self.assertEqual(len(self.detect([event(0), event(30), event(60)])), 1)
        self.assertEqual(self.detect([event(0), event(30), event(61)]), [])

    def test_rolling_window_crosses_fixed_bucket_boundary(self):
        self.assertEqual(len(self.detect([event(59), event(60), event(61)], window=3)), 1)

    def test_separate_hosts_and_sources(self):
        records = [event(0), event(1), event(2, host="other"), event(3, ip="192.0.2.20")]
        self.assertEqual(self.detect(records), [])

    def test_multiple_usernames_count_together(self):
        alert = self.detect([event(i, username=f"user{i}") for i in range(3)])[0]
        self.assertEqual(alert.usernames, ("user0", "user1", "user2"))

    def test_success_does_not_count_or_reset_failures(self):
        self.assertEqual(self.detect([event(0), event(1), event(2, outcome="success")]), [])
        alerts = self.detect([event(0), event(1, outcome="success"), event(2), event(3)])
        self.assertEqual(alerts[0].attempt_count, 3)

    def test_out_of_order_logs(self):
        alerts = self.detect([event(30), event(0), event(15)])
        self.assertEqual(alerts[0].first_seen, event(0).timestamp)
        self.assertEqual(alerts[0].last_seen, event(30).timestamp)

    def test_overlapping_windows_merge(self):
        alerts = self.detect([event(i * 20) for i in range(10)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].attempt_count, alerts[0].peak_window_count, alerts[0].severity), (10, 4, "medium"))
        self.assertGreater((alerts[0].last_seen - alerts[0].first_seen).total_seconds(), 60)

    def test_distinct_bursts_produce_distinct_alerts(self):
        alerts = self.detect([event(i) for i in (0, 1, 2, 200, 201, 202)])
        self.assertEqual([alert.attempt_count for alert in alerts], [3, 3])
        self.assertNotEqual(alerts[0].alert_id, alerts[1].alert_id)

    def test_nonqualifying_tail_not_counted(self):
        alert = self.detect([event(i) for i in (0, 1, 2, 100)])[0]
        self.assertEqual(alert.attempt_count, 3)
        self.assertEqual(alert.last_seen, event(2).timestamp)

    def test_multiple_failures_same_timestamp(self):
        alert = self.detect([event(0, line=i) for i in range(6)])[0]
        self.assertEqual((alert.attempt_count, alert.severity), (6, "high"))

    def test_all_severity_boundaries(self):
        for count, severity in ((3, "medium"), (5, "medium"), (6, "high"), (11, "high"), (12, "critical")):
            with self.subTest(count=count):
                self.assertEqual(self.detect([event(i) for i in range(count)])[0].severity, severity)

    def test_evidence_bounded_and_stable_ids(self):
        records = [event(i, line=i + 1) for i in range(20)]
        alert = self.detect(records)[0]
        self.assertEqual(len(alert.evidence), 10)
        self.assertEqual(alert.alert_id, self.detect(reversed(records))[0].alert_id)

    def test_threshold_one(self):
        alerts = self.detect([event(0)], threshold=1)
        self.assertEqual(alerts[0].attempt_count, 1)

    def test_configuration_validation(self):
        for threshold, window in ((0, 60), (-1, 60), (1, 0), (1, -1), (True, 60), (1, 31_536_001)):
            with self.subTest(threshold=threshold, window=window), self.assertRaises(ValueError):
                DetectionConfig(threshold, window)


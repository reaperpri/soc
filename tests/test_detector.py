import unittest
from datetime import timezone
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detector import (
    detect_failed_logon_bursts,
    detect_interesting_processes,
    parse_timestamp,
    run_detections,
)


class ParseTimestampTests(unittest.TestCase):
    def test_parses_utc_z_suffix(self):
        parsed = parse_timestamp("2026-10-29T10:00:00Z")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_treats_naive_timestamp_as_utc(self):
        parsed = parse_timestamp("2026-10-29T10:00:00")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_returns_none_for_missing_or_invalid_value(self):
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp("not-a-timestamp"))


class FailedLogonBurstTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {
                "event_id": f"FAIL-{index}",
                "timestamp": f"2026-10-29T09:{55 + index}:00Z",
                "username": "analyst",
                "source_ip": "192.0.2.10",
                "computer": "WORKSTATION-1",
                "windows_event_id": 4625,
            }
            for index in range(5)
        ]
        self.events.append({
            "event_id": "SUCCESS-1",
            "timestamp": "2026-10-29T10:00:00Z",
            "username": "analyst",
            "source_ip": "192.0.2.10",
            "computer": "WORKSTATION-1",
            "windows_event_id": 4624,
        })

    def test_detects_threshold_failures_before_success(self):
        alerts = detect_failed_logon_bursts(self.events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "AUTH-001")
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["success_event_id"], "SUCCESS-1")

    def test_does_not_alert_below_threshold(self):
        alerts = detect_failed_logon_bursts(self.events[:-2])

        self.assertEqual(alerts, [])

    def test_does_not_match_failures_from_another_source(self):
        for event in self.events[:5]:
            event["source_ip"] = "192.0.2.99"

        self.assertEqual(detect_failed_logon_bursts(self.events), [])


class InterestingProcessTests(unittest.TestCase):
    def test_flags_discovery_command(self):
        alerts = detect_interesting_processes([{
            "event_id": "PROC-1",
            "command_line": "net.exe user",
            "username": "analyst",
            "computer": "WORKSTATION-1",
        }])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "PROC-001")
        self.assertEqual(alerts[0]["event_id"], "PROC-1")

    def test_ignores_unmatched_command(self):
        alerts = detect_interesting_processes([{
            "event_id": "PROC-2",
            "command_line": "notepad.exe",
        }])

        self.assertEqual(alerts, [])


class RunDetectionsTests(unittest.TestCase):
    def test_combines_authentication_and_process_alerts(self):
        auth_events = [
            {
                "event_id": f"FAIL-{index}",
                "timestamp": f"2026-10-29T09:{55 + index}:00Z",
                "username": "analyst",
                "source_ip": "192.0.2.10",
                "windows_event_id": 4625,
            }
            for index in range(5)
        ]
        auth_events.append({
            "event_id": "SUCCESS-1",
            "timestamp": "2026-10-29T10:00:00Z",
            "username": "analyst",
            "source_ip": "192.0.2.10",
            "windows_event_id": 4624,
        })
        evidence = {
            "authentication": auth_events,
            "process": [{
                "event_id": "PROC-1",
                "command_line": "whoami.exe /all",
            }],
            "network": [],
        }

        alerts = run_detections(evidence)

        self.assertEqual(
            [alert["rule_id"] for alert in alerts],
            ["AUTH-001", "PROC-001"],
        )


if __name__ == "__main__":
    unittest.main()

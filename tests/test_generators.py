"""Tests for event generators."""

import unittest
from datetime import datetime, timezone

from xdr_simulator.generators.syslog_generator import SyslogGenerator
from xdr_simulator.generators.filebeat_generator import FilebeatGenerator
from xdr_simulator.generators.json_generator import JSONAPIGenerator
from xdr_simulator.generators.event_orchestrator import EventOrchestrator


class TestSyslogGenerator(unittest.TestCase):
    """Test SyslogGenerator."""

    def setUp(self):
        self.gen = SyslogGenerator(attack_probability=0.5)

    def test_generate_event_returns_dict(self):
        event = self.gen.generate_event()
        self.assertIsInstance(event, dict)

    def test_event_has_required_fields(self):
        event = self.gen.generate_event()
        self.assertIn("timestamp", event)
        self.assertIn("hostname", event)
        self.assertIn("source_type", event)
        self.assertEqual(event["source_type"], "syslog")

    def test_event_with_custom_timestamp(self):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        event = self.gen.generate_event(timestamp=ts)
        self.assertIn("2025-06-15", event["timestamp"])

    def test_generates_attack_events(self):
        gen = SyslogGenerator(attack_probability=1.0)
        event = gen.generate_event()
        # Attack events should have warning or alert severity
        self.assertIn(event["severity"], ["warning", "alert", "notice"])


class TestFilebeatGenerator(unittest.TestCase):
    """Test FilebeatGenerator."""

    def setUp(self):
        self.gen = FilebeatGenerator(attack_probability=0.5)

    def test_generate_event_returns_dict(self):
        event = self.gen.generate_event()
        self.assertIsInstance(event, dict)

    def test_event_has_source_type(self):
        event = self.gen.generate_event()
        self.assertEqual(event.get("source_type"), "filebeat")

    def test_event_has_timestamp(self):
        event = self.gen.generate_event()
        self.assertIn("@timestamp", event)


class TestJSONAPIGenerator(unittest.TestCase):
    """Test JSONAPIGenerator."""

    def setUp(self):
        self.gen = JSONAPIGenerator(attack_probability=0.5)

    def test_generate_event_returns_dict(self):
        event = self.gen.generate_event()
        self.assertIsInstance(event, dict)

    def test_event_has_required_fields(self):
        event = self.gen.generate_event()
        self.assertIn("timestamp", event)
        self.assertIn("source_type", event)
        self.assertIn("event_type", event)
        self.assertEqual(event["source_type"], "json_api")


class TestEventOrchestrator(unittest.TestCase):
    """Test EventOrchestrator."""

    def test_generate_day_produces_events(self):
        orch = EventOrchestrator(events_per_day=1000, attack_probability=0.1)
        events = orch.generate_day(inject_attack_scenario=False)
        self.assertGreater(len(events), 500)

    def test_events_are_sorted_by_timestamp(self):
        orch = EventOrchestrator(events_per_day=500, attack_probability=0.1)
        events = orch.generate_day(inject_attack_scenario=False)
        timestamps = [
            e.get("timestamp", e.get("@timestamp", ""))
            for e in events
        ]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_attack_scenario_injection(self):
        orch = EventOrchestrator(events_per_day=500, attack_probability=0.1)
        events_with = orch.generate_day(inject_attack_scenario=True)
        orch2 = EventOrchestrator(events_per_day=500, attack_probability=0.1)
        events_without = orch2.generate_day(inject_attack_scenario=False)
        self.assertGreater(len(events_with), len(events_without))

    def test_stream_events(self):
        orch = EventOrchestrator(events_per_day=500, attack_probability=0.1)
        batches = list(orch.stream_events(batch_size=100))
        self.assertGreater(len(batches), 0)
        for batch in batches:
            self.assertLessEqual(len(batch), 100)


if __name__ == "__main__":
    unittest.main()

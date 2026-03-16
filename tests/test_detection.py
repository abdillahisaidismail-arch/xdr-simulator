"""Tests for the detection engine."""

import unittest
from datetime import datetime, timezone, timedelta

from xdr_simulator.detection.detection_engine import DetectionEngine
from xdr_simulator.utils.models import (
    NormalizedEvent, SourceType, EventCategory, Severity, IncidentType,
)


class TestDetectionEngine(unittest.TestCase):
    """Test DetectionEngine."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_detect_ssh_brute_force(self):
        """Test SSH brute-force detection with 10 failed attempts."""
        base_time = datetime(2025, 6, 15, 2, 0, 0, tzinfo=timezone.utc)
        events = []
        for i in range(10):
            events.append(NormalizedEvent(
                timestamp=(base_time + timedelta(seconds=i * 20)).isoformat(),
                source_type=SourceType.SYSLOG,
                source_ip="185.220.101.42",
                hostname="srv-core-banking-01",
                username="root",
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
                outcome="failure",
                severity=Severity.MEDIUM,
            ))

        incidents = self.engine.detect(events)
        brute_force = [
            i for i in incidents
            if i.incident_type == IncidentType.SSH_BRUTE_FORCE
        ]
        self.assertGreater(len(brute_force), 0)
        self.assertEqual(brute_force[0].source_ip, "185.220.101.42")

    def test_no_ssh_brute_force_below_threshold(self):
        """Under threshold should not trigger."""
        base_time = datetime(2025, 6, 15, 2, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(
                timestamp=(base_time + timedelta(seconds=i * 20)).isoformat(),
                source_type=SourceType.SYSLOG,
                source_ip="185.220.101.42",
                hostname="srv-core-banking-01",
                username="root",
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
                outcome="failure",
                severity=Severity.MEDIUM,
            )
            for i in range(3)
        ]
        incidents = self.engine.detect(events)
        brute_force = [
            i for i in incidents
            if i.incident_type == IncidentType.SSH_BRUTE_FORCE
        ]
        self.assertEqual(len(brute_force), 0)

    def test_detect_privilege_escalation(self):
        """Test privilege escalation detection."""
        base_time = datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(
                timestamp=(base_time + timedelta(minutes=i)).isoformat(),
                source_type=SourceType.SYSLOG,
                hostname="srv-core-banking-01",
                username="test_user",
                category=EventCategory.PRIVILEGE_CHANGE,
                action="sudo_denied",
                outcome="failure",
                severity=Severity.HIGH,
                metadata={"command": f"/bin/dangerous_cmd_{i}"},
            )
            for i in range(3)
        ]

        incidents = self.engine.detect(events)
        privesc = [
            i for i in incidents
            if i.incident_type == IncidentType.PRIVILEGE_ESCALATION
        ]
        self.assertGreater(len(privesc), 0)

    def test_detect_abnormal_access(self):
        """Test abnormal access detection — external IP at odd hours."""
        ts = datetime(2025, 6, 15, 1, 0, 0, tzinfo=timezone.utc)  # 4 AM EAT
        events = [
            NormalizedEvent(
                timestamp=ts.isoformat(),
                source_type=SourceType.SYSLOG,
                source_ip="185.220.101.42",
                hostname="srv-core-banking-01",
                username="admin_bcd",
                category=EventCategory.AUTHENTICATION,
                action="ssh_login /api/v1/admin/users",
                outcome="success",
                severity=Severity.MEDIUM,
            ),
            # Same IP in filebeat (multi-source)
            NormalizedEvent(
                timestamp=ts.isoformat(),
                source_type=SourceType.FILEBEAT,
                source_ip="185.220.101.42",
                hostname="srv-web-portal-01",
                username="admin_bcd",
                category=EventCategory.APPLICATION,
                action="GET /api/v1/admin/users",
                outcome="success",
                severity=Severity.HIGH,
            ),
        ]
        incidents = self.engine.detect(events)
        abnormal = [
            i for i in incidents
            if i.incident_type == IncidentType.ABNORMAL_ACCESS
        ]
        self.assertGreater(len(abnormal), 0)

    def test_stats(self):
        """Test detection stats."""
        stats = self.engine.get_stats()
        self.assertIn("total_incidents", stats)
        self.assertEqual(stats["total_incidents"], 0)


if __name__ == "__main__":
    unittest.main()

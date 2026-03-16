"""Tests for the event parser."""

import unittest
from datetime import datetime, timezone

from xdr_simulator.parsers.event_parser import EventParser
from xdr_simulator.utils.models import (
    NormalizedEvent, SourceType, EventCategory, Severity,
)


class TestEventParser(unittest.TestCase):
    """Test EventParser."""

    def setUp(self):
        self.parser = EventParser()

    def test_parse_ssh_failed(self):
        event = {
            "raw": "<86>Mar 15 02:15:33 srv-core-banking-01 sshd[1234]: Failed password for root from 185.220.101.42 port 54321 ssh2",
            "timestamp": "2025-06-15T02:15:33+00:00",
            "hostname": "srv-core-banking-01",
            "facility": "authpriv",
            "severity": "warning",
            "message": "sshd[1234]: Failed password for root from 185.220.101.42 port 54321 ssh2",
            "source_type": "syslog",
        }
        result = self.parser.parse(event)
        self.assertIsInstance(result, NormalizedEvent)
        self.assertEqual(result.source_type, SourceType.SYSLOG)
        self.assertEqual(result.category, EventCategory.AUTHENTICATION)
        self.assertEqual(result.outcome, "failure")
        self.assertEqual(result.username, "root")
        self.assertEqual(result.source_ip, "185.220.101.42")

    def test_parse_ssh_success(self):
        event = {
            "message": "sshd[5678]: Accepted publickey for admin_bcd from 10.10.1.15 port 40000 ssh2: RSA SHA256:abc123",
            "timestamp": "2025-06-15T10:00:00+00:00",
            "hostname": "srv-core-banking-01",
            "source_type": "syslog",
        }
        result = self.parser.parse(event)
        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.username, "admin_bcd")

    def test_parse_sudo_denied(self):
        event = {
            "message": "sudo: test : command not allowed ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "timestamp": "2025-06-15T03:00:00+00:00",
            "hostname": "srv-core-banking-01",
            "source_type": "syslog",
        }
        result = self.parser.parse(event)
        self.assertEqual(result.category, EventCategory.PRIVILEGE_CHANGE)
        self.assertEqual(result.outcome, "failure")
        self.assertEqual(result.action, "sudo_denied")

    def test_parse_filebeat_event(self):
        event = {
            "@timestamp": "2025-06-15T14:30:00+00:00",
            "source_type": "filebeat",
            "agent": {"hostname": "srv-web-portal-01", "type": "filebeat", "version": "8.11.0"},
            "source": {"ip": "10.10.1.50"},
            "destination": {"ip": "10.10.1.15", "port": 443},
            "http": {
                "request": {"method": "GET", "path": "/api/v1/accounts/balance", "user_agent": "Mozilla/5.0"},
                "response": {"status_code": 200, "bytes": 1500},
            },
            "event": {"category": "web", "outcome": "success"},
            "user": {"name": "user_1234"},
        }
        result = self.parser.parse(event)
        self.assertEqual(result.source_type, SourceType.FILEBEAT)
        self.assertEqual(result.source_ip, "10.10.1.50")
        self.assertIn("GET", result.action)

    def test_parse_json_api_event(self):
        event = {
            "timestamp": "2025-06-15T12:00:00+00:00",
            "source_type": "json_api",
            "application": "core-banking-system",
            "event_type": "authentication",
            "auth": {"method": "password", "outcome": "failure", "reason": "invalid_password"},
            "user": {"id": "USR-1234", "username": "admin", "ip": "10.10.1.100"},
            "metadata": {"tags": ["brute_force"], "attempt_count": 15},
        }
        result = self.parser.parse(event)
        self.assertEqual(result.source_type, SourceType.JSON_API)
        self.assertEqual(result.category, EventCategory.AUTHENTICATION)
        self.assertEqual(result.outcome, "failure")

    def test_parse_batch(self):
        events = [
            {"source_type": "syslog", "message": "test event 1", "timestamp": "2025-06-15T00:00:00+00:00", "hostname": "test"},
            {"source_type": "syslog", "message": "test event 2", "timestamp": "2025-06-15T00:01:00+00:00", "hostname": "test"},
        ]
        results = self.parser.parse_batch(events)
        self.assertEqual(len(results), 2)
        self.assertEqual(self.parser.parsed_count, 2)

    def test_parser_stats(self):
        event = {"source_type": "syslog", "message": "test", "timestamp": "2025-06-15T00:00:00+00:00", "hostname": "test"}
        self.parser.parse(event)
        stats = self.parser.get_stats()
        self.assertEqual(stats["parsed_count"], 1)
        self.assertEqual(stats["error_count"], 0)


if __name__ == "__main__":
    unittest.main()

"""
Multi-source event parser and normalizer.
Transforms raw events from Syslog, Filebeat, and JSON API sources
into a unified NormalizedEvent schema for correlation processing.
"""

import re
from datetime import datetime, timezone

from ..utils.models import (
    NormalizedEvent, SourceType, EventCategory, Severity,
)
from ..utils.logger import get_logger


class EventParser:
    """
    Parse and normalize events from multiple sources.
    Converts heterogeneous event formats into NormalizedEvent instances.
    """

    # Syslog regex patterns
    SSH_FAILED_RE = re.compile(
        r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) "
        r"from (\S+) port (\d+)"
    )
    SSH_ACCEPTED_RE = re.compile(
        r"sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) "
        r"from (\S+) port (\d+)"
    )
    SUDO_RE = re.compile(
        r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.*)"
    )
    SUDO_DENIED_RE = re.compile(
        r"sudo:\s+(\S+)\s+: command not allowed.*COMMAND=(.*)"
    )
    SU_FAILED_RE = re.compile(
        r"su\[\d+\]: FAILED SU \(to (\S+)\) (\S+)"
    )
    PAM_AUTH_FAILURE_RE = re.compile(
        r"pam_unix\((\S+):auth\): authentication failure.*rhost=(\S+)\s+user=(\S+)"
    )

    def __init__(self):
        self.logger = get_logger()
        self.parsed_count = 0
        self.error_count = 0

    def parse(self, raw_event: dict) -> NormalizedEvent:
        """
        Parse a raw event into a NormalizedEvent.

        Args:
            raw_event: Raw event dictionary from any generator.

        Returns:
            NormalizedEvent instance.
        """
        source_type = raw_event.get(
            "source_type",
            raw_event.get("source_type", "unknown"),
        )

        try:
            if source_type == SourceType.SYSLOG.value:
                normalized = self._parse_syslog(raw_event)
            elif source_type == SourceType.FILEBEAT.value:
                normalized = self._parse_filebeat(raw_event)
            elif source_type == SourceType.JSON_API.value:
                normalized = self._parse_json_api(raw_event)
            else:
                normalized = self._parse_unknown(raw_event)

            self.parsed_count += 1
            return normalized

        except Exception as e:
            self.error_count += 1
            self.logger.log_event(
                "error",
                f"Parse error for {source_type}: {e}",
            )
            return self._fallback_event(raw_event, str(e))

    def parse_batch(self, events: list[dict]) -> list[NormalizedEvent]:
        """Parse a batch of raw events."""
        return [self.parse(event) for event in events]

    def _parse_syslog(self, event: dict) -> NormalizedEvent:
        """Parse a syslog event."""
        message = event.get("message", event.get("raw", ""))
        hostname = event.get("hostname", "")
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

        # SSH failed authentication
        match = self.SSH_FAILED_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(1),
                source_ip=match.group(2),
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
                outcome="failure",
                severity=Severity.MEDIUM,
                raw_message=message,
                metadata={"port": match.group(3), "service": "sshd"},
            )

        # SSH successful authentication
        match = self.SSH_ACCEPTED_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(1),
                source_ip=match.group(2),
                category=EventCategory.AUTHENTICATION,
                action="ssh_login",
                outcome="success",
                severity=Severity.INFO,
                raw_message=message,
                metadata={"port": match.group(3), "service": "sshd"},
            )

        # Sudo denied
        match = self.SUDO_DENIED_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(1),
                category=EventCategory.PRIVILEGE_CHANGE,
                action="sudo_denied",
                outcome="failure",
                severity=Severity.HIGH,
                raw_message=message,
                metadata={"command": match.group(2).strip()},
            )

        # Sudo executed
        match = self.SUDO_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(1),
                category=EventCategory.PRIVILEGE_CHANGE,
                action="sudo_exec",
                outcome="success",
                severity=Severity.LOW,
                raw_message=message,
                metadata={
                    "target_user": match.group(2),
                    "command": match.group(3).strip(),
                },
            )

        # SU failed
        match = self.SU_FAILED_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(2),
                category=EventCategory.PRIVILEGE_CHANGE,
                action="su_failed",
                outcome="failure",
                severity=Severity.HIGH,
                raw_message=message,
                metadata={"target_user": match.group(1)},
            )

        # PAM authentication failure
        match = self.PAM_AUTH_FAILURE_RE.search(message)
        if match:
            return NormalizedEvent(
                timestamp=timestamp,
                source_type=SourceType.SYSLOG,
                hostname=hostname,
                username=match.group(3),
                source_ip=match.group(2),
                category=EventCategory.AUTHENTICATION,
                action="pam_auth",
                outcome="failure",
                severity=Severity.MEDIUM,
                raw_message=message,
                metadata={"service": match.group(1)},
            )

        # Default syslog
        severity = self._syslog_severity_to_model(event.get("severity", "info"))
        return NormalizedEvent(
            timestamp=timestamp,
            source_type=SourceType.SYSLOG,
            hostname=hostname,
            category=EventCategory.SYSTEM,
            action="syslog_event",
            outcome="unknown",
            severity=severity,
            raw_message=message,
        )

    def _parse_filebeat(self, event: dict) -> NormalizedEvent:
        """Parse a Filebeat event."""
        timestamp = event.get("@timestamp", datetime.now(timezone.utc).isoformat())
        agent = event.get("agent", {})
        source = event.get("source", {})
        destination = event.get("destination", {})
        http = event.get("http", {})
        evt_info = event.get("event", {})
        user = event.get("user", {})
        firewall = event.get("firewall", {})

        hostname = agent.get("hostname", "")
        source_ip = source.get("ip", "")
        dest_ip = destination.get("ip", "")
        outcome = evt_info.get("outcome", "unknown")
        category_str = evt_info.get("category", "network")
        tags = evt_info.get("tags", [])

        # Determine category
        if category_str == "web":
            category = EventCategory.APPLICATION
        elif category_str == "network":
            category = EventCategory.NETWORK
        else:
            category = EventCategory.SYSTEM

        # Determine severity based on tags and status
        severity = Severity.INFO
        if isinstance(tags, list):
            if any(t in tags for t in ["abnormal_access", "web_scan",
                                       "potential_exfil"]):
                severity = Severity.HIGH
            elif any(t in tags for t in ["large_response"]):
                severity = Severity.MEDIUM

        request = http.get("request", {})
        response = http.get("response", {})
        status_code = response.get("status_code", 0)
        if status_code >= 500:
            severity = Severity.MEDIUM
        elif status_code in (401, 403):
            severity = Severity.MEDIUM

        action = ""
        if request:
            method = request.get("method", "")
            path = request.get("path", "")
            action = f"{method} {path}"
        elif firewall:
            action = f"firewall_{firewall.get('action', 'unknown').lower()}"

        return NormalizedEvent(
            timestamp=timestamp,
            source_type=SourceType.FILEBEAT,
            source_ip=source_ip,
            destination_ip=dest_ip,
            hostname=hostname,
            username=user.get("name", ""),
            category=category,
            action=action,
            outcome=outcome,
            severity=severity,
            raw_message=str(event.get("message", "")),
            metadata={
                "http_status": status_code,
                "response_bytes": response.get("bytes", 0),
                "user_agent": request.get("user_agent", ""),
                "tags": tags if isinstance(tags, list) else [],
                "event_id": event.get("event_id", ""),
            },
        )

    def _parse_json_api(self, event: dict) -> NormalizedEvent:
        """Parse a JSON API event."""
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        event_type = event.get("event_type", "unknown")
        application = event.get("application", "")
        user = event.get("user", {})
        auth = event.get("auth", {})
        transaction = event.get("transaction", {})
        metadata = event.get("metadata", {})

        username = user.get("username", user.get("id", ""))
        source_ip = user.get("ip", "")
        tags = metadata.get("tags", [])

        # Map event type to category
        category_map = {
            "authentication": EventCategory.AUTHENTICATION,
            "authorization": EventCategory.AUTHORIZATION,
            "transaction": EventCategory.APPLICATION,
            "health_check": EventCategory.SYSTEM,
            "audit": EventCategory.SYSTEM,
        }
        category = category_map.get(event_type, EventCategory.APPLICATION)

        # Determine action and outcome
        if event_type == "authentication":
            action = f"api_auth_{auth.get('method', 'unknown')}"
            outcome = auth.get("outcome", "unknown")
        elif event_type == "authorization":
            action = f"api_authz_{auth.get('action', 'unknown').lower()}"
            outcome = auth.get("outcome", "unknown")
        elif event_type == "transaction":
            action = f"transaction_{transaction.get('type', 'unknown').lower()}"
            outcome = "success" if transaction.get("status") == "completed" else "pending"
        else:
            action = event_type
            outcome = "success"

        # Determine severity
        severity = Severity.INFO
        if isinstance(tags, list):
            if any(t in tags for t in ["brute_force", "privilege_escalation"]):
                severity = Severity.HIGH
            elif any(t in tags for t in ["suspicious", "high_value"]):
                severity = Severity.MEDIUM

        risk_score = metadata.get("risk_score", 0)
        if risk_score >= 80:
            severity = Severity.HIGH
        elif risk_score >= 60:
            severity = Severity.MEDIUM

        if outcome == "failure" and event_type == "authentication":
            severity = max(severity, Severity.MEDIUM, key=lambda s: list(Severity).index(s))

        return NormalizedEvent(
            timestamp=timestamp,
            source_type=SourceType.JSON_API,
            source_ip=source_ip,
            hostname=application,
            username=username,
            category=category,
            action=action,
            outcome=outcome,
            severity=severity,
            raw_message=str(event),
            metadata={
                "application": application,
                "event_type": event_type,
                "tags": tags if isinstance(tags, list) else [],
                "risk_score": risk_score,
                "transaction_id": transaction.get("id", ""),
                "event_id": event.get("event_id", ""),
            },
        )

    def _parse_unknown(self, event: dict) -> NormalizedEvent:
        """Parse an unknown event type."""
        return NormalizedEvent(
            timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            category=EventCategory.SYSTEM,
            action="unknown",
            outcome="unknown",
            severity=Severity.LOW,
            raw_message=str(event),
        )

    def _fallback_event(self, event: dict, error: str) -> NormalizedEvent:
        """Create a fallback event when parsing fails."""
        return NormalizedEvent(
            category=EventCategory.SYSTEM,
            action="parse_error",
            outcome="failure",
            severity=Severity.LOW,
            raw_message=str(event),
            metadata={"parse_error": error},
        )

    @staticmethod
    def _syslog_severity_to_model(severity: str) -> Severity:
        """Map syslog severity to model Severity."""
        mapping = {
            "emerg": Severity.CRITICAL,
            "alert": Severity.CRITICAL,
            "crit": Severity.CRITICAL,
            "err": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "notice": Severity.LOW,
            "info": Severity.INFO,
            "debug": Severity.INFO,
        }
        return mapping.get(severity.lower(), Severity.INFO)

    def get_stats(self) -> dict:
        """Return parser statistics."""
        return {
            "parsed_count": self.parsed_count,
            "error_count": self.error_count,
            "success_rate": (
                f"{(self.parsed_count / (self.parsed_count + self.error_count) * 100):.1f}%"
                if (self.parsed_count + self.error_count) > 0
                else "N/A"
            ),
        }

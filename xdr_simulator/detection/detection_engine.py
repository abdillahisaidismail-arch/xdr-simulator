"""
Automated Detection Engine.
Implements three detection rules aligned with the XDR simulator requirements:
1. SSH Brute Force
2. Abnormal Access
3. Privilege Escalation

Each rule maps to MITRE ATT&CK tactics and techniques for structured reporting.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any
import time

from ..utils.models import (
    NormalizedEvent, Incident, IncidentType, Severity,
    EventCategory, SourceType,
)
from ..utils.logger import get_logger


class DetectionEngine:
    """
    Automated incident detection engine.

    Analyzes normalized events and correlation results to generate
    security incidents with MITRE ATT&CK mapping.
    """

    # Detection thresholds
    SSH_BRUTE_FORCE_THRESHOLD = 5       # Failed SSH attempts
    SSH_BRUTE_FORCE_WINDOW = 300        # 5 minutes
    ABNORMAL_ACCESS_WINDOW = 600        # 10 minutes
    PRIVESC_WINDOW = 1800               # 30 minutes

    # Known internal IP ranges (RFC 1918)
    INTERNAL_RANGES = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                       "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                       "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                       "172.29.", "172.30.", "172.31."]

    # Business hours (EAT — East Africa Time, UTC+3)
    BUSINESS_HOURS = (7, 19)  # 07:00 - 19:00

    # Sensitive paths
    SENSITIVE_PATHS = [
        "/api/v1/admin/", "/portal/admin/",
        "/api/v1/swift/", "/api/v1/admin/database/",
    ]

    def __init__(self):
        self.logger = get_logger()
        self.incidents: list[Incident] = []
        self._detection_start = time.time()
        self.logger.log_event("info", "DetectionEngine initialized")

    def detect(
        self,
        events: list[NormalizedEvent],
        correlations: list[dict] | None = None,
    ) -> list[Incident]:
        """
        Run all detection rules on events and correlations.

        Args:
            events: Normalized events to analyze.
            correlations: Correlation results from the CorrelationEngine.

        Returns:
            List of detected incidents.
        """
        incidents = []

        # Rule 1: SSH Brute Force
        ssh_incidents = self._detect_ssh_brute_force(events)
        incidents.extend(ssh_incidents)

        # Rule 2: Abnormal Access
        access_incidents = self._detect_abnormal_access(events)
        incidents.extend(access_incidents)

        # Rule 3: Privilege Escalation
        privesc_incidents = self._detect_privilege_escalation(events)
        incidents.extend(privesc_incidents)

        # Enhanced detection from correlation results
        if correlations:
            corr_incidents = self._detect_from_correlations(
                events, correlations
            )
            incidents.extend(corr_incidents)

        self.incidents.extend(incidents)

        for incident in incidents:
            self.logger.log_security_event(
                event_type=incident.incident_type.value,
                severity=incident.severity.value,
                source="detection_engine",
                details=incident.to_dict(),
            )

        if incidents:
            self.logger.log_event(
                "warning",
                f"Detection engine raised {len(incidents)} incidents: "
                + ", ".join(i.incident_type.value for i in incidents),
            )

        return incidents

    # ---------------------------------------------------------------
    # Rule 1: SSH Brute Force Detection
    # MITRE ATT&CK: T1110 — Brute Force (TA0006 — Credential Access)
    # ---------------------------------------------------------------
    def _detect_ssh_brute_force(
        self, events: list[NormalizedEvent],
    ) -> list[Incident]:
        """Detect SSH brute-force attacks."""
        incidents = []

        # Filter SSH authentication failures
        ssh_failures: list[NormalizedEvent] = [
            e for e in events
            if (
                e.category == EventCategory.AUTHENTICATION
                and e.outcome == "failure"
                and e.action in ("ssh_login", "pam_auth")
            )
        ]

        # Group by source IP
        by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in ssh_failures:
            if event.source_ip:
                by_ip[event.source_ip].append(event)

        for ip, ip_events in by_ip.items():
            if len(ip_events) < self.SSH_BRUTE_FORCE_THRESHOLD:
                continue

            # Sort by timestamp
            ip_events.sort(key=lambda e: e.timestamp)

            # Sliding window
            for i in range(len(ip_events)):
                try:
                    start = datetime.fromisoformat(ip_events[i].timestamp)
                except (ValueError, TypeError):
                    continue

                end = start + timedelta(seconds=self.SSH_BRUTE_FORCE_WINDOW)
                window = [
                    e for e in ip_events[i:]
                    if self._parse_ts(e.timestamp) and self._parse_ts(e.timestamp) <= end
                ]

                if len(window) >= self.SSH_BRUTE_FORCE_THRESHOLD:
                    # Check if a successful login follows (compromise indicator)
                    successful_login = self._find_success_after(
                        events, ip, window[-1].timestamp
                    )

                    ttd = (time.time() - self._detection_start)

                    target_users = list(set(e.username for e in window if e.username))
                    target_hosts = list(set(e.hostname for e in window if e.hostname))

                    severity = Severity.CRITICAL if successful_login else Severity.HIGH

                    incident = Incident(
                        incident_type=IncidentType.SSH_BRUTE_FORCE,
                        severity=severity,
                        source_ip=ip,
                        target=", ".join(target_hosts),
                        description=(
                            f"SSH brute-force detected: {len(window)} failed "
                            f"attempts from {ip} in "
                            f"{self._time_span(window):.0f}s. "
                            f"Targeted users: {', '.join(target_users)}. "
                            f"{'COMPROMISED: successful login detected!' if successful_login else 'No successful login detected.'}"
                        ),
                        correlated_events=[e.event_id for e in window],
                        event_count=len(window),
                        ttd_seconds=ttd,
                        mitre_tactic="TA0006 — Credential Access",
                        mitre_technique="T1110 — Brute Force",
                        recommended_action=(
                            "IMMEDIATE: Block source IP at perimeter firewall. "
                            "Rotate credentials for targeted accounts. "
                            "Review access logs for lateral movement."
                            if successful_login else
                            "Block source IP at perimeter firewall. "
                            "Monitor targeted accounts for further attempts."
                        ),
                        metadata={
                            "target_users": target_users,
                            "target_hosts": target_hosts,
                            "successful_login_after": successful_login,
                            "is_external": not self._is_internal(ip),
                        },
                    )
                    incidents.append(incident)
                    break  # One incident per IP

        return incidents

    # ---------------------------------------------------------------
    # Rule 2: Abnormal Access Detection
    # MITRE ATT&CK: T1078 — Valid Accounts (TA0001 — Initial Access)
    # ---------------------------------------------------------------
    def _detect_abnormal_access(
        self, events: list[NormalizedEvent],
    ) -> list[Incident]:
        """Detect abnormal access patterns."""
        incidents = []

        for event in events:
            anomalies = []
            is_external = (
                event.source_ip
                and not self._is_internal(event.source_ip)
            )

            # Check 1: External IP accessing internal resources
            if (
                is_external
                and event.outcome == "success"
                and event.category in (
                    EventCategory.AUTHENTICATION,
                    EventCategory.APPLICATION,
                )
            ):
                anomalies.append("external_ip_access")

            # Check 2: Access outside business hours (only relevant for external)
            ts = self._parse_ts(event.timestamp)
            if ts and is_external:
                hour_eat = (ts.hour + 3) % 24  # Convert UTC to EAT
                if (
                    hour_eat < self.BUSINESS_HOURS[0]
                    or hour_eat > self.BUSINESS_HOURS[1]
                ) and event.category == EventCategory.AUTHENTICATION:
                    anomalies.append("off_hours_access")

            # Check 3: Sensitive path access from external IP
            if event.action and is_external:
                for path in self.SENSITIVE_PATHS:
                    if path in event.action:
                        anomalies.append("sensitive_path_access")
                        break

            # Check 4: Multiple source types for same external IP
            if is_external and len(anomalies) >= 1:
                source_types = set()
                for e in events:
                    if e.source_ip == event.source_ip:
                        source_types.add(e.source_type)
                if len(source_types) > 1:
                    anomalies.append("multi_source_activity")

            if len(anomalies) >= 2:
                ttd = (time.time() - self._detection_start)
                incident = Incident(
                    incident_type=IncidentType.ABNORMAL_ACCESS,
                    severity=Severity.HIGH,
                    source_ip=event.source_ip,
                    target=event.hostname or event.action,
                    description=(
                        f"Abnormal access detected from {event.source_ip}: "
                        f"{', '.join(anomalies)}. "
                        f"User: {event.username or 'unknown'}, "
                        f"Action: {event.action}."
                    ),
                    correlated_events=[event.event_id],
                    event_count=1,
                    ttd_seconds=ttd,
                    mitre_tactic="TA0001 — Initial Access",
                    mitre_technique="T1078 — Valid Accounts",
                    recommended_action=(
                        "Verify user identity and access legitimacy. "
                        "Check for compromised credentials. "
                        "Review network logs for the source IP. "
                        "Enforce MFA for sensitive resources."
                    ),
                    metadata={
                        "anomalies": anomalies,
                        "username": event.username,
                        "source_type": event.source_type.value,
                    },
                )
                incidents.append(incident)

        # Deduplicate by source IP
        seen_ips = set()
        deduped = []
        for inc in incidents:
            if inc.source_ip not in seen_ips:
                seen_ips.add(inc.source_ip)
                deduped.append(inc)

        return deduped

    # ---------------------------------------------------------------
    # Rule 3: Privilege Escalation Detection
    # MITRE ATT&CK: T1548 — Abuse Elevation Control (TA0004 — Priv Esc)
    # ---------------------------------------------------------------
    def _detect_privilege_escalation(
        self, events: list[NormalizedEvent],
    ) -> list[Incident]:
        """Detect privilege escalation attempts and successes."""
        incidents = []

        # Collect privilege-change events
        privesc_events = [
            e for e in events
            if e.category in (
                EventCategory.PRIVILEGE_CHANGE,
                EventCategory.AUTHORIZATION,
            )
        ]

        # Group by user
        by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in privesc_events:
            if event.username:
                by_user[event.username].append(event)

        for username, user_events in by_user.items():
            # Look for escalation patterns
            failed_privesc = [
                e for e in user_events if e.outcome == "failure"
            ]
            successful_privesc = [
                e for e in user_events if e.outcome == "success"
                and e.action in ("sudo_exec", "api_authz_role_change",
                                 "api_authz_permission_grant",
                                 "api_authz_admin_access")
            ]

            # Pattern 1: Multiple failed privilege escalation attempts
            if len(failed_privesc) >= 2:
                ttd = (time.time() - self._detection_start)

                # Check if any succeeded after failures
                compromised = len(successful_privesc) > 0

                commands = [
                    e.metadata.get("command", "N/A")
                    for e in failed_privesc
                    if e.metadata.get("command")
                ]

                severity = Severity.CRITICAL if compromised else Severity.HIGH

                incident = Incident(
                    incident_type=IncidentType.PRIVILEGE_ESCALATION,
                    severity=severity,
                    source_ip=failed_privesc[0].source_ip or "local",
                    target=failed_privesc[0].hostname,
                    description=(
                        f"Privilege escalation {'SUCCESSFUL' if compromised else 'attempt'} "
                        f"by user '{username}': "
                        f"{len(failed_privesc)} failed attempts"
                        f"{f', {len(successful_privesc)} succeeded' if compromised else ''}. "
                        f"Commands: {', '.join(commands[:5])}."
                    ),
                    correlated_events=[
                        e.event_id for e in user_events
                    ],
                    event_count=len(user_events),
                    ttd_seconds=ttd,
                    mitre_tactic="TA0004 — Privilege Escalation",
                    mitre_technique="T1548 — Abuse Elevation Control Mechanism",
                    recommended_action=(
                        "IMMEDIATE: Terminate user session. "
                        "Revoke elevated privileges. "
                        "Audit all actions performed with elevated rights. "
                        "Forensic analysis of the affected system."
                        if compromised else
                        "Review user permissions and sudo configuration. "
                        "Monitor the account for further suspicious activity. "
                        "Verify legitimate need for elevated access."
                    ),
                    metadata={
                        "username": username,
                        "failed_attempts": len(failed_privesc),
                        "successful_attempts": len(successful_privesc),
                        "commands": commands,
                        "compromised": compromised,
                    },
                )
                incidents.append(incident)

            # Pattern 2: Suspicious role change in application
            for event in user_events:
                if (
                    event.action in ("api_authz_role_change",
                                     "api_authz_config_modify")
                    and event.metadata.get("risk_score", 0) >= 70
                ):
                    ttd = (time.time() - self._detection_start)
                    incident = Incident(
                        incident_type=IncidentType.PRIVILEGE_ESCALATION,
                        severity=Severity.HIGH,
                        source_ip=event.source_ip or "local",
                        target=event.hostname,
                        description=(
                            f"Suspicious role change by '{username}': "
                            f"{event.action} "
                            f"(risk score: {event.metadata.get('risk_score', 'N/A')}). "
                            f"Source: {event.source_type.value}."
                        ),
                        correlated_events=[event.event_id],
                        event_count=1,
                        ttd_seconds=ttd,
                        mitre_tactic="TA0004 — Privilege Escalation",
                        mitre_technique="T1078.003 — Valid Accounts: Local Accounts",
                        recommended_action=(
                            "Verify legitimacy of role change with the user's manager. "
                            "Review recent actions performed under the new role."
                        ),
                        metadata={
                            "username": username,
                            "action": event.action,
                            "risk_score": event.metadata.get("risk_score"),
                        },
                    )
                    incidents.append(incident)

        return incidents

    def _detect_from_correlations(
        self,
        events: list[NormalizedEvent],
        correlations: list[dict],
    ) -> list[Incident]:
        """Generate enhanced incidents from correlation results."""
        incidents = []

        for corr in correlations:
            if corr.get("multi_source") and corr.get("event_count", 0) >= 4:
                ttd = (time.time() - self._detection_start)

                incident = Incident(
                    incident_type=IncidentType.ABNORMAL_ACCESS,
                    severity=Severity.CRITICAL,
                    source_ip=corr.get("group_key", "").split("|")[0],
                    target="multi-host",
                    description=(
                        f"Multi-source correlated attack detected "
                        f"({corr['rule_name']}): "
                        f"{corr['event_count']} events across "
                        f"{', '.join(corr.get('sources', []))} "
                        f"in {corr.get('time_span_seconds', 0):.0f}s."
                    ),
                    correlated_events=corr.get("event_ids", []),
                    event_count=corr["event_count"],
                    ttd_seconds=ttd,
                    mitre_tactic="TA0001 — Initial Access + TA0008 — Lateral Movement",
                    mitre_technique="T1078 — Valid Accounts",
                    recommended_action=(
                        "CRITICAL: Activate incident response procedure. "
                        "Isolate affected systems. "
                        "Perform full forensic analysis across all sources."
                    ),
                    metadata={
                        "correlation_rule": corr["rule_id"],
                        "sources": corr.get("sources", []),
                        "categories": corr.get("categories", []),
                    },
                )
                incidents.append(incident)

        return incidents

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    def _find_success_after(
        self,
        events: list[NormalizedEvent],
        ip: str,
        after_timestamp: str,
    ) -> bool:
        """Check if a successful login from this IP exists after a timestamp."""
        for event in events:
            if (
                event.source_ip == ip
                and event.outcome == "success"
                and event.category == EventCategory.AUTHENTICATION
                and event.timestamp > after_timestamp
            ):
                return True
        return False

    def _is_internal(self, ip: str) -> bool:
        """Check if an IP is in the internal network range."""
        return any(ip.startswith(prefix) for prefix in self.INTERNAL_RANGES)

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime | None:
        """Parse an ISO timestamp string."""
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _time_span(events: list[NormalizedEvent]) -> float:
        """Calculate the time span between first and last event."""
        try:
            first = datetime.fromisoformat(events[0].timestamp)
            last = datetime.fromisoformat(events[-1].timestamp)
            return (last - first).total_seconds()
        except (ValueError, TypeError, IndexError):
            return 0.0

    def get_stats(self) -> dict:
        """Return detection statistics."""
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        for inc in self.incidents:
            type_counts[inc.incident_type.value] += 1
            severity_counts[inc.severity.value] += 1

        return {
            "total_incidents": len(self.incidents),
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
        }

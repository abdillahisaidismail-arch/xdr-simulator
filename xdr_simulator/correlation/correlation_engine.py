"""
Multi-source Correlation Engine.
Links events across Syslog, Filebeat, and JSON API sources
to detect complex attack patterns spanning multiple data streams.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from ..utils.models import (
    NormalizedEvent, CorrelationRule, EventCategory, Severity, SourceType,
)
from ..utils.logger import get_logger


class CorrelationEngine:
    """
    Multi-source event correlation engine.

    Implements sliding-window correlation across heterogeneous sources
    to detect attack patterns that no single source can reveal alone.
    """

    def __init__(self):
        self.logger = get_logger()
        self.rules: list[CorrelationRule] = self._load_default_rules()
        self.event_buffer: list[NormalizedEvent] = []
        self.correlations: list[dict] = []

        # Indexes for fast lookup
        self._ip_index: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self._user_index: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self._host_index: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self._category_index: dict[str, list[NormalizedEvent]] = defaultdict(list)

        self.logger.log_event(
            "info",
            f"CorrelationEngine initialized with {len(self.rules)} rules",
        )

    def _load_default_rules(self) -> list[CorrelationRule]:
        """Load built-in correlation rules."""
        return [
            CorrelationRule(
                rule_id="COR-001",
                name="SSH Brute Force Detection",
                description=(
                    "Detects multiple SSH authentication failures from the "
                    "same source IP within a time window."
                ),
                event_types=[EventCategory.AUTHENTICATION],
                threshold=5,
                time_window_seconds=300,  # 5 minutes
                group_by=["source_ip"],
                severity=Severity.HIGH,
            ),
            CorrelationRule(
                rule_id="COR-002",
                name="Cross-Source Abnormal Access",
                description=(
                    "Detects access from unusual IPs correlated across "
                    "multiple sources (SSH + web + API)."
                ),
                event_types=[
                    EventCategory.AUTHENTICATION,
                    EventCategory.APPLICATION,
                ],
                threshold=3,
                time_window_seconds=600,  # 10 minutes
                group_by=["source_ip"],
                severity=Severity.HIGH,
            ),
            CorrelationRule(
                rule_id="COR-003",
                name="Privilege Escalation Chain",
                description=(
                    "Detects privilege escalation attempts following "
                    "successful authentication."
                ),
                event_types=[
                    EventCategory.AUTHENTICATION,
                    EventCategory.PRIVILEGE_CHANGE,
                    EventCategory.AUTHORIZATION,
                ],
                threshold=2,
                time_window_seconds=1800,  # 30 minutes
                group_by=["username", "hostname"],
                severity=Severity.CRITICAL,
            ),
            CorrelationRule(
                rule_id="COR-004",
                name="Multi-Source Attack Chain",
                description=(
                    "Detects a full attack chain: brute force → access → "
                    "privilege escalation across all three sources."
                ),
                event_types=[
                    EventCategory.AUTHENTICATION,
                    EventCategory.PRIVILEGE_CHANGE,
                    EventCategory.APPLICATION,
                ],
                threshold=4,
                time_window_seconds=3600,  # 1 hour
                group_by=["source_ip"],
                severity=Severity.CRITICAL,
            ),
        ]

    def ingest(self, events: list[NormalizedEvent]) -> None:
        """
        Ingest normalized events into the correlation buffer.

        Args:
            events: List of normalized events to process.
        """
        for event in events:
            self.event_buffer.append(event)
            self._index_event(event)

        self.logger.log_event(
            "info",
            f"Ingested {len(events)} events (buffer size: {len(self.event_buffer)})",
        )

    def _index_event(self, event: NormalizedEvent) -> None:
        """Index an event for fast correlation lookups."""
        if event.source_ip:
            self._ip_index[event.source_ip].append(event)
        if event.username:
            self._user_index[event.username].append(event)
        if event.hostname:
            self._host_index[event.hostname].append(event)
        self._category_index[event.category.value].append(event)

    def correlate(self) -> list[dict]:
        """
        Run all correlation rules against the event buffer.

        Returns:
            List of correlation results (matches).
        """
        results = []

        for rule in self.rules:
            matches = self._evaluate_rule(rule)
            results.extend(matches)

        # Deduplicate overlapping correlations
        results = self._deduplicate(results)

        self.correlations.extend(results)

        if results:
            self.logger.log_event(
                "warning",
                f"Correlation engine found {len(results)} matches",
            )
            for r in results:
                self.logger.log_security_event(
                    event_type="correlation_match",
                    severity=r["severity"],
                    source="correlation_engine",
                    details={
                        "rule_id": r["rule_id"],
                        "rule_name": r["rule_name"],
                        "event_count": r["event_count"],
                        "group_key": r["group_key"],
                    },
                )

        return results

    def _evaluate_rule(self, rule: CorrelationRule) -> list[dict]:
        """Evaluate a single correlation rule against the event buffer."""
        matches = []

        # Get relevant events by category
        relevant_events: list[NormalizedEvent] = []
        for cat in rule.event_types:
            relevant_events.extend(self._category_index.get(cat.value, []))

        if len(relevant_events) < rule.threshold:
            return []

        # Group events by the rule's group_by fields
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in relevant_events:
            key_parts = []
            for field in rule.group_by:
                key_parts.append(getattr(event, field, "unknown"))
            group_key = "|".join(key_parts)
            groups[group_key].append(event)

        # Check each group against threshold within time window
        for group_key, events in groups.items():
            if len(events) < rule.threshold:
                continue

            # Sort by timestamp
            events.sort(key=lambda e: e.timestamp)

            # Sliding window check
            window_matches = self._sliding_window_check(
                events, rule.time_window_seconds, rule.threshold
            )

            for window_events in window_matches:
                # Check multi-source correlation
                sources = set(e.source_type for e in window_events)
                source_bonus = len(sources) > 1  # Multi-source correlation

                severity = rule.severity.value
                if source_bonus:
                    severity = "critical" if severity == "high" else severity

                matches.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "description": rule.description,
                    "severity": severity,
                    "group_key": group_key,
                    "event_count": len(window_events),
                    "event_ids": [e.event_id for e in window_events],
                    "sources": [s.value for s in sources],
                    "multi_source": source_bonus,
                    "time_span_seconds": self._time_span(window_events),
                    "first_event": window_events[0].timestamp,
                    "last_event": window_events[-1].timestamp,
                    "categories": list(set(
                        e.category.value for e in window_events
                    )),
                })

        return matches

    def _sliding_window_check(
        self,
        events: list[NormalizedEvent],
        window_seconds: int,
        threshold: int,
    ) -> list[list[NormalizedEvent]]:
        """
        Sliding window to find groups of events within the time window
        that exceed the threshold.
        """
        results = []
        n = len(events)

        for i in range(n):
            try:
                start_time = datetime.fromisoformat(events[i].timestamp)
            except (ValueError, TypeError):
                continue

            window_end = start_time + timedelta(seconds=window_seconds)
            window_events = [events[i]]

            for j in range(i + 1, n):
                try:
                    evt_time = datetime.fromisoformat(events[j].timestamp)
                except (ValueError, TypeError):
                    continue

                if evt_time <= window_end:
                    window_events.append(events[j])
                else:
                    break

            if len(window_events) >= threshold:
                results.append(window_events)
                break  # One match per group to avoid flood

        return results

    @staticmethod
    def _time_span(events: list[NormalizedEvent]) -> float:
        """Calculate time span between first and last event in seconds."""
        try:
            first = datetime.fromisoformat(events[0].timestamp)
            last = datetime.fromisoformat(events[-1].timestamp)
            return (last - first).total_seconds()
        except (ValueError, TypeError, IndexError):
            return 0.0

    @staticmethod
    def _deduplicate(results: list[dict]) -> list[dict]:
        """Deduplicate overlapping correlation results."""
        seen_keys = set()
        deduped = []
        for r in results:
            key = f"{r['rule_id']}:{r['group_key']}"
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(r)
        return deduped

    def get_stats(self) -> dict:
        """Return correlation engine statistics."""
        return {
            "buffer_size": len(self.event_buffer),
            "total_correlations": len(self.correlations),
            "rules_count": len(self.rules),
            "index_sizes": {
                "ip": len(self._ip_index),
                "user": len(self._user_index),
                "host": len(self._host_index),
                "category": len(self._category_index),
            },
        }

    def clear_buffer(self) -> None:
        """Clear the event buffer and indexes."""
        self.event_buffer.clear()
        self._ip_index.clear()
        self._user_index.clear()
        self._host_index.clear()
        self._category_index.clear()

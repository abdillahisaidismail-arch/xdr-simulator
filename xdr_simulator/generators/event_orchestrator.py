"""
Event Orchestrator.
Coordinates event generation across all sources to produce realistic
traffic patterns simulating a banking SI with 10,000+ events/day.
"""

import random
from datetime import datetime, timezone, timedelta
from typing import Iterator

from .syslog_generator import SyslogGenerator
from .filebeat_generator import FilebeatGenerator
from .json_generator import JSONAPIGenerator
from ..utils.logger import get_logger


class EventOrchestrator:
    """
    Orchestrate multi-source event generation.

    Produces a realistic mix of events from Syslog, Filebeat, and JSON sources
    with time-based traffic patterns (business hours peak, night low, attack
    bursts).
    """

    # Traffic distribution by hour (0-23) — multiplier on base rate
    HOURLY_WEIGHTS = {
        0: 0.3, 1: 0.2, 2: 0.15, 3: 0.15, 4: 0.2, 5: 0.3,
        6: 0.5, 7: 0.8, 8: 1.2, 9: 1.5, 10: 1.5, 11: 1.4,
        12: 1.0, 13: 1.3, 14: 1.5, 15: 1.4, 16: 1.3, 17: 1.0,
        18: 0.7, 19: 0.5, 20: 0.4, 21: 0.35, 22: 0.3, 23: 0.3,
    }

    # Source distribution weights
    SOURCE_WEIGHTS = {
        "syslog": 40,
        "filebeat": 35,
        "json_api": 25,
    }

    def __init__(
        self,
        events_per_day: int = 12000,
        attack_probability: float = 0.12,
    ):
        self.events_per_day = events_per_day
        self.attack_probability = attack_probability
        self.logger = get_logger()

        # Initialize generators
        self.syslog = SyslogGenerator(attack_probability)
        self.filebeat = FilebeatGenerator(attack_probability)
        self.json_api = JSONAPIGenerator(attack_probability)

        self.logger.log_event(
            "info",
            f"EventOrchestrator initialized: {events_per_day} events/day, "
            f"attack_prob={attack_probability:.0%}",
        )

    def generate_day(
        self,
        date: datetime | None = None,
        inject_attack_scenario: bool = True,
    ) -> list[dict]:
        """
        Generate a full day of events.

        Args:
            date: The date to generate events for (default: today).
            inject_attack_scenario: Whether to inject a coordinated attack.

        Returns:
            List of events sorted by timestamp.
        """
        if date is None:
            date = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )

        events = []
        total_weight = sum(self.HOURLY_WEIGHTS.values())

        for hour in range(24):
            weight = self.HOURLY_WEIGHTS[hour]
            hourly_count = int(
                self.events_per_day * (weight / total_weight)
            )

            for _ in range(hourly_count):
                # Random minute/second within the hour
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = date.replace(hour=hour, minute=minute, second=second)

                event = self._generate_single_event(ts)
                events.append(event)

        # Inject coordinated attack scenario
        if inject_attack_scenario:
            attack_events = self._generate_attack_scenario(date)
            events.extend(attack_events)
            self.logger.log_event(
                "info",
                f"Injected attack scenario: {len(attack_events)} events",
            )

        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", e.get("@timestamp", "")))

        self.logger.log_event(
            "info",
            f"Generated {len(events)} events for {date.strftime('%Y-%m-%d')}",
        )
        self.logger.log_audit(
            "EVENT_GENERATION",
            {
                "date": date.isoformat(),
                "total_events": len(events),
                "attack_scenario": inject_attack_scenario,
            },
        )

        return events

    def stream_events(
        self,
        date: datetime | None = None,
        batch_size: int = 100,
    ) -> Iterator[list[dict]]:
        """
        Stream events in batches (for real-time simulation).

        Yields:
            Batches of events.
        """
        events = self.generate_day(date)
        for i in range(0, len(events), batch_size):
            yield events[i : i + batch_size]

    def _generate_single_event(self, timestamp: datetime) -> dict:
        """Generate a single event from a randomly selected source."""
        source = random.choices(
            ["syslog", "filebeat", "json_api"],
            weights=[
                self.SOURCE_WEIGHTS["syslog"],
                self.SOURCE_WEIGHTS["filebeat"],
                self.SOURCE_WEIGHTS["json_api"],
            ],
            k=1,
        )[0]

        generators = {
            "syslog": self.syslog,
            "filebeat": self.filebeat,
            "json_api": self.json_api,
        }

        return generators[source].generate_event(timestamp)

    def _generate_attack_scenario(self, date: datetime) -> list[dict]:
        """
        Generate a coordinated multi-phase attack scenario.

        Phase 1 (02:00-02:30): SSH brute-force reconnaissance
        Phase 2 (02:30-03:00): Successful login + lateral movement
        Phase 3 (03:00-03:30): Privilege escalation attempts
        Phase 4 (03:30-04:00): Data access + potential exfiltration
        """
        events = []
        attacker_ip = f"185.220.101.{random.randint(1, 254)}"
        compromised_user = "svc_backup"
        target_host = "srv-core-banking-01"

        # Phase 1: SSH Brute Force (02:00 - 02:30)
        base_time = date.replace(hour=2, minute=0, second=0)
        for i in range(random.randint(30, 60)):
            ts = base_time + timedelta(seconds=random.randint(0, 1800))
            user = random.choice(["root", "admin", "test", "oracle",
                                  compromised_user])
            events.append({
                "raw": (
                    f"<86>{ts.strftime('%b %d %H:%M:%S')} {target_host} "
                    f"sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {'invalid user ' if user != compromised_user else ''}"
                    f"{user} from {attacker_ip} "
                    f"port {random.randint(40000,65535)} ssh2"
                ),
                "timestamp": ts.isoformat(),
                "hostname": target_host,
                "facility": "authpriv",
                "severity": "warning",
                "message": f"Failed password for {user} from {attacker_ip}",
                "source_type": "syslog",
                "attack_phase": "reconnaissance",
                "attacker_ip": attacker_ip,
            })

        # Phase 2: Successful login (02:30)
        ts = date.replace(hour=2, minute=30, second=random.randint(0, 59))
        events.append({
            "raw": (
                f"<86>{ts.strftime('%b %d %H:%M:%S')} {target_host} "
                f"sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {compromised_user} from {attacker_ip} "
                f"port {random.randint(40000,65535)} ssh2"
            ),
            "timestamp": ts.isoformat(),
            "hostname": target_host,
            "facility": "authpriv",
            "severity": "info",
            "message": f"Accepted password for {compromised_user} from {attacker_ip}",
            "source_type": "syslog",
            "attack_phase": "initial_access",
            "attacker_ip": attacker_ip,
        })

        # Phase 3: Privilege escalation (03:00 - 03:30)
        base_time = date.replace(hour=3, minute=0, second=0)
        privesc_commands = [
            "/usr/bin/sudo -l",
            "/usr/bin/find / -perm -4000 -type f",
            "/usr/bin/passwd root",
            "/bin/chmod 4755 /tmp/.backdoor",
            "/usr/sbin/useradd -o -u 0 -g 0 admin2",
        ]
        for cmd in privesc_commands:
            ts = base_time + timedelta(seconds=random.randint(0, 1800))
            events.append({
                "raw": (
                    f"<84>{ts.strftime('%b %d %H:%M:%S')} {target_host} "
                    f"sudo: {compromised_user} : command not allowed ; "
                    f"TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND={cmd}"
                ),
                "timestamp": ts.isoformat(),
                "hostname": target_host,
                "facility": "authpriv",
                "severity": "alert",
                "message": f"Privilege escalation attempt: {cmd}",
                "source_type": "syslog",
                "attack_phase": "privilege_escalation",
                "attacker_ip": attacker_ip,
            })

        # Phase 4: Abnormal data access (03:30 - 04:00)
        base_time = date.replace(hour=3, minute=30, second=0)
        for _ in range(random.randint(5, 15)):
            ts = base_time + timedelta(seconds=random.randint(0, 1800))
            events.append({
                "@timestamp": ts.isoformat(),
                "event_id": f"evt-{random.randint(100000, 999999)}",
                "source_type": "filebeat",
                "agent": {
                    "hostname": target_host,
                    "type": "filebeat",
                    "version": "8.11.0",
                },
                "source": {"ip": attacker_ip},
                "destination": {"ip": "10.10.1.15", "port": 443},
                "http": {
                    "request": {
                        "method": "GET",
                        "path": random.choice([
                            "/api/v1/admin/database/export",
                            "/api/v1/reports/transactions?range=all",
                            "/api/v1/admin/users?export=csv",
                            "/api/v1/swift/messages?all=true",
                        ]),
                        "user_agent": "python-requests/2.31.0",
                    },
                    "response": {
                        "status_code": 200,
                        "bytes": random.randint(100000, 5000000),
                    },
                },
                "event": {
                    "category": "web",
                    "outcome": "success",
                    "tags": ["data_access", "potential_exfil"],
                },
                "user": {"name": compromised_user},
                "attack_phase": "data_exfiltration",
                "attacker_ip": attacker_ip,
            })

        return events

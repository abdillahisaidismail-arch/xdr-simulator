"""
Filebeat event generator.
Simulates Filebeat-style structured log events from various banking
infrastructure sources: web servers, application servers, firewalls.
"""

import random
import uuid
from datetime import datetime, timezone

from ..utils.models import SourceType


class FilebeatGenerator:
    """Generate realistic Filebeat-format events."""

    AGENT_HOSTNAMES = [
        "srv-web-portal-01", "srv-web-portal-02",
        "srv-api-gateway-01", "srv-core-banking-01",
        "fw-perimeter-01", "srv-proxy-01",
        "srv-atm-controller-01",
    ]

    HTTP_PATHS = [
        "/api/v1/accounts/balance",
        "/api/v1/transfers/initiate",
        "/api/v1/auth/login",
        "/api/v1/auth/token/refresh",
        "/api/v1/admin/users",
        "/api/v1/admin/config",
        "/api/v1/reports/transactions",
        "/api/v1/swift/messages",
        "/portal/dashboard",
        "/portal/admin/settings",
        "/api/v1/cards/activate",
        "/api/v1/atm/status",
    ]

    ADMIN_PATHS = [
        "/api/v1/admin/users",
        "/api/v1/admin/config",
        "/portal/admin/settings",
        "/api/v1/admin/audit-log",
        "/api/v1/admin/roles",
        "/api/v1/admin/database/export",
    ]

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "python-requests/2.31.0",
        "curl/7.88.1",
        "PostmanRuntime/7.32.3",
        "Java/17.0.2",
    ]

    SUSPICIOUS_USER_AGENTS = [
        "sqlmap/1.7",
        "Nikto/2.1.6",
        "dirb/2.22",
        "python-requests/2.31.0",
        "curl/7.88.1",
        "Go-http-client/1.1",
    ]

    def __init__(self, attack_probability: float = 0.12):
        self.attack_probability = attack_probability
        self.source_type = SourceType.FILEBEAT

    def generate_event(self, timestamp: datetime | None = None) -> dict:
        """Generate a single Filebeat event."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        if random.random() < self.attack_probability:
            return self._generate_attack_event(timestamp)
        return self._generate_normal_event(timestamp)

    def _generate_normal_event(self, timestamp: datetime) -> dict:
        """Generate a normal Filebeat web/application event."""
        event_type = random.choices(
            ["http_access", "application_log", "firewall_log"],
            weights=[50, 30, 20],
            k=1,
        )[0]

        generators = {
            "http_access": self._http_access_event,
            "application_log": self._application_log_event,
            "firewall_log": self._firewall_log_event,
        }

        return generators[event_type](timestamp, is_attack=False)

    def _generate_attack_event(self, timestamp: datetime) -> dict:
        """Generate an attack-related Filebeat event."""
        attack_type = random.choices(
            ["abnormal_access", "web_scan", "data_exfil"],
            weights=[40, 35, 25],
            k=1,
        )[0]

        if attack_type == "abnormal_access":
            return self._abnormal_http_access(timestamp)
        elif attack_type == "web_scan":
            return self._web_scanning_event(timestamp)
        else:
            return self._data_exfiltration_event(timestamp)

    def _http_access_event(self, timestamp: datetime,
                           is_attack: bool = False) -> dict:
        """Generate HTTP access log in Filebeat format."""
        hostname = random.choice(self.AGENT_HOSTNAMES)
        src_ip = f"10.10.{random.randint(1,5)}.{random.randint(10,200)}"
        method = random.choices(
            ["GET", "POST", "PUT", "DELETE"],
            weights=[60, 25, 10, 5],
            k=1,
        )[0]
        path = random.choice(self.HTTP_PATHS)
        status = random.choices(
            [200, 201, 301, 400, 401, 403, 404, 500],
            weights=[50, 10, 5, 5, 5, 5, 10, 10],
            k=1,
        )[0]

        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": hostname,
                "type": "filebeat",
                "version": "8.11.0",
            },
            "source": {"ip": src_ip},
            "destination": {
                "ip": f"10.10.1.{random.randint(10,20)}",
                "port": 443,
            },
            "http": {
                "request": {
                    "method": method,
                    "path": path,
                    "user_agent": random.choice(self.USER_AGENTS),
                },
                "response": {
                    "status_code": status,
                    "bytes": random.randint(200, 50000),
                },
            },
            "event": {
                "category": "web",
                "outcome": "success" if status < 400 else "failure",
            },
            "user": {
                "name": f"user_{random.randint(1000, 9999)}",
            },
        }

    def _application_log_event(self, timestamp: datetime,
                               is_attack: bool = False) -> dict:
        """Generate application-level log event."""
        hostname = random.choice(self.AGENT_HOSTNAMES)
        log_levels = ["INFO", "WARN", "DEBUG"]
        level = random.choice(log_levels)

        messages = [
            "Transaction processed successfully: TXN-{}".format(
                random.randint(100000, 999999)
            ),
            "Database connection pool: {}/50 active".format(
                random.randint(5, 45)
            ),
            "SWIFT message sent: MT{} ref=BCD{}".format(
                random.choice(["103", "202", "940", "950"]),
                random.randint(10000, 99999),
            ),
            "Batch job completed: daily_reconciliation (0 discrepancies)",
            "Certificate expiry check: all certificates valid",
            "Session created for user admin_bcd (IP: 10.10.1.{})".format(
                random.randint(10, 50)
            ),
        ]

        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": hostname,
                "type": "filebeat",
                "version": "8.11.0",
            },
            "log": {
                "level": level,
                "logger": "com.bcd.banking.core",
            },
            "message": random.choice(messages),
            "event": {
                "category": "application",
                "outcome": "success",
            },
        }

    def _firewall_log_event(self, timestamp: datetime,
                            is_attack: bool = False) -> dict:
        """Generate firewall log event in Filebeat format."""
        hostname = random.choice(["fw-perimeter-01", "fw-internal-01"])
        action = random.choices(
            ["ALLOW", "DENY", "DROP"],
            weights=[70, 20, 10],
            k=1,
        )[0]

        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": hostname,
                "type": "filebeat",
                "version": "8.11.0",
            },
            "source": {
                "ip": f"10.10.{random.randint(1,5)}.{random.randint(10,200)}"
                if action == "ALLOW"
                else f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "port": random.randint(1024, 65535),
            },
            "destination": {
                "ip": f"10.10.1.{random.randint(10,50)}",
                "port": random.choice([22, 80, 443, 1521, 3306, 8080]),
            },
            "network": {
                "protocol": random.choice(["TCP", "UDP"]),
                "direction": "inbound",
            },
            "firewall": {
                "action": action,
                "rule_id": f"FW-{random.randint(100, 999)}",
            },
            "event": {
                "category": "network",
                "outcome": "success" if action == "ALLOW" else "failure",
            },
        }

    def _abnormal_http_access(self, timestamp: datetime) -> dict:
        """Generate abnormal HTTP access — accessing admin endpoints
        from unusual IPs or outside business hours."""
        external_ip = f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": random.choice(self.AGENT_HOSTNAMES),
                "type": "filebeat",
                "version": "8.11.0",
            },
            "source": {"ip": external_ip},
            "destination": {
                "ip": "10.10.1.15",
                "port": 443,
            },
            "http": {
                "request": {
                    "method": random.choice(["GET", "POST", "PUT"]),
                    "path": random.choice(self.ADMIN_PATHS),
                    "user_agent": random.choice(self.USER_AGENTS),
                },
                "response": {
                    "status_code": random.choice([200, 403, 401]),
                    "bytes": random.randint(500, 5000),
                },
            },
            "event": {
                "category": "web",
                "outcome": "success",
                "tags": ["abnormal_access", "admin_endpoint"],
            },
            "user": {
                "name": random.choice(["admin_bcd", "admin_security"]),
            },
        }

    def _web_scanning_event(self, timestamp: datetime) -> dict:
        """Generate web scanning/reconnaissance event."""
        scanner_ip = f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        scan_paths = [
            "/admin", "/wp-admin", "/phpmyadmin", "/.env",
            "/api/v1/../../../etc/passwd", "/backup.sql",
            "/api/swagger.json", "/.git/config",
            "/server-status", "/actuator/health",
        ]

        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": "srv-web-portal-01",
                "type": "filebeat",
                "version": "8.11.0",
            },
            "source": {"ip": scanner_ip},
            "destination": {"ip": "10.10.1.15", "port": 443},
            "http": {
                "request": {
                    "method": "GET",
                    "path": random.choice(scan_paths),
                    "user_agent": random.choice(self.SUSPICIOUS_USER_AGENTS),
                },
                "response": {
                    "status_code": random.choice([403, 404, 500]),
                    "bytes": random.randint(100, 1000),
                },
            },
            "event": {
                "category": "web",
                "outcome": "failure",
                "tags": ["web_scan", "reconnaissance"],
            },
        }

    def _data_exfiltration_event(self, timestamp: datetime) -> dict:
        """Generate potential data exfiltration event — large response."""
        return {
            "@timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "source_type": SourceType.FILEBEAT.value,
            "agent": {
                "hostname": random.choice(self.AGENT_HOSTNAMES),
                "type": "filebeat",
                "version": "8.11.0",
            },
            "source": {
                "ip": f"10.10.1.{random.randint(10,50)}",
            },
            "destination": {
                "ip": f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "port": 443,
            },
            "http": {
                "request": {
                    "method": "POST",
                    "path": "/api/v1/reports/transactions",
                    "user_agent": "python-requests/2.31.0",
                },
                "response": {
                    "status_code": 200,
                    "bytes": random.randint(500000, 5000000),  # Large payload
                },
            },
            "event": {
                "category": "web",
                "outcome": "success",
                "tags": ["large_response", "potential_exfil"],
            },
            "user": {
                "name": random.choice(["svc_batch", "analyst_risk"]),
            },
        }

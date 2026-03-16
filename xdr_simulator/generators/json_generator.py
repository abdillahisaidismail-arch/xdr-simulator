"""
JSON API event generator.
Simulates structured JSON events from application APIs, SIEM feeds,
and custom banking applications in the Banque Centrale de Djibouti SI.
"""

import random
import uuid
from datetime import datetime, timezone

from ..utils.models import SourceType


class JSONAPIGenerator:
    """Generate realistic JSON-format events from banking APIs."""

    APPLICATION_NAMES = [
        "core-banking-system", "swift-gateway",
        "atm-monitoring", "card-management",
        "customer-portal", "risk-engine",
        "fraud-detection", "audit-system",
        "batch-processor", "reporting-engine",
    ]

    TRANSACTION_TYPES = [
        "TRANSFER_DOMESTIC", "TRANSFER_INTERNATIONAL",
        "CASH_WITHDRAWAL", "CASH_DEPOSIT",
        "CARD_PAYMENT", "SWIFT_MT103",
        "SWIFT_MT202", "STANDING_ORDER",
        "SALARY_BATCH", "FEE_COLLECTION",
    ]

    def __init__(self, attack_probability: float = 0.10):
        self.attack_probability = attack_probability
        self.source_type = SourceType.JSON_API

    def generate_event(self, timestamp: datetime | None = None) -> dict:
        """Generate a single JSON API event."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        if random.random() < self.attack_probability:
            return self._generate_attack_event(timestamp)
        return self._generate_normal_event(timestamp)

    def _generate_normal_event(self, timestamp: datetime) -> dict:
        """Generate a normal banking application event."""
        event_type = random.choices(
            ["transaction", "auth_event", "system_health", "audit_event"],
            weights=[35, 25, 20, 20],
            k=1,
        )[0]

        generators = {
            "transaction": self._transaction_event,
            "auth_event": self._auth_event,
            "system_health": self._system_health_event,
            "audit_event": self._audit_event,
        }

        return generators[event_type](timestamp, is_attack=False)

    def _generate_attack_event(self, timestamp: datetime) -> dict:
        """Generate an attack-indicator JSON event."""
        attack_type = random.choices(
            ["brute_force_api", "privilege_abuse", "abnormal_transaction"],
            weights=[40, 30, 30],
            k=1,
        )[0]

        if attack_type == "brute_force_api":
            return self._brute_force_api_event(timestamp)
        elif attack_type == "privilege_abuse":
            return self._privilege_abuse_event(timestamp)
        else:
            return self._abnormal_transaction_event(timestamp)

    def _transaction_event(self, timestamp: datetime,
                           is_attack: bool = False) -> dict:
        """Generate a banking transaction event."""
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": random.choice(self.APPLICATION_NAMES[:4]),
            "event_type": "transaction",
            "transaction": {
                "id": f"TXN-{random.randint(100000, 999999)}",
                "type": random.choice(self.TRANSACTION_TYPES),
                "amount": round(random.uniform(100, 500000), 2),
                "currency": random.choice(["DJF", "USD", "EUR"]),
                "status": "completed",
                "source_account": f"DJ{random.randint(10000000, 99999999)}",
                "destination_account": f"DJ{random.randint(10000000, 99999999)}",
            },
            "user": {
                "id": f"USR-{random.randint(1000, 9999)}",
                "role": random.choice(["teller", "officer", "manager"]),
                "ip": f"10.10.1.{random.randint(10, 200)}",
            },
            "metadata": {
                "channel": random.choice(["branch", "online", "mobile", "atm"]),
                "branch_code": f"BCD-{random.randint(1, 15):03d}",
            },
        }

    def _auth_event(self, timestamp: datetime,
                    is_attack: bool = False) -> dict:
        """Generate an authentication event from the banking app."""
        success = random.random() > 0.1
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": random.choice(["customer-portal", "core-banking-system"]),
            "event_type": "authentication",
            "auth": {
                "method": random.choice(["password", "mfa", "certificate", "token"]),
                "outcome": "success" if success else "failure",
                "reason": None if success else random.choice([
                    "invalid_password", "expired_token",
                    "invalid_mfa_code", "account_locked",
                ]),
            },
            "user": {
                "id": f"USR-{random.randint(1000, 9999)}",
                "username": f"user_{random.randint(100, 999)}",
                "role": random.choice(["customer", "teller", "admin"]),
                "ip": f"10.10.{random.randint(1,5)}.{random.randint(10, 200)}",
            },
            "session": {
                "id": str(uuid.uuid4()),
                "duration_seconds": random.randint(0, 3600) if success else 0,
            },
        }

    def _system_health_event(self, timestamp: datetime,
                             is_attack: bool = False) -> dict:
        """Generate a system health / monitoring event."""
        app = random.choice(self.APPLICATION_NAMES)
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": app,
            "event_type": "health_check",
            "health": {
                "status": random.choices(
                    ["healthy", "degraded", "critical"],
                    weights=[80, 15, 5],
                    k=1,
                )[0],
                "cpu_percent": round(random.uniform(5, 95), 1),
                "memory_percent": round(random.uniform(20, 90), 1),
                "disk_percent": round(random.uniform(10, 85), 1),
                "active_connections": random.randint(5, 500),
                "response_time_ms": random.randint(1, 2000),
            },
            "hostname": f"srv-{app.split('-')[0]}-01",
        }

    def _audit_event(self, timestamp: datetime,
                     is_attack: bool = False) -> dict:
        """Generate an audit trail event (PCI-DSS compliant)."""
        actions = [
            ("VIEW", "customer_record", "low"),
            ("MODIFY", "account_settings", "medium"),
            ("CREATE", "new_account", "medium"),
            ("DELETE", "temporary_hold", "high"),
            ("EXPORT", "transaction_report", "high"),
            ("APPROVE", "wire_transfer", "high"),
        ]
        action, resource, risk = random.choice(actions)

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": "audit-system",
            "event_type": "audit",
            "audit": {
                "action": action,
                "resource": resource,
                "risk_level": risk,
                "result": "authorized",
            },
            "user": {
                "id": f"USR-{random.randint(1000, 9999)}",
                "role": random.choice(["teller", "officer", "manager", "admin"]),
                "ip": f"10.10.1.{random.randint(10, 200)}",
            },
            "pci_dss": {
                "requirement": "10.2",
                "sub_requirement": random.choice([
                    "10.2.1", "10.2.2", "10.2.4", "10.2.5", "10.2.7",
                ]),
            },
        }

    def _brute_force_api_event(self, timestamp: datetime) -> dict:
        """Generate brute-force attack on API authentication."""
        attacker_ip = f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": "customer-portal",
            "event_type": "authentication",
            "auth": {
                "method": "password",
                "outcome": "failure",
                "reason": random.choice([
                    "invalid_password", "invalid_username",
                    "account_not_found",
                ]),
            },
            "user": {
                "id": None,
                "username": random.choice([
                    "admin", "root", "test", "administrator",
                    f"user_{random.randint(1,100)}",
                ]),
                "ip": attacker_ip,
            },
            "metadata": {
                "attempt_count": random.randint(5, 50),
                "tags": ["brute_force", "api_auth"],
            },
        }

    def _privilege_abuse_event(self, timestamp: datetime) -> dict:
        """Generate privilege abuse / escalation event."""
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": "core-banking-system",
            "event_type": "authorization",
            "auth": {
                "action": random.choice([
                    "ROLE_CHANGE", "PERMISSION_GRANT",
                    "ADMIN_ACCESS", "CONFIG_MODIFY",
                ]),
                "outcome": random.choice(["success", "failure"]),
                "target_role": "admin",
                "previous_role": "teller",
            },
            "user": {
                "id": f"USR-{random.randint(1000, 9999)}",
                "username": random.choice([
                    "temp_user", "intern_01", "contractor_ext",
                ]),
                "role": "teller",
                "ip": f"10.10.{random.randint(1,5)}.{random.randint(10, 200)}",
            },
            "metadata": {
                "tags": ["privilege_escalation", "role_change"],
                "risk_score": random.randint(70, 100),
            },
        }

    def _abnormal_transaction_event(self, timestamp: datetime) -> dict:
        """Generate an abnormal/suspicious transaction event."""
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "source_type": SourceType.JSON_API.value,
            "application": "core-banking-system",
            "event_type": "transaction",
            "transaction": {
                "id": f"TXN-{random.randint(100000, 999999)}",
                "type": "TRANSFER_INTERNATIONAL",
                "amount": round(random.uniform(500000, 5000000), 2),
                "currency": "USD",
                "status": "pending_review",
                "source_account": f"DJ{random.randint(10000000, 99999999)}",
                "destination_account": f"XX{random.randint(10000000, 99999999)}",
                "destination_country": random.choice([
                    "KY", "PA", "VG", "BZ",  # High-risk jurisdictions
                ]),
            },
            "user": {
                "id": f"USR-{random.randint(1000, 9999)}",
                "role": "teller",
                "ip": f"10.10.1.{random.randint(10, 200)}",
            },
            "metadata": {
                "tags": ["high_value", "international", "suspicious"],
                "risk_score": random.randint(75, 100),
                "aml_flag": True,
            },
        }

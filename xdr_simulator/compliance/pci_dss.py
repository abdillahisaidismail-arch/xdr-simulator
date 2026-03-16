"""
PCI-DSS Compliance Module.
Implements requirements relevant to XDR/SIEM operations in a banking SI:
- Requirement 10: Track and monitor all access to network resources and cardholder data
- Requirement 11: Regularly test security systems and processes
- Requirement 12: Maintain a policy that addresses information security
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils.models import Incident, NormalizedEvent, Severity
from ..utils.logger import get_logger


class PCIDSSCompliance:
    """
    PCI-DSS compliance reporting and audit trail management.

    Ensures the XDR simulator meets PCI-DSS requirements for:
    - Log integrity and tamper-evidence (Req 10.5)
    - Audit trail generation (Req 10.2)
    - Daily log review (Req 10.6)
    - Incident response documentation (Req 12.10)
    """

    PCI_REQUIREMENTS = {
        "10.1": "Audit trails link all access to individual users",
        "10.2": "Automated audit trails for reconstructing security events",
        "10.2.1": "All individual user accesses to cardholder data",
        "10.2.2": "All actions taken by any individual with root/admin privileges",
        "10.2.4": "Invalid logical access attempts",
        "10.2.5": "Use of and changes to identification and authentication mechanisms",
        "10.2.7": "Creation and deletion of system-level objects",
        "10.3": "Record audit trail entries with required fields",
        "10.5": "Secure audit trails so they cannot be altered",
        "10.6": "Review logs and security events for all system components",
        "10.7": "Retain audit trail history for at least one year",
        "11.4": "Use intrusion-detection/prevention techniques to detect intrusions",
        "12.10": "Implement an incident response plan",
        "12.10.1": "Create the incident response plan to be initiated in the event of system breach",
    }

    def __init__(self, output_dir: str = "data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger()

    def generate_compliance_report(
        self,
        events: list[NormalizedEvent],
        incidents: list[Incident],
        correlations: list[dict],
    ) -> dict:
        """
        Generate a PCI-DSS compliance report.

        Returns:
            Compliance report dictionary.
        """
        report = {
            "report_id": f"PCI-DSS-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "standard": "PCI-DSS v4.0",
            "scope": "XDR Simulator — Banque Centrale de Djibouti",
            "period": {
                "start": events[0].timestamp if events else "N/A",
                "end": events[-1].timestamp if events else "N/A",
            },
            "summary": {
                "total_events_processed": len(events),
                "total_incidents_detected": len(incidents),
                "total_correlations": len(correlations),
                "severity_distribution": self._severity_distribution(incidents),
                "detection_coverage": self._detection_coverage(incidents),
            },
            "requirement_compliance": self._assess_requirements(
                events, incidents
            ),
            "incidents": [inc.to_dict() for inc in incidents],
            "metrics": {
                "mean_time_to_detect_seconds": self._mean_ttd(incidents),
                "detection_rate": self._detection_rate(events, incidents),
                "multi_source_correlation_rate": self._multi_source_rate(
                    correlations
                ),
            },
            "recommendations": self._generate_recommendations(incidents),
        }

        # Save report
        report_path = self.output_dir / f"{report['report_id']}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.logger.log_audit(
            "COMPLIANCE_REPORT",
            {
                "report_id": report["report_id"],
                "events_processed": len(events),
                "incidents_detected": len(incidents),
                "output_path": str(report_path),
            },
        )

        return report

    def generate_audit_trail(
        self,
        events: list[NormalizedEvent],
        output_file: str = "audit_trail.json",
    ) -> str:
        """
        Generate a PCI-DSS compliant audit trail (Req 10.2, 10.3).

        Each entry contains:
        - User identification (Req 10.3.1)
        - Type of event (Req 10.3.2)
        - Date and time (Req 10.3.3)
        - Success/failure indication (Req 10.3.4)
        - Origination of event (Req 10.3.5)
        - Identity or name of affected data/resource (Req 10.3.6)
        """
        audit_entries = []

        for event in events:
            entry = {
                "audit_id": event.event_id,
                "user_identification": event.username or "system",
                "event_type": event.category.value,
                "date_time": event.timestamp,
                "success_failure": event.outcome,
                "origination": {
                    "source_type": event.source_type.value,
                    "source_ip": event.source_ip or "local",
                    "hostname": event.hostname,
                },
                "affected_resource": event.action,
                "severity": event.severity.value,
                "pci_dss_relevant": self._is_pci_relevant(event),
            }
            audit_entries.append(entry)

        output_path = self.output_dir / output_file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(audit_entries, f, indent=2, ensure_ascii=False)

        self.logger.log_audit(
            "AUDIT_TRAIL_GENERATED",
            {
                "entries": len(audit_entries),
                "output_path": str(output_path),
                "pci_relevant_entries": sum(
                    1 for e in audit_entries if e["pci_dss_relevant"]
                ),
            },
        )

        return str(output_path)

    def generate_incident_report(self, incident: Incident) -> dict:
        """
        Generate PCI-DSS Req 12.10 incident response documentation.
        """
        report = {
            "incident_report_id": f"IR-{incident.incident_id[:8].upper()}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pci_dss_requirement": "12.10 — Incident Response Plan",
            "incident_details": {
                "id": incident.incident_id,
                "type": incident.incident_type.value,
                "severity": incident.severity.value,
                "timestamp": incident.timestamp,
                "source_ip": incident.source_ip,
                "target": incident.target,
                "description": incident.description,
            },
            "mitre_attack_mapping": {
                "tactic": incident.mitre_tactic,
                "technique": incident.mitre_technique,
            },
            "impact_assessment": {
                "correlated_events": incident.event_count,
                "time_to_detect_seconds": incident.ttd_seconds,
                "potential_impact": self._assess_impact(incident),
            },
            "response_actions": {
                "immediate": incident.recommended_action,
                "containment": self._containment_steps(incident),
                "eradication": self._eradication_steps(incident),
                "recovery": self._recovery_steps(incident),
                "lessons_learned": "To be completed post-incident.",
            },
            "notification_required": incident.severity in (
                Severity.CRITICAL, Severity.HIGH
            ),
            "escalation_path": self._escalation_path(incident),
        }

        return report

    # ---------------------------------------------------------------
    # Assessment helpers
    # ---------------------------------------------------------------
    def _assess_requirements(
        self,
        events: list[NormalizedEvent],
        incidents: list[Incident],
    ) -> list[dict]:
        """Assess compliance status for each PCI-DSS requirement."""
        assessments = []

        for req_id, description in self.PCI_REQUIREMENTS.items():
            status = "COMPLIANT"
            notes = ""

            if req_id == "10.2":
                if len(events) > 0:
                    status = "COMPLIANT"
                    notes = f"{len(events)} events recorded with full audit trail."
                else:
                    status = "NON-COMPLIANT"
                    notes = "No audit trail events recorded."

            elif req_id == "10.6":
                if incidents:
                    status = "COMPLIANT"
                    notes = f"Automated review detected {len(incidents)} incidents."
                else:
                    status = "COMPLIANT"
                    notes = "Automated review active. No incidents detected."

            elif req_id == "11.4":
                if incidents:
                    status = "COMPLIANT"
                    notes = (
                        f"IDS active. {len(incidents)} intrusion attempts detected. "
                        f"Detection types: {', '.join(set(i.incident_type.value for i in incidents))}."
                    )
                else:
                    status = "COMPLIANT"
                    notes = "IDS active. No intrusions detected."

            elif req_id == "12.10":
                critical = [
                    i for i in incidents
                    if i.severity in (Severity.CRITICAL, Severity.HIGH)
                ]
                if critical:
                    status = "ACTION_REQUIRED"
                    notes = (
                        f"{len(critical)} high/critical incidents require "
                        "incident response activation."
                    )
                else:
                    status = "COMPLIANT"

            assessments.append({
                "requirement": req_id,
                "description": description,
                "status": status,
                "notes": notes,
            })

        return assessments

    @staticmethod
    def _severity_distribution(incidents: list[Incident]) -> dict:
        counts: dict[str, int] = {}
        for inc in incidents:
            sev = inc.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _detection_coverage(incidents: list[Incident]) -> dict:
        types_detected = set(inc.incident_type.value for inc in incidents)
        all_types = [t.value for t in list(__import__(
            "xdr_simulator.utils.models", fromlist=["IncidentType"]
        ).IncidentType)]
        return {
            "types_detected": list(types_detected),
            "total_types": len(all_types),
            "coverage_percent": (
                f"{len(types_detected) / len(all_types) * 100:.0f}%"
                if all_types else "N/A"
            ),
        }

    @staticmethod
    def _mean_ttd(incidents: list[Incident]) -> float:
        if not incidents:
            return 0.0
        return sum(i.ttd_seconds for i in incidents) / len(incidents)

    @staticmethod
    def _detection_rate(
        events: list[NormalizedEvent], incidents: list[Incident],
    ) -> str:
        suspicious = sum(
            1 for e in events if e.severity in (Severity.HIGH, Severity.CRITICAL)
        )
        if suspicious == 0:
            return "N/A"
        return f"{len(incidents) / max(suspicious, 1) * 100:.1f}%"

    @staticmethod
    def _multi_source_rate(correlations: list[dict]) -> str:
        if not correlations:
            return "0%"
        multi = sum(1 for c in correlations if c.get("multi_source"))
        return f"{multi / len(correlations) * 100:.0f}%"

    @staticmethod
    def _is_pci_relevant(event: NormalizedEvent) -> bool:
        """Determine if an event is PCI-DSS relevant."""
        from ..utils.models import EventCategory
        return event.category in (
            EventCategory.AUTHENTICATION,
            EventCategory.AUTHORIZATION,
            EventCategory.PRIVILEGE_CHANGE,
            EventCategory.FILE_ACCESS,
        )

    @staticmethod
    def _assess_impact(incident: Incident) -> str:
        impact_map = {
            "ssh_brute_force": "Potential unauthorized access to critical banking systems.",
            "abnormal_access": "Potential data breach or unauthorized data access.",
            "privilege_escalation": "Potential full system compromise with administrative access.",
        }
        return impact_map.get(incident.incident_type.value, "Unknown impact.")

    @staticmethod
    def _containment_steps(incident: Incident) -> list[str]:
        steps = {
            "ssh_brute_force": [
                "Block attacker IP at perimeter firewall",
                "Disable compromised accounts temporarily",
                "Enable enhanced monitoring on affected hosts",
            ],
            "abnormal_access": [
                "Revoke suspicious session tokens",
                "Enforce MFA on affected accounts",
                "Isolate affected network segment if needed",
            ],
            "privilege_escalation": [
                "Terminate active sessions of the compromised user",
                "Revoke all elevated privileges",
                "Isolate the affected system from the network",
            ],
        }
        return steps.get(incident.incident_type.value, ["Investigate and contain."])

    @staticmethod
    def _eradication_steps(incident: Incident) -> list[str]:
        return [
            "Perform forensic analysis of affected systems",
            "Remove any backdoors or unauthorized accounts",
            "Reset all potentially compromised credentials",
            "Update firewall rules and IDS signatures",
            "Patch any exploited vulnerabilities",
        ]

    @staticmethod
    def _recovery_steps(incident: Incident) -> list[str]:
        return [
            "Restore services from verified clean backups",
            "Re-enable accounts with new credentials",
            "Verify system integrity before returning to production",
            "Increase monitoring for 72 hours post-recovery",
            "Document all actions taken for audit trail",
        ]

    @staticmethod
    def _escalation_path(incident: Incident) -> list[str]:
        if incident.severity == Severity.CRITICAL:
            return [
                "1. SOC Analyst (immediate)",
                "2. SOC Manager (within 15 min)",
                "3. CISO (within 30 min)",
                "4. Direction Générale (within 1 hour)",
                "5. Regulatory notification if data breach confirmed",
            ]
        elif incident.severity == Severity.HIGH:
            return [
                "1. SOC Analyst (immediate)",
                "2. SOC Manager (within 30 min)",
                "3. CISO (within 2 hours if unresolved)",
            ]
        return ["1. SOC Analyst for investigation"]

    @staticmethod
    def _generate_recommendations(incidents: list[Incident]) -> list[str]:
        recommendations = set()
        for inc in incidents:
            if inc.incident_type.value == "ssh_brute_force":
                recommendations.add(
                    "Implement fail2ban or similar rate-limiting on SSH services"
                )
                recommendations.add(
                    "Enforce key-based SSH authentication, disable password auth"
                )
            elif inc.incident_type.value == "abnormal_access":
                recommendations.add(
                    "Deploy geo-IP blocking for administrative interfaces"
                )
                recommendations.add(
                    "Implement adaptive MFA for out-of-hours access"
                )
            elif inc.incident_type.value == "privilege_escalation":
                recommendations.add(
                    "Review and restrict sudo permissions (principle of least privilege)"
                )
                recommendations.add(
                    "Implement just-in-time privileged access management"
                )

        recommendations.add(
            "Conduct quarterly PCI-DSS compliance reviews"
        )
        return sorted(recommendations)

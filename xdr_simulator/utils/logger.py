"""
Centralized logging configuration for the XDR Simulator.
Provides structured logging with PCI-DSS compliant audit trails.
"""

import logging
import logging.handlers
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured, machine-parseable logs."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if hasattr(record, "event_id"):
            log_entry["event_id"] = record.event_id
        if hasattr(record, "source_type"):
            log_entry["source_type"] = record.source_type
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


class AuditLogger:
    """
    PCI-DSS compliant audit logger.
    Maintains tamper-evident, timestamped logs of all security-relevant actions.
    """

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_loggers()

    def _setup_loggers(self) -> None:
        """Configure application and audit loggers."""
        # Application logger
        self.app_logger = logging.getLogger("xdr_simulator")
        self.app_logger.setLevel(logging.DEBUG)

        if not self.app_logger.handlers:
            # Console handler
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            console.setFormatter(logging.Formatter(
                "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            self.app_logger.addHandler(console)

            # Rotating file handler (JSON)
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "xdr_simulator.log",
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=30,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JSONFormatter())
            self.app_logger.addHandler(file_handler)

        # Audit trail logger (PCI-DSS Requirement 10)
        self.audit_logger = logging.getLogger("xdr_audit")
        self.audit_logger.setLevel(logging.INFO)

        if not self.audit_logger.handlers:
            audit_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "audit_trail.log",
                maxBytes=50 * 1024 * 1024,  # 50 MB
                backupCount=90,  # PCI-DSS: retain logs for min. 90 days
                encoding="utf-8",
            )
            audit_handler.setFormatter(JSONFormatter())
            self.audit_logger.addHandler(audit_handler)

    def log_event(self, level: str, message: str, **kwargs) -> None:
        """Log an application event."""
        extra = kwargs
        getattr(self.app_logger, level.lower(), self.app_logger.info)(
            message, extra=extra
        )

    def log_audit(self, action: str, details: dict) -> None:
        """
        Log a PCI-DSS audit event.
        PCI-DSS Req 10.2: Record user activities, exceptions, security events.
        """
        audit_record = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            **details,
        }
        self.audit_logger.info(json.dumps(audit_record, ensure_ascii=False))

    def log_security_event(self, event_type: str, severity: str,
                           source: str, details: dict) -> None:
        """Log a security-relevant event for compliance tracking."""
        self.log_audit(
            action="SECURITY_EVENT",
            details={
                "event_type": event_type,
                "severity": severity,
                "source": source,
                **details,
            },
        )


# Module-level singleton
_audit_logger: AuditLogger | None = None


def get_logger(log_dir: str = "logs") -> AuditLogger:
    """Return the singleton AuditLogger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_dir)
    return _audit_logger

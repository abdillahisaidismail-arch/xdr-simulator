"""
Syslog event generator.
Simulates realistic syslog messages from Linux/Unix servers in a banking SI,
including SSH authentication, sudo operations, PAM events, and system logs.
"""

import random
from datetime import datetime, timezone, timedelta

from ..utils.models import SourceType


class SyslogGenerator:
    """Generate realistic syslog events for a banking infrastructure."""

    # Realistic banking infrastructure hosts
    HOSTNAMES = [
        "srv-core-banking-01", "srv-core-banking-02",
        "srv-db-oracle-01", "srv-db-oracle-02",
        "srv-swift-gw-01", "srv-web-portal-01",
        "srv-backup-01", "srv-monitoring-01",
        "fw-perimeter-01", "fw-internal-01",
        "srv-ldap-01", "srv-dns-01",
        "srv-mail-01", "srv-proxy-01",
        "srv-atm-controller-01", "srv-batch-processing-01",
    ]

    # Realistic usernames
    LEGITIMATE_USERS = [
        "admin_bcd", "dba_oracle", "svc_swift", "svc_backup",
        "op_monitoring", "admin_network", "svc_batch",
        "analyst_risk", "admin_security", "svc_web",
    ]

    SUSPICIOUS_USERS = [
        "root", "test", "admin", "guest", "user1",
        "postgres", "oracle", "ftp", "nobody",
    ]

    # Source IPs
    INTERNAL_IPS = [
        "10.10.1.{}".format(i) for i in range(10, 60)
    ] + [
        "10.10.2.{}".format(i) for i in range(10, 40)
    ]

    EXTERNAL_IPS = [
        "185.220.101.{}".format(random.randint(1, 254)),
        "45.33.32.{}".format(random.randint(1, 254)),
        "198.51.100.{}".format(random.randint(1, 254)),
        "203.0.113.{}".format(random.randint(1, 254)),
        "91.189.88.{}".format(random.randint(1, 254)),
        "176.58.100.{}".format(random.randint(1, 254)),
        "23.129.64.{}".format(random.randint(1, 254)),
        "162.247.74.{}".format(random.randint(1, 254)),
    ]

    FACILITIES = {
        "auth": 4,
        "authpriv": 10,
        "daemon": 3,
        "kern": 0,
        "local0": 16,  # Custom banking app
        "local1": 17,  # SWIFT gateway
    }

    SEVERITIES = {
        "emerg": 0, "alert": 1, "crit": 2, "err": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7,
    }

    def __init__(self, attack_probability: float = 0.15):
        self.attack_probability = attack_probability
        self.source_type = SourceType.SYSLOG

    def generate_event(self, timestamp: datetime | None = None) -> dict:
        """Generate a single syslog event."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        if random.random() < self.attack_probability:
            return self._generate_attack_event(timestamp)
        return self._generate_normal_event(timestamp)

    def _generate_normal_event(self, timestamp: datetime) -> dict:
        """Generate a normal operational syslog message."""
        event_type = random.choices(
            ["ssh_success", "sudo_success", "pam_session", "service_event",
             "cron_job", "system_event"],
            weights=[15, 10, 20, 25, 15, 15],
            k=1,
        )[0]

        hostname = random.choice(self.HOSTNAMES)
        user = random.choice(self.LEGITIMATE_USERS)
        src_ip = random.choice(self.INTERNAL_IPS)

        generators = {
            "ssh_success": self._ssh_success,
            "sudo_success": self._sudo_success,
            "pam_session": self._pam_session,
            "service_event": self._service_event,
            "cron_job": self._cron_job,
            "system_event": self._system_event,
        }

        message, facility, severity = generators[event_type](
            hostname, user, src_ip
        )

        return self._format_syslog(
            timestamp, hostname, facility, severity, message
        )

    def _generate_attack_event(self, timestamp: datetime) -> dict:
        """Generate an attack-related syslog event."""
        attack_type = random.choices(
            ["ssh_brute_force", "privilege_escalation", "abnormal_access"],
            weights=[50, 25, 25],
            k=1,
        )[0]

        hostname = random.choice(self.HOSTNAMES)

        if attack_type == "ssh_brute_force":
            return self._ssh_brute_force_event(timestamp, hostname)
        elif attack_type == "privilege_escalation":
            return self._privilege_escalation_event(timestamp, hostname)
        else:
            return self._abnormal_access_event(timestamp, hostname)

    def _ssh_success(self, hostname: str, user: str, src_ip: str) -> tuple:
        port = random.randint(40000, 65535)
        msg = (
            f"sshd[{random.randint(1000,9999)}]: "
            f"Accepted publickey for {user} from {src_ip} "
            f"port {port} ssh2: RSA SHA256:{''.join(random.choices('abcdef0123456789', k=43))}"
        )
        return msg, "authpriv", "info"

    def _sudo_success(self, hostname: str, user: str, src_ip: str) -> tuple:
        commands = [
            "/usr/bin/systemctl status oracle-db",
            "/usr/bin/tail -f /var/log/swift/gateway.log",
            "/usr/bin/service backup-agent restart",
            "/usr/sbin/iptables -L -n",
            "/usr/bin/psql -U postgres -c 'SELECT 1'",
        ]
        msg = (
            f"sudo: {user} : TTY=pts/{random.randint(0,5)} ; "
            f"PWD=/home/{user} ; USER=root ; "
            f"COMMAND={random.choice(commands)}"
        )
        return msg, "authpriv", "notice"

    def _pam_session(self, hostname: str, user: str, src_ip: str) -> tuple:
        action = random.choice(["opened", "closed"])
        msg = (
            f"pam_unix(sshd:session): session {action} for user {user} "
            f"by (uid={random.choice([0, 1000, 1001])})"
        )
        return msg, "authpriv", "info"

    def _service_event(self, hostname: str, user: str, src_ip: str) -> tuple:
        services = [
            ("oracle-listener", "TNS Listener"),
            ("swift-gateway", "SWIFT Alliance Gateway"),
            ("backup-agent", "Veeam Backup Agent"),
            ("monitoring-agent", "Zabbix Agent"),
            ("ntp-client", "NTP Synchronization"),
        ]
        service, desc = random.choice(services)
        actions = [
            f"systemd[1]: Started {desc}.",
            f"systemd[1]: {desc}: Reloading configuration.",
            f"{service}[{random.randint(1000,5000)}]: Health check passed.",
        ]
        return random.choice(actions), "daemon", "info"

    def _cron_job(self, hostname: str, user: str, src_ip: str) -> tuple:
        jobs = [
            "/opt/banking/scripts/daily_reconciliation.sh",
            "/opt/banking/scripts/log_rotation.sh",
            "/opt/backup/incremental_backup.sh",
            "/usr/local/bin/check_certificates.sh",
        ]
        msg = (
            f"CRON[{random.randint(10000,99999)}]: "
            f"({user}) CMD ({random.choice(jobs)})"
        )
        return msg, "daemon", "info"

    def _system_event(self, hostname: str, user: str, src_ip: str) -> tuple:
        events = [
            "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC={} DST=10.10.1.1 PROTO=TCP".format(
                random.choice(self.EXTERNAL_IPS)
            ),
            f"kernel: EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro",
            f"systemd-logind[{random.randint(500,999)}]: New session created.",
            "kernel: TCP: out of memory -- consider tuning tcp_mem",
        ]
        return random.choice(events), "kern", "warning"

    def _ssh_brute_force_event(self, timestamp: datetime,
                               hostname: str) -> dict:
        """Generate SSH brute-force attack event."""
        attacker_ip = random.choice(self.EXTERNAL_IPS)
        user = random.choice(self.SUSPICIOUS_USERS)
        port = random.randint(40000, 65535)

        templates = [
            f"sshd[{random.randint(1000,9999)}]: Failed password for {user} from {attacker_ip} port {port} ssh2",
            f"sshd[{random.randint(1000,9999)}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2",
            f"sshd[{random.randint(1000,9999)}]: Connection closed by authenticating user {user} {attacker_ip} port {port} [preauth]",
            f"sshd[{random.randint(1000,9999)}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={attacker_ip} user={user}",
        ]

        return self._format_syslog(
            timestamp, hostname, "authpriv", "warning",
            random.choice(templates)
        )

    def _privilege_escalation_event(self, timestamp: datetime,
                                    hostname: str) -> dict:
        """Generate privilege escalation event."""
        user = random.choice(self.SUSPICIOUS_USERS)
        dangerous_commands = [
            "/bin/bash",
            "/usr/bin/passwd root",
            "/usr/sbin/useradd backdoor",
            "/usr/sbin/visudo",
            "/bin/chmod 4755 /tmp/.hidden",
            "/usr/bin/chattr -i /etc/shadow",
            "/usr/bin/pkexec /bin/sh",
        ]

        templates = [
            (
                f"sudo: {user} : command not allowed ; "
                f"TTY=pts/{random.randint(0,5)} ; PWD=/tmp ; USER=root ; "
                f"COMMAND={random.choice(dangerous_commands)}"
            ),
            (
                f"sudo: pam_unix(sudo:auth): authentication failure; "
                f"logname={user} uid=1000 euid=0 tty=/dev/pts/{random.randint(0,5)} "
                f"ruser={user} rhost= user=root"
            ),
            (
                f"su[{random.randint(1000,9999)}]: FAILED SU (to root) {user} on pts/{random.randint(0,5)}"
            ),
        ]

        return self._format_syslog(
            timestamp, hostname, "authpriv", "alert",
            random.choice(templates)
        )

    def _abnormal_access_event(self, timestamp: datetime,
                               hostname: str) -> dict:
        """Generate abnormal access pattern event."""
        user = random.choice(self.LEGITIMATE_USERS)
        src_ip = random.choice(self.EXTERNAL_IPS)

        sensitive_targets = [
            "/etc/shadow", "/etc/passwd", "/opt/banking/config/db.conf",
            "/opt/swift/keys/private.pem", "/var/lib/oracle/wallet/",
            "/opt/banking/data/customers.db",
        ]

        templates = [
            (
                f"sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {src_ip} "
                f"port {random.randint(40000,65535)} ssh2"
            ),
            (
                f"audit[{random.randint(1000,9999)}]: "
                f"USER_AUTH pid={random.randint(1000,9999)} uid=0 "
                f"auid=1000 msg='op=PAM:authentication acct=\"{user}\" "
                f"exe=\"/usr/sbin/sshd\" hostname={src_ip} "
                f"addr={src_ip} res=success'"
            ),
        ]

        return self._format_syslog(
            timestamp, hostname, "authpriv", "notice",
            random.choice(templates)
        )

    def _format_syslog(self, timestamp: datetime, hostname: str,
                       facility: str, severity: str,
                       message: str) -> dict:
        """Format a raw syslog event with RFC 5424 structure."""
        pri = self.FACILITIES.get(facility, 1) * 8 + self.SEVERITIES.get(severity, 6)
        formatted_ts = timestamp.strftime("%b %d %H:%M:%S")

        raw = f"<{pri}>{formatted_ts} {hostname} {message}"

        return {
            "raw": raw,
            "timestamp": timestamp.isoformat(),
            "hostname": hostname,
            "facility": facility,
            "severity": severity,
            "message": message,
            "source_type": SourceType.SYSLOG.value,
        }

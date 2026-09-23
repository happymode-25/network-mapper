"""Security helpers: target allowlist and audit logging.

The hosted demo runs without a login screen, so JWT/credential code is not
included here. Authentication can be re-enabled by restoring the auth router
and the JWT helpers from the project history.
"""

import ipaddress
import json
import logging
from datetime import datetime
from typing import Optional

from .config import get_settings
from .database import SessionLocal
from .models import AuditLog

logger = logging.getLogger("network_mapper.security")

settings = get_settings()

# RFC 5735 / RFC 6890 reserved ranges that must never be scanned.
BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("ff00::/8"),
]


def is_allowed(ip: str) -> bool:
    """Return True when the IP is on the allowlist and not blocklisted.

    Blocked ranges are always rejected, even if they appear on the allowlist.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for net in BLOCKED_RANGES:
        if addr in net:
            logger.warning("Target %s is on the blocklist", ip)
            return False

    for net in settings.allowed_networks:
        if addr in net:
            return True
    return False


def log_audit(
    username: str,
    action: str,
    target: Optional[str] = None,
    status: str = "ok",
    details: Optional[str] = None,
) -> None:
    """Persist an audit trail entry to the database and a JSONL log file."""
    db = SessionLocal()
    try:
        db.add(
            AuditLog(
                username=username,
                action=action,
                target=target,
                status=status,
                details=details,
            )
        )
        db.commit()
    except Exception:  # pragma: no cover - logging must never break requests
        db.rollback()
        logger.exception("Failed to record audit log entry")
    finally:
        db.close()

    try:
        with open(settings.AUDIT_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "username": username,
                        "action": action,
                        "target": target,
                        "status": status,
                        "details": details,
                        "ts": datetime.utcnow().isoformat(),
                    }
                )
                + "\n"
            )
    except OSError:  # pragma: no cover
        logger.warning("Could not write audit log file %s", settings.AUDIT_LOG_FILE)
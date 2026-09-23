"""Application settings.

All configuration is read from environment variables (optionally loaded from a
``.env`` file via ``pydantic-settings``). See ``.env.example`` for the full
list of supported variables.
"""

import ipaddress
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Database / queue
    DATABASE_URL: str = (
        "postgresql+psycopg://network_mapper:network_mapper@localhost:5432/network_mapper"
    )
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # Scanning
    ALLOWED_TARGETS: str = "127.0.0.1, 10.0.0.0/8, 192.168.0.0/16"
    SCAN_CONCURRENCY: int = 50
    SCAN_PORT_TIMEOUT: float = 1.0
    MAX_PORTS_PER_SCAN: int = 4096
    RATE_LIMIT_SCANS_PER_MINUTE: int = 5
    AUDIT_LOG_FILE: str = "audit.log"

    # Active fingerprinting
    # Built-in TLS/HTTP probes for bannerless services (always available).
    FINGERPRINT_PROBE: bool = True
    FINGERPRINT_TIMEOUT: float = 3.0
    # Optional Nmap -sV integration (only used when the binary is found).
    USE_NMAP: bool = False
    NMAP_BINARY: str = "nmap"
    NMAP_TIMEOUT: float = 180.0

    # Vulnerability intelligence
    NVD_API_KEY: Optional[str] = None
    USE_SAMPLE_CVES: bool = True

    # When true (and no Redis is available), Celery tasks run inline so the
    # whole stack can start without a broker — handy for local/demo runs.
    CELERY_TASK_ALWAYS_EAGER: bool = False
    INLINE_SCANS: bool = False

    # Frontend
    VITE_API_URL: str = "/api"

    @property
    def allowed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse the comma-separated target allowlist into IP networks."""
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for item in self.ALLOWED_TARGETS.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                # Ignore malformed entries; fail loudly at validation time.
                continue
        return networks


@lru_cache
def get_settings() -> Settings:
    return Settings()
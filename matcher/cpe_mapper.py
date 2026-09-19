"""Product name -> CPE 2.3 mapping.

The CPE mapping is the core intelligence of the correlation engine: scanners
report a free-form product name and version, and we must turn that into a
structured ``cpe:2.3:a:vendor:product:version:...`` string usable for NVD
queries and version-aware matching.

The built-in table covers common products. Unknown products fall back to a
best-effort constructed CPE that can be used for keyword searches.
"""

import re
from typing import Optional

from scanner.version_normalizer import normalize_version

# normalized product key -> (vendor, cpe product slug)
_CPE_TABLE = {
    "openssh": ("openbsd", "openssh"),
    "apache_httpd": ("apache", "apache_httpd"),
    "nginx": ("nginx", "nginx"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "sendmail": ("sendmail", "sendmail"),
    "php": ("php", "php"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "microsoft_iis": ("microsoft", "internet_information_server"),
    "microsoft_httpapi": ("microsoft", "httpapi"),
    "openssl": ("openssl", "openssl"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "openssh_portable": ("openbsd", "openssh"),
}


def _cpe_slug(product: str) -> str:
    return re.sub(r"[^a-z0-9_.-]", "_", product.lower())


def map_to_cpe(product: Optional[str], version: Optional[str] = None) -> Optional[str]:
    """Construct a CPE 2.3 URI string for ``product``/``version``.

    Returns ``None`` when no usable product is available (callers can then fall
    back to a keyword search against NVD).
    """
    if not product:
        return None
    key = product.lower().strip()
    vendor, slug = _CPE_TABLE.get(key, (None, _cpe_slug(key)))
    if vendor is None and key.startswith("apache"):
        vendor, slug = "apache", key
    if vendor is None and "openssh" in key:
        vendor = "openbsd"
    if vendor is None:
        vendor = slug
    version_part = normalize_version(version) if version else "*"
    return (
        f"cpe:2.3:a:{vendor}:{slug}:{version_part}:"
        "*:*:*:*:*:*:*"
    )


def cpe_prefix(cpe: Optional[str]) -> Optional[str]:
    """Return the key part ``cpe:2.3:a:vendor:product`` of a CPE string.

    Used to compare a service CPE against a CVE's affected product CPE while
    ignoring the version component.
    """
    if not cpe:
        return None
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    return ":".join(parts[:5])


def cpes_match(service_cpe: Optional[str], cve_cpe: Optional[str]) -> bool:
    """Return True when the two CPEs refer to the same product (ignore version)."""
    a = cpe_prefix(service_cpe)
    b = cpe_prefix(cve_cpe)
    if not a or not b:
        return False
    return a == b
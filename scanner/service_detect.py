"""Banner-based service identification.

Parses common protocol banners (SSH, HTTP, FTP, SMTP) and normalizes product
names to stable keys used by the CPE mapper. Falls back to a port-based guess
when no banner is available.
"""

import re
from typing import Optional

from .version_normalizer import normalize_version

SSH_BANNER_RE = re.compile(r"SSH-([0-9.]+)-([^\s\r\n]+)", re.IGNORECASE)
SERVER_HEADER_RE = re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE)
POWERED_BY_RE = re.compile(r"X-Powered-By:\s*([^\r\n]+)", re.IGNORECASE)
CRLF_RE = re.compile(r"[\r\n]+")

# Maps known product names (as parsed from banners) to normalized product keys.
_PRODUCT_ALIASES = {
    "openssh": "openssh",
    "apache": "apache_httpd",
    "apache/2": "apache_httpd",
    "nginx": "nginx",
    "iis": "microsoft_iis",
    "microsoft-iis": "microsoft_iis",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "postfix": "postfix",
    "exim": "exim",
    "sendmail": "sendmail",
    "php": "php",
    "lighttpd": "lighttpd",
    "caddy": "caddy",
    "microsoft_httpapi": "microsoft_httpapi",
}

# Best-guess service name for known, bannerless ports.
_PORT_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http",
    8443: "https",
    27017: "mongodb",
}


def normalize_product(raw: Optional[str]) -> Optional[str]:
    """Map a raw product string to a normalized product key (lowercase)."""
    if not raw:
        return None
    key = raw.strip().lower().strip("*")
    key = re.sub(r"[/\s_]+", "_", key)
    key = re.sub(r"[/ *]+", "/", key)
    return _PRODUCT_ALIASES.get(key, key)


def _split_banner_value(header: str, raw: str) -> tuple[Optional[str], Optional[str]]:
    """Split a header like ``nginx/1.18.0`` into (product, version)."""
    header = header.strip().strip('"')
    tokens = re.split(r"[/\s]+", header, maxsplit=1)
    product = tokens[0] if tokens else None
    version = tokens[1] if len(tokens) > 1 else None
    if version:
        version = re.split(r"\s+", version)[0]
        version = re.sub(r"[\(\)]", "", version)
    return normalize_product(product), normalize_version(version) if version else None


def _parse_ssh(banner: str) -> dict:
    match = SSH_BANNER_RE.search(banner)
    if not match:
        return {"name": "ssh", "product": None, "version": None, "banner": banner}
    ident = match.group(2)
    product = normalize_product(ident.split("_")[0])
    raw_version = ident.split("_", 1)[1] if "_" in ident else ident
    return {
        "name": "ssh",
        "product": product,
        "version": normalize_version(raw_version),
        "banner": banner,
    }


def _parse_http(banner: str) -> dict:
    server = SERVER_HEADER_RE.search(banner)
    if server:
        product, version = _split_banner_value(server.group(1), banner)
        return {"name": "http", "product": product, "version": version, "banner": banner}
    powered = POWERED_BY_RE.search(banner)
    if powered:
        product, version = _split_banner_value(powered.group(1), banner)
        if product and product not in ("php",):
            return {"name": "http", "product": "unknown", "version": None, "banner": banner}
        return {"name": "http", "product": product, "version": version, "banner": banner}
    return {"name": "http", "product": None, "version": None, "banner": banner}


def _parse_simple_220(banner: str, default_name: str) -> dict:
    """Parse a ``220 service ready`` style banner (FTP / SMTP)."""
    low = banner.lower()
    # Known mail/FTP server software appears verbatim in the banner.
    for keyword in ("postfix", "exim", "sendmail", "vsftpd", "proftpd", "pure-ftpd", "dovecot"):
        if keyword in low:
            version = None
            match = re.search(rf"{re.escape(keyword)}\s*[\-: ]\s*(\d[\w.]*)", low)
            if match:
                version = normalize_version(match.group(1))
            return {
                "name": default_name,
                "product": normalize_product(keyword),
                "version": version,
                "banner": banner,
            }

    lines = [ln.strip() for ln in CRLF_RE.split(banner) if ln.strip()]
    if not lines:
        return {"name": default_name, "product": None, "version": None, "banner": banner}
    body = lines[0][3:].strip()  # strip the leading "220"
    body = re.sub(r"^[- ]", "", body)
    tokens = body.split()
    product = None
    version = None
    if tokens:
        candidate = tokens[0].lstrip("(").rstrip("),.")
        if candidate.isdigit():
            candidate = None
        product = candidate
    for tok in tokens:
        match_tok = re.search(r"\d+(\.\d+)+[a-zA-Z0-9.\-]*", tok)
        if match_tok:
            version = normalize_version(match_tok.group(0))
            break
    return {
        "name": default_name,
        "product": normalize_product(product),
        "version": version,
        "banner": banner,
    }


def detect_service(port: int, banner: Optional[str]) -> dict:
    """Identify a service from its TCP port and banner.

    Returns ``{name, product, version, banner}`` with ``name`` being a generic
    service family (http, ssh, ftp, smtp, ...) and ``product``/``version`` the
    extracted software, normalized for the CPE mapper.
    """
    banner = (banner or "").strip()

    if port == 22 or port == 2222 or banner.lower().startswith("ssh-"):
        return _parse_ssh(banner)

    if banner.lower().startswith(("http/", "get ", "head ", "post ", "server:")):
        return _parse_http(banner)

    if banner.lower().startswith("220"):
        name = "ftp" if port in (21,) else "smtp" if port in (25, 587, 2525) else "unknown"
        return _parse_simple_220(banner, name)

    if banner:
        # Generic fallback: keep the raw banner and a port hint.
        return {
            "name": _PORT_HINTS.get(port, "unknown"),
            "product": None,
            "version": None,
            "banner": banner,
        }

    return {
        "name": _PORT_HINTS.get(port, "unknown"),
        "product": None,
        "version": None,
        "banner": None,
    }
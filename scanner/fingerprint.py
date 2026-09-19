"""Active fingerprinting of bannerless services.

Many services (HTTPS, SMB, RDP) do not send a banner, so the passive scanner
leaves them un-identified. This module enriches those ports with two
dependency-free probes:

* a minimal HTTP ``GET /`` request (optionally over TLS) whose ``Server`` /
  ``X-Powered-By`` headers identify the product and version;
* a TLS handshake exposing the remote certificate's CN / issuer and the
  negotiated TLS version (a useful hostname hint for dashboards).

Probes are bounded by timeouts and a concurrency semaphore so they never stall
a scan. When a service already has a product from a banner, it is left alone.
"""

import asyncio
import re
import ssl
from typing import Dict, List, Optional

from .service_detect import normalize_product
from .version_normalizer import normalize_version

HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 28080}
TLS_PORTS = {443, 8443}

_MAX_HTTP_BYTES = 8192
_HTTP_REQUEST = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: network-mapper/1.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
)

_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.RegexFlag.IGNORECASE | re.MULTILINE)
_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.RegexFlag.IGNORECASE | re.MULTILINE)
_POWERED_RE = re.compile(r"^X-Powered-By:\s*(.+)$", re.RegexFlag.IGNORECASE | re.MULTILINE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.RegexFlag.IGNORECASE | re.DOTALL)


def parse_server_header(header: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Split a ``Server`` header into (product, version).

    Handles ``Apache/2.4.41 (Ubuntu)``, ``nginx/1.18.0``, ``Microsoft-IIS/10.0``
    and plain ``Apache`` (no version).
    """
    if not header:
        return None, None
    value = header.strip().strip('"')
    if not value:
        return None, None
    tokens = re.split(r"/[\s]*", value, maxsplit=1)
    product = tokens[0].strip()
    version = None
    if len(tokens) > 1:
        version = re.split(r"\s+", tokens[1])[0].strip()
        version = re.sub(r"[()]", "", version) or None
    return normalize_product(product), (normalize_version(version) if version else None)


def parse_http_response(raw: str) -> Dict[str, Optional[object]]:
    """Extract status, Server/X-Powered-By headers and <title> from an HTTP reply."""
    status_match = _STATUS_RE.search(raw)
    server_match = _SERVER_RE.search(raw)
    powered_match = _POWERED_RE.search(raw)
    title_match = _TITLE_RE.search(raw)

    product, version = parse_server_header(server_match.group(1) if server_match else None)
    if not product and powered_match:
        product, version = parse_server_header(powered_match.group(1))

    return {
        "status": int(status_match.group(1)) if status_match else None,
        "server": server_match.group(1).strip() if server_match else None,
        "product": product,
        "version": version,
        "title": re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None,
    }


def _unverified_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _cert_subject(cert) -> Optional[str]:
    """Extract the CN from a pyOpenSSL-style X509 subject tuple."""
    for key, value in cert.get("subject", ()):
        if key == "commonName" and value:
            return str(value)
    return None


def _cert_cn_binary(binary_der: Optional[bytes]) -> Optional[str]:
    """Extract the CN from the raw DER certificate (verify_mode=CERT_NONE)."""
    if not binary_der:
        return None
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(binary_der)
        for attribute in certificate.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                return str(attribute.value)
    except Exception:  # pragma: no cover - cryptography missing/corrupt cert
        return None
    return None


async def probe_http(
    host: str, port: int, use_tls: bool = False, timeout: float = 3.0
) -> Optional[Dict[str, object]]:
    """Send one minimal HTTP GET and parse the response; None on failure."""
    reader = None
    writer = None
    try:
        ssl_context = _unverified_ssl_context() if use_tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout,
        )
        writer.write(_HTTP_REQUEST.format(host=host).encode("ascii"))
        data = await asyncio.wait_for(reader.read(_MAX_HTTP_BYTES), timeout=timeout)
        raw = (data or b"").decode("utf-8", errors="replace")
        info = {**parse_http_response(raw), "tls": use_tls}
        return info
    except (asyncio.TimeoutError, TimeoutError, OSError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # pragma: no cover - best effort
                pass


async def probe_tls(
    host: str, port: int, timeout: float = 3.0
) -> Optional[Dict[str, Optional[str]]]:
    """Handshake TLS and return certificate/version details; None on failure."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_unverified_ssl_context()),
            timeout=timeout,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        cert = None
        tls_version = None
        cipher = None
        if ssl_object is not None:
            try:
                cert = ssl_object.getpeercert()
            except Exception:  # pragma: no cover - transport dependent
                cert = None
            # Under verify_mode=CERT_NONE we get an empty dict (not None).
            if not cert:
                try:
                    der = ssl_object.getpeercert(binary_form=True)
                except Exception:  # pragma: no cover
                    der = None
                cn = _cert_cn_binary(der)
            else:
                cn = _cert_subject(cert)
            tls_version = ssl_object.version()
            cipher = ssl_object.cipher()
        return {
            "tls": True,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
            "cn": cn,
            "cert": cert is not None,
        }
    except (asyncio.TimeoutError, TimeoutError, OSError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # pragma: no cover - best effort
                pass


async def fingerprint_port(
    host: str, svc: Dict[str, object], timeout: float = 3.0
) -> Dict[str, object]:
    """Enrich one service dict with TLS/HTTP fingerprints when worthwhile."""
    port = int(svc.get("port", 0))
    # Already fingerprinted from a banner, or clearly not a web service.
    if svc.get("product"):
        return svc
    name = str(svc.get("name") or "unknown")
    if name not in ("unknown", "http", "https") and port not in HTTP_PORTS | TLS_PORTS:
        return svc

    enriched = dict(svc)
    use_tls = port in TLS_PORTS or name in ("https", "tls", "ssl")
    if use_tls:
        tls = await probe_tls(host, port, timeout=timeout)
        if tls:
            enriched["name"] = "https"
            if tls.get("cn"):
                enriched["tls_cn"] = tls["cn"]
            if tls.get("tls_version"):
                enriched["tls_version"] = tls["tls_version"]

    info = await probe_http(host, port, use_tls=use_tls, timeout=timeout)
    if info:
        if not use_tls and info.get("product"):
            enriched["name"] = "http"
        if info.get("product"):
            enriched["product"] = info["product"]
        if info.get("version"):
            enriched["version"] = info["version"]
        if info.get("title") and not enriched.get("banner"):
            enriched["banner"] = f"<title>{info['title']}</title>"
    return enriched


async def enrich_services(
    host: str,
    services: List[dict],
    timeout: float = 3.0,
    concurrency: int = 20,
) -> List[dict]:
    """Enrich a list of service dicts in parallel with TLS/HTTP probes."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _one(svc: dict) -> dict:
        async with semaphore:
            return await fingerprint_port(host, svc, timeout=timeout)

    return list(await asyncio.gather(*(_one(s) for s in services)))
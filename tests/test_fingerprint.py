"""Tests for built-in TLS/HTTP fingerprinting: parsers and live probes."""

import asyncio
import ssl

from scanner import fingerprint

_CANNED_HTTP = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: nginx/1.18.0 (Ubuntu)\r\n"
    "\r\n"
    "<html><head><title>Acme Portal - index</title></head><body>hi</body></html>"
)


def test_parse_server_header_nginx():
    assert fingerprint.parse_server_header("nginx/1.18.0 (Ubuntu)") == ("nginx", "1.18.0")


def test_parse_server_header_apache_no_version():
    assert fingerprint.parse_server_header("Apache")[:1] == ("apache_httpd",)


def test_parse_server_header_iis():
    assert fingerprint.parse_server_header("Microsoft-IIS/10.0") == ("microsoft_iis", "10.0")


def test_parse_server_header_empty():
    assert fingerprint.parse_server_header("") == (None, None)
    assert fingerprint.parse_server_header(None) == (None, None)


def test_parse_http_response_extracts_headers_and_title():
    info = fingerprint.parse_http_response(_CANNED_HTTP)
    assert info["status"] == 200
    assert info["server"] == "nginx/1.18.0 (Ubuntu)"
    assert info["product"] == "nginx"
    assert info["version"] == "1.18.0"
    assert info["title"] == "Acme Portal - index"


def test_fingerprint_port_skips_when_product_known():
    async def _run():
        return await fingerprint.fingerprint_port(
            "127.0.0.1", {"port": 80, "name": "http", "product": "nginx", "version": "1.2.3"}
        )

    svc = asyncio.run(_run())
    assert svc["product"] == "nginx"


def _http_handler(raw_response: bytes):
    async def handle(reader, writer):
        try:
            await reader.read(2048)
        except Exception:
            pass
        writer.write(raw_response)
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return handle


def _with_server(handler, probe, use_tls=False, certfile=None, keyfile=None):
    """Start an asyncio server and run ``probe(port)`` in the same event loop."""

    async def _run():
        kwargs = {}
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            kwargs["ssl"] = context
        server = await asyncio.start_server(handler, host="127.0.0.1", port=0, **kwargs)
        port = server.sockets[0].getsockname()[1]
        try:
            return await probe(port)
        finally:
            server.close()
            await server.wait_closed()

    return asyncio.run(_run())


def test_probe_http_live_server(tmp_path):
    async def probe(port):
        return await fingerprint.probe_http("127.0.0.1", port, timeout=5.0)

    info = _with_server(_http_handler(_CANNED_HTTP.encode("utf-8")), probe)
    assert info is not None
    assert info["status"] == 200
    assert info["product"] == "nginx"
    assert info["version"] == "1.18.0"
    assert info["tls"] is False


def test_probe_http_closed_port_returns_none(tmp_path):
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    async def probe():
        return await fingerprint.probe_http("127.0.0.1", port, timeout=1.0)

    assert asyncio.run(probe()) is None


def _make_self_signed_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime(2020, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_probe_tls_live_server(tmp_path):
    cert, key = _make_self_signed_cert(tmp_path)

    async def probe(port):
        tls = await fingerprint.probe_tls("127.0.0.1", port, timeout=5.0)
        http = await fingerprint.probe_http("127.0.0.1", port, use_tls=True, timeout=5.0)
        return tls, http

    tls, http = _with_server(
        _http_handler(b"\xff"), probe, use_tls=True, certfile=str(cert), keyfile=str(key)
    )
    assert tls is not None
    assert tls["tls"] is True
    assert tls["cn"] == "test.example"
    assert http is not None
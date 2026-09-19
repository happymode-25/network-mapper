"""Tests for banner-based service detection and version normalization."""

from scanner.service_detect import detect_service, normalize_product
from scanner.version_normalizer import (
    compare_versions,
    is_exact_match,
    normalize_version,
    version_in_range,
)


class TestServiceDetection:
    def test_ssh_banner(self):
        svc = detect_service(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        assert svc["name"] == "ssh"
        assert svc["product"] == "openssh"
        assert svc["version"] == "8.9.1"

    def test_http_server_header(self):
        svc = detect_service(
            80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n"
        )
        assert svc["name"] == "http"
        assert svc["product"] == "nginx"
        assert svc["version"] == "1.18.0"

    def test_http_apache(self):
        svc = detect_service(8080, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n")
        assert svc["product"] == "apache_httpd"
        assert svc["version"] == "2.4.41"

    def test_ftp_banner(self):
        svc = detect_service(21, "220 (vsFTPd 3.0.3)\r\n")
        assert svc["name"] == "ftp"
        assert svc["version"] == "3.0.3"

    def test_smtp_banner(self):
        svc = detect_service(25, "220 mail.example ESMTP Postfix\r\n")
        assert svc["name"] == "smtp"
        assert svc["product"] == "postfix"

    def test_generic_banner_falls_back_to_port_hint(self):
        svc = detect_service(6379, "-ERR unknown command\r\n")
        assert svc["banner"] == "-ERR unknown command"

    def test_bannerless_port_uses_hint(self):
        svc = detect_service(3306, None)
        assert svc["name"] == "mysql"

    def test_normalize_product_aliases(self):
        assert normalize_product("OpenSSH") == "openssh"
        assert normalize_product("Apache") == "apache_httpd"
        assert normalize_product("  Nginx  ") == "nginx"


class TestVersionNormalizer:
    def test_typical_versions(self):
        assert normalize_version("8.9p1") == "8.9.1"
        assert normalize_version("2.4.41") == "2.4.41"
        assert normalize_version("v12.0.3") == "12.0.3"
        assert normalize_version("1.2.3-rc1") == "1.2.3.1"

    def test_none_and_empty(self):
        assert normalize_version(None) is None
        assert normalize_version("") == ""

    def test_comparison(self):
        assert compare_versions("2.4.41", "2.4.40") > 0
        assert compare_versions("8.9.1", "8.9.1") == 0
        assert compare_versions("8.9p1", "8.9.2") < 0

    def test_range_inclusive(self):
        assert version_in_range("2.4.41", "2.4.0", "2.4.49")
        assert not version_in_range("2.4.50", "2.4.0", "2.4.49")

    def test_range_exclusive(self):
        assert version_in_range("2.4.49", None, "2.4.50", max_exclusive=True)
        assert not version_in_range("2.4.50", None, "2.4.50", max_exclusive=True)

    def test_exact_match(self):
        assert is_exact_match("2.3.4", "2.3.4")
        assert not is_exact_match("2.3.4", "2.3.5")

    def test_missing_versions_sort_low(self):
        assert compare_versions(None, "1.0") == -1
        assert compare_versions("1.0", None) == 1
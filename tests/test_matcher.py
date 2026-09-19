"""Tests for the CPE mapper, matcher and risk scoring engine."""

import pytest

from matcher import matcher
from matcher.cpe_mapper import cpe_prefix, cpes_match, map_to_cpe


class TestCPEMapper:
    def test_known_product(self):
        cpe = map_to_cpe("openssh", "8.9p1")
        assert cpe.startswith("cpe:2.3:a:openbsd:openssh:8.9.1:")

    def test_apache_normalization(self):
        cpe = map_to_cpe("apache_httpd", "2.4.41")
        assert cpe.startswith("cpe:2.3:a:apache:apache_httpd:2.4.41:")

    def test_unknown_product_constructs_best_effort(self):
        cpe = map_to_cpe("custom_server", "1.0")
        assert cpe.startswith("cpe:2.3:a:custom_server:custom_server:1.0:")

    def test_none_product_returns_none(self):
        assert map_to_cpe(None) is None

    def test_prefix_compare_ignores_version(self):
        a = "cpe:2.3:a:openbsd:openssh:8.9.1:*:*:*:*:*:*:*"
        b = "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
        assert cpe_prefix(a) == cpe_prefix(b) == "cpe:2.3:a:openbsd:openssh"
        assert cpes_match(a, b)


class TestRiskScoring:
    def test_formula_no_data(self):
        assert matcher.compute_risk(None, None, False, "low") == 1.0

    def test_formula_cvss_and_epss(self):
        risk = matcher.compute_risk(8.0, 0.5, False, "low")
        assert risk == pytest.approx(4.0 + 1.5 + 1.0)

    def test_kev_bonus(self):
        without = matcher.compute_risk(5.0, 0.0, False, "low")
        with_kev = matcher.compute_risk(5.0, 0.0, True, "low")
        assert with_kev - without == pytest.approx(2.0)

    def test_importance_bumps_risk(self):
        low_risk = matcher.compute_risk(5.0, 0.0, False, "low")
        critical_risk = matcher.compute_risk(5.0, 0.0, False, "critical")
        assert critical_risk > low_risk
        assert critical_risk <= 10.0

    def test_risk_clamped_at_10(self):
        assert matcher.compute_risk(10.0, 1.0, True, "critical") == 10.0

    def test_severity_thresholds(self):
        assert matcher.severity_from_risk(0) == "none"
        assert matcher.severity_from_risk(3.5) == "low"
        assert matcher.severity_from_risk(5.0) == "medium"
        assert matcher.severity_from_risk(8.0) == "high"
        assert matcher.severity_from_risk(9.5) == "critical"


class TestMatchService:
    SERVICE = {"cpe": "cpe:2.3:a:openbsd:openssh:8.9.1:*:*:*:*:*:*:*", "product": "openssh", "version": "8.9.1"}

    def _cve(self, **kw):
        base = dict(
            cve_id="CVE-2024-0001",
            description="desc",
            cvss_v3=6.0,
            cvss_v4=None,
            cpe="cpe:2.3:a:openbsd:openssh",
        )
        base.update(kw)
        return base

    def test_exact_version_match_is_high_confidence(self):
        cves = [self._cve(min_version="2.0", max_version="8.9.1")]
        found = matcher.match_service(self.SERVICE, cves, asset_importance="low")
        assert len(found) == 1
        assert found[0]["confidence"] == "high"

    def test_range_match_is_medium_confidence(self):
        cves = [self._cve(min_version="2.0", max_version="9.0")]
        found = matcher.match_service(self.SERVICE, cves, asset_importance="low")
        assert len(found) == 1
        assert found[0]["confidence"] == "medium"

    def test_broad_match_is_low_confidence(self):
        cves = [self._cve(min_version=None, max_version=None)]
        found = matcher.match_service(self.SERVICE, cves, asset_importance="low")
        assert len(found) == 1
        assert found[0]["confidence"] == "low"

    def test_out_of_version_range_is_dropped(self):
        cves = [self._cve(min_version="2.0", max_version="2.0")]
        found = matcher.match_service(self.SERVICE, cves, asset_importance="low")
        assert found == []

    def test_unrelated_product_is_dropped(self):
        nginx = {
            "cpe": "cpe:2.3:a:nginx:nginx:*", "product": "nginx", "version": "1.18.0"
        }
        cves = [self._cve()]
        assert matcher.match_service(nginx, cves) == []

    def test_kev_and_epss_baked_into_risk(self):
        cves = [self._cve(min_version="2.0", max_version="9.0", kev=True, epss=1.0)]
        found = matcher.match_service(
            self.SERVICE, cves, use_kev=True, use_epss=True, asset_importance="low"
        )
        assert found[0]["kev"] is True
        assert found[0]["epss_score"] == 1.0
        # cvss 6.0*0.5 + epss 1.0*3 + kev 2 + importance 1 = 9.0 -> critical
        assert found[0]["risk_score"] == 9.0
        assert found[0]["severity"] == "critical"

    def test_kev_epss_disabled_are_zeroed(self):
        cves = [self._cve(min_version="2.0", max_version="9.0", kev=True, epss=1.0)]
        found = matcher.match_service(
            self.SERVICE, cves, use_kev=False, use_epss=False, asset_importance="low"
        )
        assert found[0]["kev"] is False
        assert found[0]["epss_score"] is None

    def test_sample_cves_load(self):
        data = matcher.load_sample_cves()
        assert len(data) >= 15
        assert all("cve_id" in c and "cpe" in c for c in data)

    def test_sample_matching_end_to_end(self):
        sample = matcher.cves_for_sample("openssh")
        service = {"cpe": "cpe:2.3:a:openbsd:openssh:8.9.1:*:*:*:*:*:*:*", "product": "openssh", "version": "8.9.1"}
        found = matcher.match_service(service, sample, use_kev=True, use_epss=True, asset_importance="low")
        ids = {f["cve_id"] for f in found}
        assert "CVE-2024-6387" in ids
        assert all(f["confidence"] in ("high", "medium", "low") for f in found)
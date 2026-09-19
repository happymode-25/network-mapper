"""Tests for the NVD / KEV / EPSS intelligence clients and NVD parsing."""

import httpx
import pytest
import respx

from matcher.epss_client import EPSSClient
from matcher.kev_client import KEVClient
from matcher.nvd_client import NVDClient, parse_nvd_cve


RAW_NVD_ITEM = {
    "cve": {
        "id": "CVE-2024-6387",
        "descriptions": [{"lang": "en", "value": "regreSSHion RCE in sshd"}],
        "published": "2024-07-01T00:00:00Z",
        "lastModified": "2024-07-25T00:00:00Z",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.1,
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpe_match": [
                            {
                                "criteria": "cpe:2.3:a:openbsd:openssh:8.5p1:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.5p1",
                            },
                            {
                                "criteria": "cpe:2.3:a:openbsd:openssh:8.6p1:*:*:*:*:*:*:*",
                                "versionEndExcluding": "9.8p1",
                            },
                        ]
                    }
                ]
            }
        ],
        "weaknesses": [{"description": [{"value": "CWE-364"}]}],
    }
}


def test_parse_nvd_cve_normalizes_fields():
    parsed = parse_nvd_cve(RAW_NVD_ITEM)
    assert parsed["cve_id"] == "CVE-2024-6387"
    assert parsed["description"] == "regreSSHion RCE in sshd"
    assert parsed["cvss_v3"] == 8.1
    assert parsed["severity"] == "HIGH"
    assert parsed["cpe"] == "cpe:2.3:a:openbsd:openssh"
    # Second match's versionEndExcluding should win over the first match.
    assert parsed["max_version"] == "9.8p1"
    assert parsed["max_exclusive"] is True
    assert parsed["min_version"] == "8.5p1"
    assert parsed["remediation"]


@respx.mock
async def test_nvd_client_get_cves_by_cpe():
    respx.get(NVDClient.BASE_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [RAW_NVD_ITEM]})
    )
    client = NVDClient(api_key=None)
    try:
        results = await client.get_cves_by_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
    finally:
        await client.aclose()
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-6387"


@respx.mock
async def test_nvd_client_get_cve_returns_none_on_404():
    respx.get(NVDClient.BASE_URL).mock(return_value=httpx.Response(404))
    client = NVDClient(api_key=None)
    try:
        result = await client.get_cve("CVE-2024-9999")
    finally:
        await client.aclose()
    assert result is None


@respx.mock
async def test_kev_client_lookup():
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-6387", "knownRansomwareCampaignUse": "Known"}
        ]
    }
    respx.get(KEVClient.KEV_URL).mock(return_value=httpx.Response(200, json=payload))
    client = KEVClient(ttl=0)  # short TTL forces a refresh
    try:
        assert await client.is_kev("CVE-2024-6387") is True
        assert await client.is_kev("CVE-2023-0000") is False
    finally:
        await client.aclose()


@respx.mock
async def test_kev_client_caches_after_first_fetch(monkeypatch):
    payload = {"vulnerabilities": [{"cveID": "CVE-2024-6387"}]}
    route = respx.get(KEVClient.KEV_URL).mock(
        return_value=httpx.Response(200, json=payload)
    )
    client = KEVClient(ttl=3600)
    try:
        await client.is_kev("CVE-2024-6387")
        await client.is_kev("CVE-2024-6387")
    finally:
        await client.aclose()
    # TTL still valid -> only one network hit.
    assert len(route.calls) == 1


@respx.mock
async def test_epss_client_batch_scores():
    respx.get(EPSSClient.EPSS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"cve": "CVE-2024-6387", "epss": "0.9751", "percentile": "0.98210"}
                ]
            },
        )
    )
    client = EPSSClient()
    try:
        scores = await client.get_scores(["CVE-2024-6387", "CVE-2024-6387"])
    finally:
        await client.aclose()
    assert scores["CVE-2024-6387"]["score"] == pytest.approx(0.9751)
    # Duplicates are collapsed respecting the API's 50-per-batch limit.
    assert len(respx.calls) == 1


async def test_epss_client_empty_list():
    client = EPSSClient()
    try:
        assert await client.get_scores([]) == {}
    finally:
        await client.aclose()



@respx.mock
async def test_nvd_client_search_by_product():
    respx.get(NVDClient.BASE_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [RAW_NVD_ITEM]})
    )
    client = NVDClient(api_key=None)
    try:
        results = await client.search_by_product("openssh")
    finally:
        await client.aclose()
    assert results[0]["cve_id"] == "CVE-2024-6387"
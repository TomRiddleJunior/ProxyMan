"""Tests for feature A (targeted validation) and feature B (ASN classification)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator.asn import classify_hosting, ASNClassifier
from src.validator.core import ProxyInfo, ProxyValidator
from src.storer import ProxyStorer


# ---------------------------------------------------------------------------
# Feature B: hosting classification
# ---------------------------------------------------------------------------

class TestClassifyHosting:
    def test_datacenter_aliyun(self):
        assert classify_hosting("Alibaba (US) Technology Co., Ltd.", "", "AS45102 Alibaba (US)") == "datacenter"

    def test_datacenter_tencent(self):
        assert classify_hosting("Tencent cloud computing", "", "AS45090 Shenzhen Tencent") == "datacenter"

    def test_datacenter_ovh(self):
        assert classify_hosting("OVH SAS", "OVH SAS", "AS16276 OVH SAS") == "datacenter"

    def test_datacenter_digitalocean(self):
        assert classify_hosting("DigitalOcean, LLC", "", "AS14061 DigitalOcean") == "datacenter"

    def test_residential_isp(self):
        # Telecom/Ltd words must NOT trigger datacenter for real ISPs
        assert classify_hosting("MTNL Delhi Telecom", "", "AS17813 BSNL Telecom") == "residential"

    def test_residential_mobile(self):
        assert classify_hosting("Jio Airtel Broadband", "Reliance Jio Infocomm", "AS55836 Reliance Jio") == "residential"

    def test_unknown(self):
        assert classify_hosting("", "", "") == "unknown"


class TestASNClassifier:
    def test_disabled_returns_empty(self):
        c = ASNClassifier(enabled=False)
        assert c.classify_ips(["8.8.8.8"]) == {}

    def test_bad_ips_filtered(self):
        c = ASNClassifier(enabled=True)
        # no network I/O should happen for invalid IPs
        assert c.classify_ips(["not-an-ip", "999.999.1.1"]) == {}


# ---------------------------------------------------------------------------
# Feature A: targeted lists + snapshot quality meta
# ---------------------------------------------------------------------------

class TestTargetedAndQualityMeta:
    def _make_proxy(self, addr, latency=0.2, protocol="socks5", target_ok=False, target_latency=0.0):
        ip, port = addr.split(":")
        return ProxyInfo(
            address=addr, protocol=protocol, anonymity="elite", latency=latency,
            ssl_supported=True, country_code="IN", country_name="India",
            verified_exit=True, target_ok=target_ok, target_latency=target_latency,
            hosting="residential", as_name="AS1 X", org="X Network",
        )

    def test_target_list_written(self, tmp_path):
        proxies = [
            self._make_proxy("1.1.1.1:80", target_ok=True, target_latency=0.15),
            self._make_proxy("2.2.2.2:80", target_ok=False),
            self._make_proxy("3.3.3.3:80", target_ok=True, target_latency=0.10),
        ]
        storer = ProxyStorer(str(tmp_path), ["txt", "json"], snapshot_state_file=str(tmp_path / "snap.json"))
        storer.save_proxies(proxies, target="example")

        target_file = tmp_path / "targets" / "example.txt"
        assert target_file.exists()
        content = target_file.read_text().strip().splitlines()
        assert content == ["3.3.3.3:80", "1.1.1.1:80"]  # sorted by target latency

        # hosting splits
        res = (tmp_path / "hosting" / "residential.txt").read_text().strip().splitlines()
        assert res == ["1.1.1.1:80", "2.2.2.2:80", "3.3.3.3:80"]

    def test_survival_rate_meta(self, tmp_path):
        storer = ProxyStorer(str(tmp_path), ["txt", "json"], snapshot_state_file=str(tmp_path / "snap.json"))
        first = [self._make_proxy("1.1.1.1:80"), self._make_proxy("2.2.2.2:80")]
        storer.save_proxies(first)
        second = [self._make_proxy("1.1.1.1:80"), self._make_proxy("9.9.9.9:80")]
        storer.save_proxies(second)

        meta = json.loads((tmp_path / "meta.json").read_text())
        assert meta["quality"]["previous_snapshot_total"] == 2
        assert meta["quality"]["survival_rate"] == 0.5
        assert meta["quality"]["churn_rate"] == 0.5
        assert meta["counts"]["residential"] == 2
        assert meta["schema"] == 3
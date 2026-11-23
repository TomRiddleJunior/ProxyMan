"""
Feature B: ASN / hosting-kind classification via free ip-api.com batch lookups.

Every validated proxy gets tagged as:
  - "residential" : ISP / mobile / non-datacenter network (gold for scraping)
  - "datacenter"  : cloud / VPS / hosting ranges (blocked by most targets)
  - "unknown"     : lookup failed or org is unclassifiable

Design constraints:
  - ip-api.com free batch endpoint: max 100 IPs/request, ~15 req/min.
    We chunk, and sleep between batches to stay inside the rate budget.
  - Lookups run ONLY on proxies that already passed validation (small set).
  - Results are persisted in pool state so checker runs reuse them without
    burning API quota (see main.py).
"""

import re
import time
import json
import logging
import urllib.request
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

BATCH_API = "http://ip-api.com/batch"
MAX_BATCH = 100
RATE_LIMIT_RPM = 15

# Substrings that mark a network as datacenter/hosting space. Curated to
# actual hosting/cloud operators only — NOT generic words ("telecom", "ltd",
# "isp") that residential providers also carry. When in doubt -> residential.
DC_KEYWORDS = [
    # global cloud / VPS / CDN
    "amazon", "aws", "azure", "microsoft corporation", "microsoft azure",
    "google llc", "google cloud", "digitalocean", "ovh",
    "hetzner", "linode", "akamai", "cloudflare", "oracle", "ibm", "vultr",
    "contabo", "leaseweb", "scaleway", "racknerd", "hostwinds", "choopa",
    "m247", "multacom", "cogent", "equinix", "hochi", "kinx", "kdatacenter",
    "colocrossing", "quadranet", "psychz", "frantech", "hostkey",
    "worldstream", "fiberhub", "serverius", "dacentec", "iomart",
    "namecheap", "godaddy", "bluehost", "hostgator", "dreamhost", "ionos",
    "hostinger", "a2hosting", "snel", "versio", "transip", "netsons",
    "aruba", "belcloud", "hostserver", "speedbone", "datacamp", "dataidea",
    "cronos srl", "latisys", "singlehop", "xfinity hosted", "unity media",
    # generic hosting-space descriptors (safe: rarely part of residential ISP names)
    "datacenter", "data center", "colo",
    # Asian/Chinese cloud & IDC operators (heavy lifters in free proxy lists)
    "alibaba", "aliyun", "tencent", "chinatelecom", "china unicom",
    "china mobile", "cncgroup", "drpeng", "21vianet", "greencloud",
    "dnspod", "xrea", "sakura internet", "conoha", "gmo internet",
    "kddi web communications", "narixiaofei", "idc",
    # hosting-centric regional players
    "apnic", "turkcell superonline", "isik university",
]

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def classify_hosting(org: str, isp: str, as_name: str) -> str:
    """Returns 'residential' | 'datacenter' | 'unknown' from ASN fields."""
    haystack = " ".join(str(x) for x in (org, isp, as_name)).lower()
    for kw in DC_KEYWORDS:
        if kw in haystack:
            return "datacenter"
    if any(x for x in (org, isp, as_name)):
        return "residential"
    return "unknown"


class ASNClassifier:
    """
    Batch ASN/org lookup with free ip-api.com endpoint.

    Usage:
        classifier = ASNClassifier(enabled=True)
        info = classifier.classify_ips(["1.2.3.4", "5.6.7.8"])
        # -> {"1.2.3.4": {"hosting": "datacenter", "as_name": "AS45102 ...", "org": "..."}}
    """

    def __init__(self, enabled: bool = True, batch_api: str = BATCH_API,
                 rate_limit_rpm: int = RATE_LIMIT_RPM):
        self.enabled = enabled
        self.batch_api = batch_api
        self.rate_limit_rpm = max(1, rate_limit_rpm)

    def classify_ips(self, ips: List[str]) -> Dict[str, dict]:
        """Batch-classify a list of unique public IPs."""
        out: Dict[str, dict] = {}
        if not self.enabled or not ips:
            return out
        unique = [ip for ip in dict.fromkeys(ips) if IP_PATTERN.match(ip)]

        for start in range(0, len(unique), MAX_BATCH):
            chunk = unique[start:start + MAX_BATCH]
            try:
                req = urllib.request.Request(
                    self.batch_api,
                    data=json.dumps(chunk).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=20) as r:
                    results = json.loads(r.read().decode("utf-8", "ignore"))
                for row in results:
                    if not isinstance(row, dict) or row.get("status") != "success":
                        continue
                    ip = row.get("query", "")
                    org = str(row.get("org", "") or "")
                    isp = str(row.get("isp", "") or "")
                    as_name = str(row.get("as", "") or "")
                    out[ip] = {
                        "hosting": classify_hosting(org, isp, as_name),
                        "as_name": as_name,
                        "org": org or isp,
                    }
            except Exception as e:
                logger.warning("[ASN] batch lookup failed: %s", e)
            if start + MAX_BATCH < len(unique):
                time.sleep(60.0 / self.rate_limit_rpm)
        logger.info("[ASN] classified %d / %d unique IPs", len(out), len(unique))
        return out
import re
import base64
import httpx
import asyncio
import datetime
import logging
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from src.config import EngineConfig

logger = logging.getLogger(__name__)

# HTTP statuses treated as transient (retryable) failures
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
MAX_RETRY_DELAY = 12.0


def _emit(results: Set[str], provenance: Optional[Dict[str, str]], address: str, label: str) -> None:
    """Adds a candidate and records its origin (first source wins on dedup)."""
    results.add(address)
    if provenance is not None:
        provenance.setdefault(address, label)


def valid_candidates(found: Set[str]) -> Set[str]:
    """Drops candidates with out-of-range ports (e.g. 99999) immediately."""
    out = set()
    for c in found:
        try:
            port = int(c.rsplit(":", 1)[1])
        except ValueError:
            continue
        if 1 <= port <= 65535:
            out.add(c)
    return out


async def get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 3,
    base_delay: float = 1.5,
    **kwargs,
) -> httpx.Response:
    """
    GET with exponential backoff for transient failures (429/5xx/network
    errors). Returns the last response when retries are exhausted on status
    codes, or raises the last transport error so callers can handle it.
    """
    last_response = None
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            resp = await client.get(url, **kwargs)
            if resp.status_code not in RETRY_STATUS_CODES:
                return resp
            last_response = resp
            logger.warning("[Retry] GET %s -> HTTP %d (attempt %d/%d).",
                           url, resp.status_code, attempt, retries)
        except Exception as e:
            last_error = e
            logger.debug("[Retry] GET %s failed: %s (attempt %d/%d).", url, e, attempt, retries)
        if attempt < retries:
            await asyncio.sleep(min(base_delay * (2 ** (attempt - 1)), MAX_RETRY_DELAY))
    if last_error is not None:
        raise last_error
    return last_response

# Regex for parsing candidates
PROXY_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b')
IP_CELL_REGEX = re.compile(r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$')
PORT_CELL_REGEX = re.compile(r'^[1-9][0-9]{1,4}$')

# ==========================================
# 1. OSINT SEARCH ENGINES CRAWLERS
# ==========================================

async def scrape_shodan(client: httpx.AsyncClient, config: EngineConfig, api_key: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "shodan") -> None:
    if not api_key:
        return
    logger.info("[*] Shodan: Querying search endpoints...")
    found_count = 0
    for query in config.queries:
        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": api_key, "query": query}
        try:
            resp = await get_with_retry(client, url, params=params, timeout=15.0)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                for match in matches:
                    ip = match.get("ip_str")
                    port = match.get("port")
                    if ip and port:
                        _emit(results, provenance, f"{ip}:{port}", label)
                        found_count += 1
        except Exception as e:
            logger.warning("Shodan query failed: %s", e)
    logger.info("[+] Shodan: Harvested %d candidates.", found_count)

async def scrape_zoomeye(client: httpx.AsyncClient, config: EngineConfig, api_key: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "zoomeye") -> None:
    if not api_key:
        return
    logger.info("[*] ZoomEye: Querying search endpoints...")
    headers = {"API-KEY": api_key}
    found_count = 0
    for query in config.queries:
        url = "https://api.zoomeye.ai/host/search"
        params = {"query": query}
        try:
            resp = await get_with_retry(client, url, params=params, headers=headers, timeout=20.0)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                for match in matches:
                    ip = match.get("ip")
                    portinfo = match.get("portinfo", {})
                    port = portinfo.get("port")
                    if ip and port:
                        _emit(results, provenance, f"{ip}:{port}", label)
                        found_count += 1
        except Exception as e:
            logger.warning("ZoomEye query failed: %s", e)
    logger.info("[+] ZoomEye: Harvested %d candidates.", found_count)

async def scrape_fofa(client: httpx.AsyncClient, config: EngineConfig, email: str, api_key: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "fofa") -> None:
    """
    Scrapes IP:PORT candidates from FOFA Search API.
    Email and API Key can be registered for free on fofa.info.
    Queries are config-driven with a sensible default fallback.
    """
    if not email or not api_key:
        return
    logger.info("[*] FOFA: Querying search endpoints...")
    queries = config.queries if config and config.queries else [
        'port="1080" && protocol="socks5"',
        'port="8080" && protocol="http"',
        'port="3128" && protocol="http"'
    ]
    found_count = 0
    for q in queries:
        q_base64 = base64.b64encode(q.encode("utf-8")).decode("utf-8")
        url = "https://fofa.info/api/v1/search/all"
        params = {
            "key": api_key,
            "email": email,
            "qbase64": q_base64,
            "fields": "ip,port",
            "size": 100
        }
        try:
            resp = await get_with_retry(client, url, params=params, timeout=20.0)
            if resp.status_code == 200:
                results_list = resp.json().get("results", [])
                for item in results_list:
                    if len(item) == 2:
                        ip, port = item[0], item[1]
                        _emit(results, provenance, f"{ip}:{port}", label)
                        found_count += 1
        except Exception as e:
            logger.warning("FOFA query failed: %s", e)
    logger.info("[+] FOFA: Harvested %d candidates.", found_count)

async def scrape_censys(client: httpx.AsyncClient, config: EngineConfig, api_id: str, api_secret: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "censys") -> None:
    """
    Scrapes IP:PORT candidates from the Censys Search v2 API.
    Authenticates with API ID + Secret via HTTP basic auth.
    """
    if not api_id or not api_secret:
        return
    logger.info("[*] Censys: Querying search endpoints...")
    found_count = 0
    auth = (api_id, api_secret)
    for query in config.queries:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": query, "per_page": 100}
        try:
            resp = await get_with_retry(client, url, params=params, auth=auth, timeout=20.0)
            if resp.status_code == 200:
                hits = resp.json().get("result", {}).get("hits", [])
                for hit in hits:
                    ip = hit.get("ip")
                    if not ip:
                        continue
                    services = hit.get("services", []) or [{}]
                    for service in services:
                        port = service.get("port")
                        if port:
                            _emit(results, provenance, f"{ip}:{port}", label)
                            found_count += 1
        except Exception as e:
            logger.warning("Censys query failed: %s", e)
    logger.info("[+] Censys: Harvested %d candidates.", found_count)

async def scrape_criminalip(client: httpx.AsyncClient, config: EngineConfig, api_key: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "criminalip") -> None:
    """
    Scrapes IP:PORT candidates from the Criminal IP Banner Search API.
    Uses defensive parsing since the API response shape varies by query type.
    """
    if not api_key:
        return
    logger.info("[*] Criminal IP: Querying search endpoints...")
    headers = {"x-api-key": api_key}
    found_count = 0
    for query in config.queries:
        url = "https://api.criminalip.io/v1/banner/search"
        params = {"query": query, "offset": 0}
        try:
            resp = await get_with_retry(client, url, params=params, headers=headers, timeout=20.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = data.get("result", []) if isinstance(data, dict) else []
                if isinstance(result, dict):
                    result = result.get("list", [])
                for entry in result:
                    ip = entry.get("ip_address") or entry.get("ip")
                    if not ip:
                        continue
                    port = entry.get("port")
                    if not port and isinstance(entry.get("services"), list):
                        for svc in entry["services"]:
                            if svc.get("port"):
                                port = svc["port"]
                                break
                    if port:
                        _emit(results, provenance, f"{ip}:{port}", label)
                        found_count += 1
        except Exception as e:
            logger.warning("Criminal IP query failed: %s", e)
    logger.info("[+] Criminal IP: Harvested %d candidates.", found_count)

# ==========================================
# 2. KEYLESS PRIMARY CRAWLERS
# ==========================================

async def scrape_proxyscrape(client: httpx.AsyncClient, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "proxyscrape") -> None:
    url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=10000&country=all&ssl=all&anonymity=all"
    try:
        resp = await get_with_retry(client, url, timeout=15.0)
        if resp.status_code == 200:
            found = set(PROXY_REGEX.findall(resp.text))
            for addr in found:
                _emit(results, provenance, addr, label)
            logger.info("[+] ProxyScrape API: Found %d candidates.", len(found))
    except Exception as e:
        logger.warning("Scraper failed for ProxyScrape: %s", e)

async def scrape_spys_me(client: httpx.AsyncClient, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "spys.me") -> None:
    url = "http://spys.me/proxy.txt"
    try:
        resp = await get_with_retry(client, url, timeout=15.0)
        if resp.status_code == 200:
            found = set(PROXY_REGEX.findall(resp.text))
            for addr in found:
                _emit(results, provenance, addr, label)
            logger.info("[+] Spys.me: Found %d candidates.", len(found))
    except Exception as e:
        logger.warning("Scraper failed for Spys.me: %s", e)

async def scrape_geonode(client: httpx.AsyncClient, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "geonode") -> None:
    url = "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"
    try:
        resp = await get_with_retry(client, url, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            found_count = 0
            for item in data:
                ip = item.get("ip")
                port = item.get("port")
                if ip and port:
                    _emit(results, provenance, f"{ip}:{port}", label)
                    found_count += 1
            logger.info("[+] Geonode API: Found %d candidates.", found_count)
    except Exception as e:
        logger.warning("Scraper failed for Geonode API: %s", e)

async def scrape_html_table(client: httpx.AsyncClient, url: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "html") -> None:
    """
    Scrapes IP:PORT pairs from HTML proxy-list tables via BeautifulSoup.
    Parses any table layout: columns are located by cell content, so row
    order, extra columns and nested markup cannot break the parser.
    """
    try:
        resp = await get_with_retry(client, url, timeout=15.0)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            found_count = 0
            for row in soup.find_all("tr"):
                cells = [c.get_text(strip=True) for c in row.find_all("td")]
                for i, cell in enumerate(cells):
                    ip_match = IP_CELL_REGEX.match(cell)
                    if not ip_match or i + 1 >= len(cells):
                        continue
                    if PORT_CELL_REGEX.match(cells[i + 1]):
                        _emit(results, provenance, f"{ip_match.group(1)}:{cells[i + 1]}", label)
                        found_count += 1
            logger.info("[+] Scraped HTML Table '%s': Found %d candidates.", url, found_count)
    except Exception as e:
        logger.warning("Scraper failed for HTML site %s: %s", url, e)

async def scrape_plain_list(client: httpx.AsyncClient, url: str, results: Set[str], provenance: Optional[Dict[str, str]] = None, label: str = "list") -> None:
    """
    Scrapes IP:PORT candidates from plain-text proxy lists (GitHub raw
    dumps, direct API lists, etc). One candidate per line, optionally with
    extra columns/comments - PROXY_REGEX extracts everything that matters.
    """
    try:
        resp = await get_with_retry(client, url, timeout=20.0)
        if resp.status_code == 200:
            found = valid_candidates(set(PROXY_REGEX.findall(resp.text)))
            for addr in found:
                _emit(results, provenance, addr, label)
            logger.info("[+] Plain list '%s': Found %d candidates.", url, len(found))
    except Exception as e:
        logger.warning("Scraper failed for plain list %s: %s", url, e)

# ==========================================
# 3. PIPELINE COORDINATOR
# ==========================================

async def run_scraper_pipeline(
    engines_config: Dict[str, EngineConfig],
    keys: Dict[str, str],
    list_sources: List[str] = None,
    html_sources: List[str] = None,
    provenance: Optional[Dict[str, str]] = None,
    source_stats=None,
) -> List[str]:
    """
    Combines OSINT keyed search engines with keyless primary web scrapers.
    provenance (address -> source label) is filled in when provided; a
    SourceStats instance gates chronically dead sources via should_skip().
    """
    # Tier-B engines (Shodan/FOFA) run on the 8-hour boundary of the 2-hourly
    # cadence: UTC hours 0, 8 and 16. The old round(hour/2)*2 arithmetic used
    # banker's rounding and was non-monotonic, so it mis-slotted odd hours.
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    utc_hour = utc_now.hour
    is_8hour_interval = (utc_hour % 8 == 0)

    logger.info("[*] Launching hybrid OSINT + Primary Harvester... (UTC Hour: %d, 8h-tier: %s)", utc_hour, is_8hour_interval)
    
    unique_proxies: Set[str] = set()

    def want(label: str) -> bool:
        """True when the source should be scraped this run (not disabled)."""
        if source_stats is None:
            return True
        skip = source_stats.should_skip(label)
        if skip:
            logger.info("[Sources] Skipping '%s' (disabled or under-performing).", label)
        return not skip
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(headers=headers) as client:
        tasks = []

        # -- TIER A: Keyless Primary Sources (Runs on every harvester run - every 2h) --
        if want("proxyscrape"):
            tasks.append(scrape_proxyscrape(client, unique_proxies, provenance=provenance, label="proxyscrape"))
        if want("spys.me"):
            tasks.append(scrape_spys_me(client, unique_proxies, provenance=provenance, label="spys.me"))
        if want("geonode"):
            tasks.append(scrape_geonode(client, unique_proxies, provenance=provenance, label="geonode"))
        
        for url in (html_sources or []):
            label = f"html:{urlparse(url).hostname or 'unknown'}"
            if want(label):
                tasks.append(scrape_html_table(client, url, unique_proxies, provenance=provenance, label=label))

        # -- TIER A.5: Curated plain-text lists (GitHub raw, direct dumps) --
        for url in (list_sources or []):
            label = f"list:{urlparse(url).hostname or 'unknown'}"
            if want(label):
                tasks.append(scrape_plain_list(client, url, unique_proxies, provenance=provenance, label=label))

        # -- TIER B: OSINT Engines (Tiered/Keyed runs) --
        # 1. ZoomEye (Tier A: Run every 2 hours)
        if "zoomeye" in engines_config and keys.get("ZOOMEYE_API_KEY") and want("zoomeye"):
            tasks.append(scrape_zoomeye(client, engines_config["zoomeye"], keys["ZOOMEYE_API_KEY"], unique_proxies, provenance=provenance, label="zoomeye"))

        # 2. Censys (Tier A: Run every 2 hours)
        if "censys" in engines_config and keys.get("CENSYS_API_ID") and keys.get("CENSYS_API_SECRET") and want("censys"):
            tasks.append(scrape_censys(client, engines_config["censys"], keys["CENSYS_API_ID"], keys["CENSYS_API_SECRET"], unique_proxies, provenance=provenance, label="censys"))

        # 3. Criminal IP (Tier A: Run every 2 hours)
        if "criminalip" in engines_config and keys.get("CRIMINALIP_API_KEY") and want("criminalip"):
            tasks.append(scrape_criminalip(client, engines_config["criminalip"], keys["CRIMINALIP_API_KEY"], unique_proxies, provenance=provenance, label="criminalip"))

        # 4. Shodan (Tier B: Run every 8 hours)
        if "shodan" in engines_config and keys.get("SHODAN_API_KEY") and want("shodan"):
            if is_8hour_interval:
                tasks.append(scrape_shodan(client, engines_config["shodan"], keys["SHODAN_API_KEY"], unique_proxies, provenance=provenance, label="shodan"))
            else:
                logger.info("[!] Shodan skipped (runs strictly on 8-hour intervals).")

        # 5. FOFA (Tier B: Run every 8 hours)
        if keys.get("FOFA_EMAIL") and keys.get("FOFA_API_KEY") and want("fofa"):
            if is_8hour_interval:
                fofa_cfg = engines_config.get("fofa")
                tasks.append(scrape_fofa(client, fofa_cfg, keys["FOFA_EMAIL"], keys["FOFA_API_KEY"], unique_proxies, provenance=provenance, label="fofa"))
            else:
                logger.info("[!] FOFA skipped (runs strictly on 8-hour intervals).")

        await asyncio.gather(*tasks, return_exceptions=True)

    compiled_list = sorted(list(unique_proxies))
    logger.info("[+] Harvester complete. Total unique primary candidates compiled: %d", len(compiled_list))
    return compiled_list

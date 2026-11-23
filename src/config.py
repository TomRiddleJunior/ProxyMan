import os
import yaml
import logging
from dataclasses import dataclass, field
from typing import List, Dict

logger = logging.getLogger(__name__)

# Echo endpoints used to prove a proxy routes real traffic (order = fallback
# order). Kept module-level so load_config can reuse it as the default.
DEFAULT_EXIT_ENDPOINTS = [
    "http://api.ipify.org/?format=json",
    "http://ip-api.com/json?fields=query",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com/",
]


def _as_bool(value, default: bool = True) -> bool:
    """String-lenient boolean parse: YAML gives real bools, but quoted values
    like "false" would otherwise be truthy strings. Accepts 1/0/true/false/
    yes/no/on/off and falls back to the default on garbage."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default

@dataclass
class ValidationConfig:
    test_urls: List[str] = field(default_factory=lambda: ["http://httpbin.org/headers", "http://postman-echo.com/headers"])
    ssl_test_url: str = "https://www.google.com"
    connect_timeout: float = 3.0
    read_timeout: float = 5.5
    timeout: float = 9.0
    max_concurrency: int = 400
    verify_exit: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    # Echo endpoints used to PROVE a proxy routes real traffic: the runner's
    # public IP is fetched THROUGH the proxy from each endpoint in turn until
    # one answers. Multiple endpoints remove the single-point-of-failure that
    # silently downgraded most of the pool to "unverified".
    exit_endpoints: List[str] = field(default_factory=lambda: list(DEFAULT_EXIT_ENDPOINTS))

@dataclass
class PublishConfig:
    """Hard quality gate for the public feeds.

    verified_only: only proxies whose traffic was PROVEN to route through
    them (exit IP fetched through the proxy, different from our own) are
    published. Handshake-only survivors are held back until they prove real
    routing - a port that merely speaks SOCKS5 is not a usable proxy.
    degrade_when_runner_ip_unknown: if the runner's own public IP cannot be
    established, verification is impossible; publish handshake-validated
    entries for that run (honestly flagged verified_exit=false) instead of
    shipping an empty feed."""
    verified_only: bool = True
    degrade_when_runner_ip_unknown: bool = True

@dataclass
class PremiumConfig:
    """Premium tier: exit-verified + stable + fast. Emits premium.txt.
    - min_streak: consecutive proven-alive checks required
    - max_latency: honest end-to-end RTT ceiling (seconds)
    - require_ssl: proxy must tunnel TLS (CONNECT to :443)"""
    min_streak: int = 5
    max_latency: float = 1.0
    require_ssl: bool = True

@dataclass
class OutputConfig:
    output_dir: str = "./output"
    formats: List[str] = field(default_factory=lambda: ["json", "txt", "csv"])
    fast_latency_threshold: float = 0.8

@dataclass
class EngineConfig:
    queries: List[str] = field(default_factory=list)


@dataclass
class TargetConfig:
    """Feature A: a named site you want site-ready proxy lists for."""
    urls: List[str] = field(default_factory=list)


@dataclass
class ASNConfig:
    """Feature B: ASN/hosting classification of validated proxies."""
    enabled: bool = True
    batch_api: str = "http://ip-api.com/batch"
    rate_limit_rpm: int = 15

@dataclass
class PoolConfig:
    state_file: str = "./state/pool_state.json"
    max_consecutive_failures: int = 3
    retest_interval: int = 8
    retention_days: int = 14
    min_successful_checks: int = 1
    # Bounded state: known-dead entries expire far sooner than live ones, so
    # the pool file cannot grow without bound. max_entries is the hard ceiling.
    dead_retention_days: int = 3
    max_entries: int = 200000
    # Compounding pool: proxies proven alive recently that dropped out of the
    # feed after a transient failure are re-seeded into the checker.
    revival_within_hours: int = 24
    revival_limit: int = 500


@dataclass
class SourcesConfig:
    state_file: str = "./state/source_stats.json"
    min_live_ratio: float = 0.02
    min_checks: int = 50
    disable_runs: int = 48
    retention_days: int = 14


@dataclass
class AppConfig:
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)
    sources: SourcesConfig = field(default_factory=SourcesConfig)
    publish: PublishConfig = field(default_factory=PublishConfig)
    premium: PremiumConfig = field(default_factory=PremiumConfig)
    targets: Dict[str, TargetConfig] = field(default_factory=dict)
    asn: ASNConfig = field(default_factory=ASNConfig)
    list_sources: List[str] = field(default_factory=list)
    html_sources: List[str] = field(default_factory=list)
    engines: Dict[str, EngineConfig] = field(default_factory=dict)

def load_config(config_path: str = "config.yaml") -> AppConfig:
    if not os.path.exists(config_path):
        return AppConfig()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("[!] Error reading config file: %s", e)
        return AppConfig()

    v_data = data.get("validation", {})
    validation = ValidationConfig(
        test_urls=v_data.get("test_urls", ["http://httpbin.org/headers", "http://postman-echo.com/headers"]),
        ssl_test_url=v_data.get("ssl_test_url", "https://www.google.com"),
        connect_timeout=float(v_data.get("connect_timeout", 3.0)),
        read_timeout=float(v_data.get("read_timeout", 5.5)),
        timeout=float(v_data.get("timeout", 9.0)),
        max_concurrency=int(v_data.get("max_concurrency", 400)),
        verify_exit=_as_bool(v_data.get("verify_exit", True), True),
        user_agent=v_data.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        exit_endpoints=v_data.get("exit_endpoints", DEFAULT_EXIT_ENDPOINTS),
    )

    pub_data = data.get("publish", {}) or {}
    publish = PublishConfig(
        verified_only=_as_bool(pub_data.get("verified_only", True), True),
        degrade_when_runner_ip_unknown=_as_bool(pub_data.get("degrade_when_runner_ip_unknown", True), True),
    )

    prem_data = data.get("premium", {}) or {}
    premium = PremiumConfig(
        min_streak=int(prem_data.get("min_streak", 5)),
        max_latency=float(prem_data.get("max_latency", 1.0)),
        require_ssl=_as_bool(prem_data.get("require_ssl", True), True),
    )

    o_data = data.get("output", {})
    output = OutputConfig(
        output_dir=o_data.get("output_dir", "./output"),
        formats=o_data.get("formats", ["json", "txt", "csv"]),
        fast_latency_threshold=float(o_data.get("fast_latency_threshold", 0.8)),
    )

    engines = {}
    engines_data = data.get("search_engines", {})
    for name, eng_val in engines_data.items():
        engines[name] = EngineConfig(queries=eng_val.get("queries", []))

    targets = {}
    for name, t_val in (data.get("targets", {}) or {}).items():
        targets[name] = TargetConfig(urls=t_val.get("urls", []) or [])

    a_data = data.get("asn", {}) or {}
    asn = ASNConfig(
        enabled=_as_bool(a_data.get("enabled", True), True),
        batch_api=a_data.get("batch_api", "http://ip-api.com/batch"),
        rate_limit_rpm=int(a_data.get("rate_limit_rpm", 15)),
    )

    p_data = data.get("pool", {})
    pool = PoolConfig(
        state_file=p_data.get("state_file", "./state/pool_state.json"),
        max_consecutive_failures=int(p_data.get("max_consecutive_failures", 3)),
        retest_interval=int(p_data.get("retest_interval", 8)),
        retention_days=int(p_data.get("retention_days", 14)),
        min_successful_checks=int(p_data.get("min_successful_checks", 1)),
        dead_retention_days=int(p_data.get("dead_retention_days", 3)),
        max_entries=int(p_data.get("max_entries", 200000)),
        revival_within_hours=int(p_data.get("revival_within_hours", 24)),
        revival_limit=int(p_data.get("revival_limit", 500)),
    )

    list_sources = data.get("list_sources", []) or []
    html_sources = data.get("html_sources", []) or []

    s_data = data.get("sources", {})
    sources = SourcesConfig(
        state_file=s_data.get("state_file", "./state/source_stats.json"),
        min_live_ratio=float(s_data.get("min_live_ratio", 0.02)),
        min_checks=int(s_data.get("min_checks", 50)),
        disable_runs=int(s_data.get("disable_runs", 48)),
        retention_days=int(s_data.get("retention_days", 14)),
    )

    return AppConfig(
        validation=validation,
        output=output,
        pool=pool,
        sources=sources,
        publish=publish,
        premium=premium,
        targets=targets,
        asn=asn,
        list_sources=list_sources,
        html_sources=html_sources,
        engines=engines
    )

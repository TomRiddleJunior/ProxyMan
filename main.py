import os
import sys
import time
import json
import argparse
import asyncio
import logging
import logging.handlers
import tomllib
from pathlib import Path
from typing import Dict, Optional
from src.config import load_config
from src.scraper.base import run_scraper_pipeline
from src.validator.geo import GeoIPResolver
from src.validator.core import ProxyValidator, is_public_ip, ProxyInfo
from src.storer import ProxyStorer
from src.state import PoolState
from src.sources import SourceStats

logger = logging.getLogger("proxyman")


def setup_logging(verbose: bool, log_file: str = None) -> None:
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=5_000_000, backupCount=2
            )
        )
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


async def worker(queue: asyncio.Queue, validator: ProxyValidator, results: list, semaphore: asyncio.Semaphore):
    while True:
        raw_proxy = await queue.get()
        try:
            async with semaphore:
                info = await validator.validate_single_proxy(raw_proxy)
                if info:
                    results.append(info)
                    logger.info(
                        "[+] Active: %s | %s | %s | Latency: %.3fs | %s (%s)",
                        info.address, info.protocol.upper(), info.anonymity,
                        info.latency, info.country_code, info.country_name
                    )
        except Exception as e:
            logger.debug("Worker error on %s: %s", raw_proxy, e)
        finally:
            queue.task_done()


def _version() -> str:
    """Reads the version from pyproject.toml (single source of truth)."""
    pyproject = Path(__file__).parent / "pyproject.toml"
    try:
        with open(pyproject, "rb") as f:
            return tomllib.load(f)["project"]["version"]
    except Exception:
        return "unknown"


def _raise_fd_limit() -> None:
    """Best-effort file-descriptor limit raise: deep validation opens
    several sockets per concurrent worker; the default soft limit can
    starve the event loop with OSError(EMFILE) on constrained hosts."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            logger.debug("Raised RLIMIT_NOFILE %d -> %d", soft, hard)
    except Exception:
        pass


async def amain():
    start_time = time.monotonic()
    _raise_fd_limit()

    # 1. Parse command line arguments
    parser = argparse.ArgumentParser(description="ProxyMan OSINT Crawler & Checker Engine")
    parser.add_argument("--mode", choices=["harvest", "check"], required=True, help="Execution mode")
    parser.add_argument("--target", default=None,
                        help="Feature A: emit targets/<site>.txt for this site (see config.yaml targets:)")
    parser.add_argument("--no-asn", action="store_true",
                        help="Feature B: skip ASN/hosting classification even when config enables it")
    parser.add_argument("--output-dir", default=None, help="Dynamic output directory destination")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG level logging")
    parser.add_argument("--dry-run", action="store_true",
                        help="Rehearse the pipeline with synthetic results (no network I/O)")
    parser.add_argument("--log-file", default=None,
                        help="Write logs to this file (rotating, 5MB x 3)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    args = parser.parse_args()

    setup_logging(args.verbose, args.log_file)

    # 2. Load configuration
    config = load_config("config.yaml")

    all_candidates = []
    provenance: Dict[str, str] = {}

    # Source effectiveness tracker: gates dead sources during scraping,
    # records per-source live ratios after validation
    source_stats = SourceStats(
        state_file=config.sources.state_file,
        min_live_ratio=config.sources.min_live_ratio,
        min_checks=config.sources.min_checks,
        disable_runs=config.sources.disable_runs,
        retention_days=config.sources.retention_days,
    )

    if args.mode == "harvest":
        # Extract OSINT API keys from environment
        keys = {
            "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
            "CENSYS_API_ID": os.getenv("CENSYS_API_ID", ""),
            "CENSYS_API_SECRET": os.getenv("CENSYS_API_SECRET", ""),
            "ZOOMEYE_API_KEY": os.getenv("ZOOMEYE_API_KEY", ""),
            "CRIMINALIP_API_KEY": os.getenv("CRIMINALIP_API_KEY", ""),
            "FOFA_EMAIL": os.getenv("FOFA_EMAIL", ""),
            "FOFA_API_KEY": os.getenv("FOFA_API_KEY", "")
        }

        # Run scraping pipelines concurrently (provenance: address -> source)
        scraped_candidates = await run_scraper_pipeline(
            config.engines, keys, config.list_sources, config.html_sources,
            provenance=provenance, source_stats=source_stats,
        )

        # Merge with existing active proxies from the public list to grow the pool
        existing_candidates = []
        if os.path.exists("public_list/proxies.json"):
            try:
                with open("public_list/proxies.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    existing_candidates = [item["address"] for item in data if "address" in item]
                    logger.info("Loaded %d existing active proxies to merge.", len(existing_candidates))
            except Exception as e:
                logger.warning("Failed to load public_list/proxies.json: %s", e)

        candidates = sorted(list(set(scraped_candidates + existing_candidates)))
        all_candidates = candidates
        for addr in existing_candidates:
            provenance.setdefault(addr, "pool")

    elif args.mode == "check":
        # Checker mode only validates already active proxies inside public list
        if os.path.exists("public_list/proxies.json"):
            try:
                with open("public_list/proxies.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    candidates = [item["address"] for item in data if "address" in item]
                    all_candidates = candidates
                    provenance = {addr: "pool" for addr in candidates}
                    logger.info("Loaded %d active proxies for re-validation.", len(candidates))
            except Exception as e:
                logger.error("Failed to load public_list/proxies.json: %s", e)
                sys.exit(1)
        else:
            logger.warning("No active pool found at public_list/proxies.json. Skipping checker execution.")
            sys.exit(0)

    # 3. Pool stability filter: skip known-dead candidates (with periodic retest)
    pool_state = PoolState(
        state_file=config.pool.state_file,
        max_consecutive_failures=config.pool.max_consecutive_failures,
        retest_interval=config.pool.retest_interval,
        retention_days=config.pool.retention_days,
        dead_retention_days=config.pool.dead_retention_days,
        max_entries=config.pool.max_entries,
    )

    # Compounding pool: re-seed the checker with proxies that were PROVEN
    # alive recently but dropped out of the feed after a transient failure.
    # Without this, one failed check evicts a real proxy permanently and the
    # pool can never grow beyond whatever the last feed snapshot contained.
    if args.mode == "check":
        revival = pool_state.recently_alive_addresses(
            within_hours=config.pool.revival_within_hours,
            limit=config.pool.revival_limit,
        )
        known = set(all_candidates)
        revived = [a for a in revival if a not in known]
        if revived:
            all_candidates.extend(revived)
            for addr in revived:
                provenance.setdefault(addr, "pool-revival")
            logger.info("[Pool] Re-seeding %d recently-alive proxies that left the feed.", len(revived))

    # Pre-filter: drop private/reserved/malformed candidates before they
    # consume queue slots or probe time
    all_candidates = [
        c for c in all_candidates
        if is_public_ip(c.split(":", 1)[0] if ":" in c else "")
    ]

    candidates = []
    for proxy in all_candidates:
        if not pool_state.consider_skip(proxy):
            candidates.append(proxy)
    skipped = len(all_candidates) - len(candidates)
    if skipped:
        logger.info("[Pool] Skipped %d known-dead candidates (stability filter).", skipped)

    if not candidates:
        logger.warning("Queue is empty. Shutting down.")
        sys.exit(0)

    # 4. Setup GeoIP resolver (skipped in dry-run: no network I/O at all)
    geo_resolver = None
    if not args.dry_run:
        geo_resolver = GeoIPResolver()
        await geo_resolver.ensure_db_downloaded()
        geo_resolver.initialize_reader()
    else:
        logger.warning("DRY-RUN MODE: synthetic validation, network I/O disabled.")

    # 5. Setup Validator Engine
    validator = ProxyValidator(
        test_urls=config.validation.test_urls,
        ssl_test_url=config.validation.ssl_test_url,
        connect_timeout=config.validation.connect_timeout,
        read_timeout=config.validation.read_timeout,
        timeout=config.validation.timeout,
        user_agent=config.validation.user_agent,
        geo_resolver=geo_resolver,
        dry_run=args.dry_run,
        verify_exit=config.validation.verify_exit,
        exit_endpoints=config.validation.exit_endpoints,
    )
    if not args.dry_run:
        await validator.select_active_reflector()
        await validator.fetch_my_ip()

    # 6. Populate Queue and Run workers
    queue = asyncio.Queue()
    for proxy in candidates:
        queue.put_nowait(proxy)

    results = []
    semaphore = asyncio.Semaphore(config.validation.max_concurrency)
    worker_count = min(config.validation.max_concurrency, len(candidates))

    workers = []
    for _ in range(worker_count):
        workers.append(asyncio.create_task(worker(queue, validator, results, semaphore)))

    logger.info("Commencing validation on %d candidates using %d async workers...", len(candidates), worker_count)
    await queue.join()

    # Cancel workers
    for task in workers:
        task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    # Close DB reader
    if geo_resolver:
        geo_resolver.close()

    # 7. Update pool state with this run's outcome
    #
    # Publish-gate semantics: when verified-only publishing is active, a
    # handshake-only survivor is NOT a success. Pool streaks must track
    # "proven to route real traffic", otherwise the pool fills with
    # greeting-only ghosts that answer SOCKS5 hellos but tunnel nothing.
    verified_gate = config.publish.verified_only and config.validation.verify_exit
    if verified_gate and args.dry_run:
        verified_gate = False  # dry-run has no runner IP; publish synthetic results
    elif verified_gate and validator.my_ip is None:
        if config.publish.degrade_when_runner_ip_unknown:
            logger.warning(
                "[Publish] Runner public IP unknown - exit verification impossible. "
                "Degrading this run to handshake-validated publish (flagged verified_exit=false)."
            )
            verified_gate = False
        else:
            logger.error("[Publish] Runner public IP unknown and degrade disabled - refusing to publish.")

    def _routed(info: Optional[ProxyInfo]) -> bool:
        return info is not None and (info.verified_exit or not verified_gate)

    validated_map = {info.address: info for info in results}
    for proxy in candidates:
        info = validated_map.get(proxy)
        pool_state.record_check(
            proxy,
            success=_routed(info),
            latency=info.latency if info else None,
            protocol=info.protocol if info else None,
        )
    pool_state.prune()
    pool_state.save()

    # 7b. Record per-source effectiveness (which sources actually feed the pool)
    source_checked: Dict[str, int] = {}
    source_live: Dict[str, int] = {}
    for proxy in candidates:
        src = provenance.get(proxy, "unknown")
        source_checked[src] = source_checked.get(src, 0) + 1
    for info in results:
        src = provenance.get(info.address, "unknown")
        if _routed(info):
            source_live[src] = source_live.get(src, 0) + 1
    source_stats.record_run(source_checked, source_live)
    source_stats.save()

    # Only publish proxies that cleared the stability bar (min consecutive
    # successes) AND - when the verified-only gate is active - actually
    # proved they route traffic. A handshake without routed traffic is a
    # dead proxy wearing a live one's coat.
    publishable = []
    held_unverified = 0
    for info in results:
        e = pool_state.entry(info.address)
        streak = e.get("consecutive_success", 0) if e else 0
        if streak < config.pool.min_successful_checks:
            logger.debug("[Pool] Holding %s (streak %d < min %d)",
                         info.address, streak, config.pool.min_successful_checks)
        elif verified_gate and not info.verified_exit:
            held_unverified += 1
        else:
            publishable.append(info)
    if held_unverified:
        logger.info("[Publish] Holding %d handshake-only proxies (exit not proven; publish.verified_only=true).",
                    held_unverified)

    # Premium tier: proven exit + stability streak + fast honest RTT + TLS
    # capable. Emits premium.txt - the "works right now, repeatedly" list.
    for info in publishable:
        e = pool_state.entry(info.address)
        streak = e.get("consecutive_success", 0) if e else 0
        info.premium = (
            info.verified_exit
            and streak >= config.premium.min_streak
            and info.latency <= config.premium.max_latency
            and (info.ssl_supported or not config.premium.require_ssl)
        )
    # Feed ordering: premium entries first, each block by ascending latency
    publishable.sort(key=lambda p: (not p.premium, p.latency))
    premium_count = sum(1 for i in publishable if i.premium)
    if publishable:
        logger.info("[Premium] %d / %d published proxies meet the premium bar "
                    "(verified, streak >= %d, RTT <= %.2fs, TLS-capable).",
                    premium_count, len(publishable),
                    config.premium.min_streak, config.premium.max_latency)

    # 7b. Feature A: targeted validation — probe each publishable proxy against
    # the requested site and write targets/<site>.txt with the ones that reach it.
    target_label = args.target
    target_url = None
    if target_label:
        target_cfg = config.targets.get(target_label)
        if not target_cfg or not target_cfg.urls:
            logger.error("[Target] '%s' not defined in config.yaml targets: section", target_label)
            sys.exit(2)
        target_url = target_cfg.urls[0]
        if args.dry_run:
            logger.warning("[Target] dry-run: marking proxies synthetic target_ok")
            for info in publishable:
                info.target_ok = True
                info.target_latency = round(info.latency, 3)
        else:
            logger.info("[Target] probing %d candidates against %s (%s)", len(publishable), target_label, target_url)
            target_sem = asyncio.Semaphore(min(200, config.validation.max_concurrency))

            async def target_worker(info: ProxyInfo) -> None:
                async with target_sem:
                    lat = await validator.probe_target(
                        info.address.split(":")[0], int(info.address.split(":")[1]),
                        info.protocol, target_url,
                    )
                    if lat is not None:
                        info.target_ok = True
                        info.target_latency = lat

            await asyncio.gather(*(target_worker(i) for i in publishable))
            reached = sum(1 for i in publishable if i.target_ok)
            logger.info("[Target] %s: %d / %d proxies reached the site", target_label, reached, len(publishable))

    # 7c. Feature B: ASN / hosting classification (with pool-state caching).
    if config.asn.enabled and not args.no_asn and not args.dry_run and publishable:
        from src.validator.asn import ASNClassifier
        classifier = ASNClassifier(
            enabled=True,
            batch_api=config.asn.batch_api,
            rate_limit_rpm=config.asn.rate_limit_rpm,
        )
        need: Dict[str, str] = {}
        for info in publishable:
            addr_ip = info.address.split(":")[0]
            cached = None
            entry = pool_state.entry(info.address)
            if entry and isinstance(entry.get("hosting"), dict):
                cached = entry["hosting"]
            if cached:
                info.hosting = cached.get("hosting", "unknown")
                info.as_name = cached.get("as_name", "")
                info.org = cached.get("org", "")
            else:
                need[info.address] = addr_ip
        if need:
            classified = classifier.classify_ips(list(need.values()))
            for info in publishable:
                addr_ip = info.address.split(":")[0]
                if addr_ip in classified:
                    host_info = classified[addr_ip]
                    info.hosting = host_info["hosting"]
                    info.as_name = host_info["as_name"]
                    info.org = host_info["org"]
                    pool_state.set_hosting(info.address, host_info)
            pool_state.save()
        res = sum(1 for i in publishable if i.hosting == "residential")
        dc = sum(1 for i in publishable if i.hosting == "datacenter")
        logger.info("[ASN] residential=%d datacenter=%d unknown=%d", res, dc,
                    len(publishable) - res - dc)

    # 8. Export outputs
    elapsed = time.monotonic() - start_time
    logger.info("=" * 60)
    logger.info("PROXYMAN RUN SUMMARY (%s MODE)", args.mode.upper())
    logger.info("=" * 60)
    logger.info("Candidates Tested: %d", len(candidates))
    logger.info("Active Found     : %d", len(results))
    logger.info("Exit-Verified    : %d", sum(1 for r in results if r.verified_exit))
    logger.info("Published        : %d (premium: %d)", len(publishable), premium_count)

    pool_stats = pool_state.stats()
    logger.info("Pool Tracked     : %d (alive %d / dead %d)",
                pool_stats["total"], pool_stats["alive"], pool_stats["dead"])
    if pool_stats["skipped_this_run"]:
        logger.info("Pool Skipped     : %d known-dead candidates", pool_stats["skipped_this_run"])

    top_sources = source_stats.summary(limit=8)
    if top_sources:
        logger.info("=== SOURCE EFFECTIVENESS (14d) ===")
        for src, checked, live, ratio in top_sources:
            logger.info("  %-30s checked=%-6d live=%-4d ratio=%5.1f%%", src, checked, live, ratio * 100)

    if results:
        counts = {}
        for r in results:
            counts[r.protocol] = counts.get(r.protocol, 0) + 1
        for proto, count in counts.items():
            logger.info(" - %s: %d", proto.upper().ljust(14), count)

        elite = sum(1 for r in results if r.anonymity == "elite")
        logger.info(" - ELITE (ANON)  : %d", elite)
        logger.info("Average Latency  : %.3fs", sum(r.latency for r in results) / len(results))

    logger.info("Total Duration   : %.2fs", elapsed)
    logger.info("=" * 60)

    output_dir = args.output_dir or config.output.output_dir
    storer = ProxyStorer(
        output_dir=output_dir,
        formats=config.output.formats,
        fast_latency_threshold=config.output.fast_latency_threshold,
        snapshot_state_file=os.path.join(os.path.dirname(output_dir) or ".", "state", "last_snapshot.json"),
    )
    storer.save_proxies(publishable, target=target_label)


def cli() -> None:
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        logging.getLogger("proxyman").warning("Interrupted by user. Exiting cleanly.")
        sys.exit(130)


if __name__ == "__main__":
    cli()
"""
Pool stability scoring: persistent per-proxy history.

The pipeline runs unattended every 15 minutes (checker) and 2 hours
(harvester). Without history it treats every host as brand new on every
run, wasting validation work on known-dead hosts and publishing flapping
proxies that pass once and die the next run.

This module persists a compact state file (JSON) of per-address health:
  - known-dead hosts are skipped on future runs (with periodic retest to
    catch revivals), cutting validation I/O dramatically
  - proxies must clear a minimum consecutive-success streak before being
    published, so the public feeds only contain proven, stable nodes
  - stale entries are pruned after a configurable retention window
"""

import os
import json
import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class PoolState:
    def __init__(
        self,
        state_file: str,
        max_consecutive_failures: int = 3,
        retest_interval: int = 8,
        retention_days: int = 14,
        dead_retention_days: int = 3,
        max_entries: int = 200000,
    ):
        self.state_file = state_file
        self.max_consecutive_failures = max(1, max_consecutive_failures)
        self.retest_interval = max(1, retest_interval)
        self.retention_days = max(1, retention_days)
        # Known-dead hosts expire on a much shorter clock than live ones, so
        # the state file stays bounded no matter how many candidates churn
        # through it. max_entries is the hard ceiling.
        self.dead_retention_days = max(1, dead_retention_days)
        self.max_entries = max(1000, max_entries)
        self.entries: Dict[str, dict] = {}
        self.skipped_this_run = 0
        self.load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.entries = data.get("entries", {}) if isinstance(data, dict) else {}
            logger.info("[Pool] Loaded %d tracked entries from %s", len(self.entries), self.state_file)
        except Exception as e:
            logger.warning("[Pool] Failed to load state (cold start): %s", e)
            self.entries = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        tmp_path = f"{self.state_file}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "entries": self.entries}, f, indent=1)
            os.replace(tmp_path, self.state_file)
        except Exception as e:
            logger.warning("[Pool] Failed to save state: %s", e)

    # ------------------------------------------------------------------
    # Queries & mutations
    # ------------------------------------------------------------------

    def entry(self, address: str) -> Optional[dict]:
        return self.entries.get(address)

    def set_hosting(self, address: str, hosting: dict) -> None:
        """Feature B: cache ASN classification on the entry so checker runs
        never re-query ip-api for addresses we already classified."""
        entry = self.entries.setdefault(address, {})
        entry["hosting"] = hosting

    def consider_skip(self, address: str) -> bool:
        """
        Returns True when the proxy is known-dead and should NOT be queued
        for validation this run. Known-dead hosts are retested on a
        countdown cadence (retest_interval runs) so revived hosts are
        rediscovered instead of being skipped forever.
        """
        e = self.entries.get(address)
        if not e:
            return False
        if e.get("consecutive_failures", 0) < self.max_consecutive_failures:
            return False

        e["retest_countdown"] = e.get("retest_countdown", self.retest_interval) - 1
        if e["retest_countdown"] > 0:
            # NOTE: last_seen_ts is deliberately NOT refreshed here. Refreshing
            # it on every skip was the bug that made prune() a no-op forever -
            # known-dead hosts would stay "recently seen" indefinitely and the
            # state file grew without bound (observed: 8.9 MB / 28k entries and
            # climbing). Retests are tracked separately instead.
            e["last_retest_ts"] = time.time()
            self.skipped_this_run += 1
            return True

        e["retest_countdown"] = self.retest_interval
        return False  # countdown expired -> re-validate this run

    def record_check(
        self,
        address: str,
        success: bool,
        latency: Optional[float] = None,
        protocol: Optional[str] = None,
    ) -> None:
        now = time.time()
        e = self.entries.get(address)
        if e is None:
            e = {
                "first_seen_ts": now,
                "checks": 0,
                "ok_count": 0,
                "fail_count": 0,
                "consecutive_failures": 0,
                "consecutive_success": 0,
                "last_seen_ts": now,
                "last_ok_ts": None,
                "dead_since_ts": None,
                "best_latency": None,
                "protocols": [],
                "retest_countdown": 0,
            }
            self.entries[address] = e

        e["last_seen_ts"] = now
        e["checks"] += 1

        if success:
            e["consecutive_failures"] = 0
            e["consecutive_success"] = e.get("consecutive_success", 0) + 1
            e["ok_count"] += 1
            e["last_ok_ts"] = now
            e["dead_since_ts"] = None  # back on the live clock
            if latency is not None:
                best = e.get("best_latency")
                e["best_latency"] = latency if best is None else min(best, latency)
            if protocol and protocol not in e.get("protocols", []):
                e.setdefault("protocols", []).append(protocol)
        else:
            e["consecutive_failures"] = e.get("consecutive_failures", 0) + 1
            e["consecutive_success"] = 0
            e["fail_count"] += 1
            # Start the retest countdown the moment a host crosses the
            # dead threshold, so it is skipped for (interval-1) runs next.
            if e["consecutive_failures"] == self.max_consecutive_failures:
                e["retest_countdown"] = self.retest_interval
            # Stamp (but never reset) the death time so prune() can expire the
            # entry on the short dead clock. The >= guard also stamps legacy
            # entries that were already dead before this bookkeeping existed.
            if e["consecutive_failures"] >= self.max_consecutive_failures and not e.get("dead_since_ts"):
                e["dead_since_ts"] = now

    def prune(self) -> int:
        """Bounds the state file.

        Live entries expire after `retention_days` without a check. Known-dead
        entries expire after the much shorter `dead_retention_days`, measured
        from when they crossed the dead threshold, so dead hosts can never
        accumulate forever. A hard `max_entries` ceiling evicts the least
        valuable entries (dead before alive, oldest before newest) if the pool
        still exceeds it.
        """
        now = time.time()
        stale_cutoff = now - self.retention_days * 86400
        dead_cutoff = now - self.dead_retention_days * 86400
        before = len(self.entries)

        kept: Dict[str, dict] = {}
        for k, v in self.entries.items():
            is_dead = v.get("consecutive_failures", 0) >= self.max_consecutive_failures
            if is_dead:
                dead_ts = v.get("dead_since_ts") or v.get("last_seen_ts", 0)
                if dead_ts < dead_cutoff:
                    continue
            elif v.get("last_seen_ts", 0) < stale_cutoff:
                continue
            kept[k] = v

        if len(kept) > self.max_entries:
            def rank(item):
                _, v = item
                dead = v.get("consecutive_failures", 0) >= self.max_consecutive_failures
                # live first, then newest first
                return (0 if dead else 1, v.get("last_seen_ts", 0))
            kept = dict(sorted(kept.items(), key=rank, reverse=True)[: self.max_entries])

        self.entries = kept
        removed = before - len(kept)
        if removed:
            logger.info("[Pool] Pruned %d stale/dead entries (%d tracked).", removed, len(kept))
        return removed

    def recently_alive_addresses(self, within_hours: int = 24, limit: int = 500) -> List[str]:
        """Addresses PROVEN alive recently but possibly dropped from the feed.

        The checker unions these back into its candidate set so a flaky-but-real
        proxy can re-earn its place instead of being lost the first time one
        check fails (the old behaviour, which pinned the pool at whatever the
        last feed snapshot contained). Ordered most-recent-success first, then
        best latency; capped at `limit` to bound validation cost.
        """
        cutoff = time.time() - max(1, within_hours) * 3600
        rows = []
        for addr, v in self.entries.items():
            last_ok = v.get("last_ok_ts")
            if v.get("ok_count", 0) > 0 and last_ok and last_ok >= cutoff:
                rows.append((last_ok, v.get("best_latency") or 99.0, addr))
        rows.sort(key=lambda r: (-r[0], r[1]))
        return [addr for _, _, addr in rows[: max(0, limit)]]

    def stats(self) -> dict:
        total = len(self.entries)
        dead = sum(
            1 for e in self.entries.values()
            if e.get("consecutive_failures", 0) >= self.max_consecutive_failures
        )
        return {
            "total": total,
            "alive": total - dead,
            "dead": dead,
            "skipped_this_run": self.skipped_this_run,
        }
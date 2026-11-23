"""
Per-source effectiveness tracking.

Every candidate is tagged with the scraper that yielded it. Runs accumulate
per-day checked/live counts per source; summaries surface which sources
actually feed the pool and which are dead weight. A conservative auto-disable
machinery skips chronically dead sources so validation budget goes to
productive sources only.
"""
import os
import json
import datetime
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

RETENTION_DAYS = 14


class SourceStats:
    def __init__(
        self,
        state_file: str,
        min_live_ratio: float = 0.02,
        min_checks: int = 50,
        disable_runs: int = 48,
        retention_days: int = RETENTION_DAYS,
    ):
        self.state_file = state_file
        self.min_live_ratio = min_live_ratio
        self.min_checks = min_checks
        self.disable_runs = disable_runs
        self.retention_days = retention_days
        self.days: Dict[str, Dict[str, dict]] = {}   # date -> source -> {checked, live}
        self.disabled: Dict[str, int] = {}           # source -> runs remaining
        self.run_counter = 0
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
            self.days = data.get("days", {}) if isinstance(data, dict) else {}
            self.disabled = data.get("disabled", {})
            self.run_counter = int(data.get("run_counter", 0))
            logger.info("[Sources] Loaded %d day-buckets, %d disabled sources.",
                        len(self.days), len(self.disabled))
        except Exception as e:
            logger.warning("[Sources] Failed to load state (cold start): %s", e)
            self.days = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        tmp_path = f"{self.state_file}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({
                    "days": self.days,
                    "disabled": self.disabled,
                    "run_counter": self.run_counter,
                }, f, indent=1)
            os.replace(tmp_path, self.state_file)
        except Exception as e:
            logger.warning("[Sources] Failed to save state: %s", e)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_run(self, checked: Dict[str, int], live: Dict[str, int]) -> None:
        """checked: source -> candidates validated this run; live: source -> alive."""
        today = datetime.date.today().isoformat()
        bucket = self.days.setdefault(today, {})
        for source, count in checked.items():
            rec = bucket.setdefault(source, {"checked": 0, "live": 0})
            rec["checked"] += count
            rec["live"] += live.get(source, 0)
        self.run_counter += 1
        self._tick_disabled()
        self.prune()

    def _tick_disabled(self) -> None:
        for source in list(self.disabled):
            self.disabled[source] -= 1
            if self.disabled[source] <= 0:
                del self.disabled[source]

    # ------------------------------------------------------------------
    # Auto-disable decision (consulted at harvest time)
    # ------------------------------------------------------------------

    def should_skip(self, source: str) -> bool:
        """True when the source must not be scraped this run.

        Disabled sources stay skipped for disable_runs runs, then get a
        fresh chance; chronically dead ones simply re-disable. The live
        ratio is judged over the most recent `_recent_records(source, days=3)`
        day-buckets (day granularity, not per-run - that is what is stored).
        """
        if source in self.disabled:
            return True

        recents = self._recent_records(source, days=3)
        total_checked = sum(r["checked"] for r in recents)
        if total_checked < self.min_checks:
            return False  # not enough evidence yet - keep collecting
        total_live = sum(r["live"] for r in recents)
        ratio = total_live / total_checked
        if ratio < self.min_live_ratio:
            self.disabled[source] = self.disable_runs
            logger.warning(
                "[Sources] '%s' live ratio %.1f%% < %.1f%% over %d checks - disabled for %d runs.",
                source, ratio * 100, self.min_live_ratio * 100,
                total_checked, self.disable_runs,
            )
            return True
        return False

    def _recent_records(self, source: str, days: int) -> List[dict]:
        """Aggregates for `source` from the last `days` day-buckets (day
        buckets are inserted in chronological order)."""
        records = []
        for day_records in self.days.values():
            if source in day_records:
                records.append((day_records[source]["checked"], day_records[source]["live"]))
        return [{"checked": c, "live": l} for c, l in records[-days:]]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def summary(self, limit: int = 10) -> List[Tuple[str, int, int, float]]:
        """Top sources by live yield: (source, checked, live, ratio)."""
        totals: Dict[str, list] = {}
        for day_records in self.days.values():
            for source, rec in day_records.items():
                agg = totals.setdefault(source, [0, 0])
                agg[0] += rec["checked"]
                agg[1] += rec["live"]
        rows = [
            (source, agg[0], agg[1], agg[1] / agg[0] if agg[0] else 0.0)
            for source, agg in totals.items()
        ]
        rows.sort(key=lambda r: r[2], reverse=True)
        return rows[:limit]

    def prune(self) -> int:
        cutoff = (datetime.date.today() - datetime.timedelta(days=self.retention_days)).isoformat()
        before = len(self.days)
        self.days = {d: v for d, v in self.days.items() if d >= cutoff}
        removed = before - len(self.days)
        if removed:
            logger.info("[Sources] Pruned %d stale day-buckets.", removed)
        return removed
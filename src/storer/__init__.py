import os
import json
import csv
import logging
import datetime
from typing import List, Dict, Optional
from src.validator.core import ProxyInfo

logger = logging.getLogger(__name__)

class ProxyStorer:
    def __init__(self, output_dir: str, formats: List[str], fast_latency_threshold: float = 0.4,
                 snapshot_state_file: Optional[str] = None):
        self.output_dir = output_dir
        self.formats = [fmt.lower() for fmt in formats]
        self.fast_latency_threshold = fast_latency_threshold
        self.snapshot_state_file = snapshot_state_file or os.path.join(
            os.path.dirname(output_dir) or ".", "state", "last_snapshot.json")

    def ensure_dir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def save_proxies(self, active_proxies: List[ProxyInfo], target: Optional[str] = None) -> None:
        """
        Saves proxies into multiple formats grouped by protocol, country, and
        anonymity levels. When `target` is set, only proxies that reached the
        target site are written to targets/<target>.txt.
        """
        self.ensure_dir(self.output_dir)
        
        # 1. Output TXT files with split hierarchies
        if "txt" in self.formats:
            self._save_txt_files(active_proxies, target)

        # 2. Output detailed JSON file
        if "json" in self.formats:
            self._save_json_file(active_proxies)

        # 3. Output CSV spreadsheet
        if "csv" in self.formats:
            self._save_csv_file(active_proxies)

        # 4. Always emit meta.json with live stats (powers README badges)
        self._save_meta_file(active_proxies)

        # 5. Completion marker: publish steps gate on this file so a crashed
        # or partial run can never be shipped to the public feeds.
        marker_path = os.path.join(self.output_dir, ".complete")
        with open(marker_path, "w", encoding="utf-8") as f:
            f.write(datetime.datetime.now(datetime.timezone.utc).isoformat())

        logger.info("[+] Proxy lists stored in '%s'", self.output_dir)

    def _load_last_snapshot(self) -> Optional[List[str]]:
        """Feature C: previous run's published addresses (for churn/survival)."""
        try:
            with open(self.snapshot_state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("addresses", [])
        except Exception:
            return None

    def _save_snapshot(self, addresses: List[str]) -> None:
        os.makedirs(os.path.dirname(self.snapshot_state_file) or ".", exist_ok=True)
        with open(self.snapshot_state_file, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "addresses": addresses,
            }, f)

    def _save_meta_file(self, proxies: List[ProxyInfo]) -> None:
        """Writes machine-readable feed statistics consumed by shields.io badges.
        Feature C adds honest quality metrics: survival rate vs the previous
        run's snapshot, churn, hosting-kind splits and the verified ratio."""
        meta_path = os.path.join(self.output_dir, "meta.json")
        counts = {
            "total": len(proxies),
            "http": 0,
            "socks4": 0,
            "socks5": 0,
            "elite": 0,
            "anonymous": 0,
            "ssl": 0,
            "fast": 0,
            "best": 0,
            "verified": 0,
            "premium": 0,
            "residential": 0,
            "datacenter": 0,
            "unknown_hosting": 0,
            "countries": len({
                p.country_code for p in proxies
                if p.country_code and p.country_code not in ("Unknown", "--")
            }),
        }
        for p in proxies:
            if p.protocol in counts:
                counts[p.protocol] += 1
            if p.anonymity == "elite":
                counts["elite"] += 1
            elif p.anonymity == "anonymous":
                counts["anonymous"] += 1
            if p.ssl_supported:
                counts["ssl"] += 1
            if p.verified_exit:
                counts["verified"] += 1
            if p.premium:
                counts["premium"] += 1
            hosting = getattr(p, "hosting", "unknown")
            if hosting == "residential":
                counts["residential"] += 1
            elif hosting == "datacenter":
                counts["datacenter"] += 1
            else:
                counts["unknown_hosting"] += 1
            if p.latency <= self.fast_latency_threshold:
                counts["fast"] = counts.get("fast", 0) + 1
                if p.anonymity == "elite" and p.ssl_supported:
                    counts["best"] = counts.get("best", 0) + 1

        # Feature C: honest survival vs previous snapshot
        current = {p.address for p in proxies}
        prev = set(self._load_last_snapshot() or [])
        survival_rate = None
        churn = None
        if prev:
            survived = len(current & prev)
            survival_rate = round(survived / len(prev), 4)
            churn = round(1.0 - len(prev & current) / max(1, len(prev)), 4)
        self._save_snapshot(sorted(current))

        meta = {
            "schema": 3,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "counts": counts,
            "avg_latency": round(sum(p.latency for p in proxies) / len(proxies), 3) if proxies else 0.0,
            "quality": {
                "verified_ratio": round(counts["verified"] / max(1, counts["total"]), 4),
                "premium_ratio": round(counts["premium"] / max(1, counts["total"]), 4),
                "previous_snapshot_total": len(prev) if prev else None,
                "survival_rate": survival_rate,
                "churn_rate": churn,
                "note": (
                    "verified = traffic was PROVEN to route through the proxy "
                    "(public IP fetched through it, different from our own). "
                    "premium = verified + stable streak + RTT <= 1s + TLS-capable. "
                    "survival_rate = fraction of the previous run's list still alive "
                    "this run; free lists churn fast by nature."
                ),
            },
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def _save_txt_files(self, proxies: List[ProxyInfo], target: Optional[str] = None) -> None:
        # Create subfolders for split APIs
        protocols_dir = os.path.join(self.output_dir, "protocols")
        countries_dir = os.path.join(self.output_dir, "countries")
        anonymity_dir = os.path.join(self.output_dir, "anonymity")
        targets_dir = os.path.join(self.output_dir, "targets")
        hosting_dir = os.path.join(self.output_dir, "hosting")

        self.ensure_dir(protocols_dir)
        self.ensure_dir(countries_dir)
        self.ensure_dir(anonymity_dir)
        self.ensure_dir(targets_dir)
        self.ensure_dir(hosting_dir)

        # 1. Clear every fixed output file up front
        master_path = os.path.join(self.output_dir, "proxies.txt")
        ssl_only_path = os.path.join(self.output_dir, "ssl_only.txt")
        fast_path = os.path.join(self.output_dir, "fast.txt")
        best_path = os.path.join(self.output_dir, "best.txt")
        premium_path = os.path.join(self.output_dir, "premium.txt")
        fixed_paths = [
            master_path, ssl_only_path, fast_path, best_path, premium_path,
            *[os.path.join(protocols_dir, f"{proto}.txt") for proto in ("http", "socks4", "socks5")],
            *[os.path.join(anonymity_dir, f"{anon}.txt") for anon in ("elite", "anonymous")],
            os.path.join(hosting_dir, "residential.txt"),
            os.path.join(hosting_dir, "datacenter.txt"),
        ]
        for path in fixed_paths:
            with open(path, "w", encoding="utf-8") as f:
                pass

        # Purge ALL existing country + target files up front.
        # A country/target with zero proxies in this run must not keep its
        # stale list alive in the published feeds (dead proxies would linger).
        for directory in (countries_dir, targets_dir):
            for fname in os.listdir(directory):
                if fname.endswith(".txt"):
                    try:
                        os.remove(os.path.join(directory, fname))
                    except OSError:
                        pass

        # 2. Group lines per target file and flush each file exactly once.
        # Batching avoids one open() syscall per proxy per output, which
        # matters when pools are thousands of entries across 6+ files.
        lines: Dict[str, List[str]] = {}

        def add(path: str, line: str) -> None:
            lines.setdefault(path, []).append(line)

        for p in proxies:
            add(master_path, p.address)

            if p.protocol in ("http", "socks4", "socks5"):
                add(os.path.join(protocols_dir, f"{p.protocol}.txt"), p.address)

            if p.anonymity in ("elite", "anonymous"):
                add(os.path.join(anonymity_dir, f"{p.anonymity}.txt"), p.address)

            # Country split files (directory purged above, so this builds a
            # fresh per-country list for this run)
            if p.country_code and p.country_code != "--":
                add(os.path.join(countries_dir, f"{p.country_code.lower()}.txt"), p.address)

            # SSL HTTP Tunnel proxies
            if p.protocol == "http" and p.ssl_supported:
                add(ssl_only_path, p.address)

            # Speed tiers: fast = latency under threshold, best = elite + SSL + fast
            if p.latency <= self.fast_latency_threshold:
                add(fast_path, p.address)
                if p.anonymity == "elite" and p.ssl_supported:
                    add(best_path, p.address)

            # Premium tier: exit-verified + stable + fast + TLS-capable.
            # The proxies list arrives sorted (premium first, by latency),
            # so premium.txt is naturally ordered by ascending RTT.
            if p.premium:
                add(premium_path, p.address)

            # Feature B: hosting-kind splits
            hosting = getattr(p, "hosting", "unknown")
            if hosting in ("residential", "datacenter"):
                add(os.path.join(hosting_dir, f"{hosting}.txt"), p.address)

        # Feature A: targeted lists (only proxies that reached the site)
        if target:
            target_list = [p for p in proxies if getattr(p, "target_ok", False)]
            target_path = os.path.join(targets_dir, f"{target}.txt")
            target_lines = sorted(
                target_list,
                key=lambda p: (getattr(p, "target_latency", 99.0), p.address)
            )
            with open(target_path, "w", encoding="utf-8") as f:
                f.write("\n".join(p.address for p in target_lines))
                if target_lines:
                    f.write("\n")
            logger.info("[+] targets/%s.txt: %d site-ready proxies", target, len(target_lines))

        for path, content in lines.items():
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n".join(content) + "\n")

    def _save_json_file(self, proxies: List[ProxyInfo]) -> None:
        json_path = os.path.join(self.output_dir, "proxies.json")
        data = []
        for p in proxies:
            data.append({
                "address": p.address,
                "ip": p.address.split(":")[0],
                "port": int(p.address.split(":")[1]),
                "protocol": p.protocol,
                "anonymity": p.anonymity,
                "latency": p.latency,
                "ssl_supported": p.ssl_supported,
                "verified_exit": p.verified_exit,
                "premium": p.premium,
                "country_code": p.country_code,
                "country_name": p.country_name,
                "hosting": getattr(p, "hosting", "unknown"),
                "as_name": getattr(p, "as_name", ""),
                "org": getattr(p, "org", ""),
                "target_ok": getattr(p, "target_ok", False),
                "target_latency": getattr(p, "target_latency", 0.0),
            })
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def _save_csv_file(self, proxies: List[ProxyInfo]) -> None:
        csv_path = os.path.join(self.output_dir, "proxies.csv")
        headers = ["address", "ip", "port", "protocol", "anonymity", "latency", "ssl_supported", "verified_exit", "premium", "country_code", "country_name", "hosting", "as_name", "org", "target_ok", "target_latency"]
        
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for p in proxies:
                    ip, port = p.address.split(":")
                    writer.writerow([
                        p.address,
                        ip,
                        port,
                        p.protocol,
                        p.anonymity,
                        p.latency,
                        str(p.ssl_supported),
                        str(p.verified_exit),
                        str(p.premium),
                        p.country_code,
                        p.country_name,
                        getattr(p, "hosting", "unknown"),
                        getattr(p, "as_name", ""),
                        getattr(p, "org", ""),
                        str(getattr(p, "target_ok", False)),
                        getattr(p, "target_latency", 0.0),
                    ])
        except Exception as e:
            logger.warning("[!] Error writing CSV: %s", e)

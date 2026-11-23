import os
import time
import asyncio
import httpx
import maxminddb
import logging
from typing import Dict

logger = logging.getLogger(__name__)

GEO_DB_DIR = "./geoip"
GEO_DB_PATH = os.path.join(GEO_DB_DIR, "GeoLite2-Country.mmdb")
GEO_DB_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb"
STALE_DAYS = 30
MAX_DOWNLOAD_ATTEMPTS = 3


class GeoIPResolver:
    def __init__(self):
        self.reader = None

    @staticmethod
    def _is_stale(path: str) -> bool:
        """True when the DB is missing or older than STALE_DAYS."""
        try:
            age = time.time() - os.path.getmtime(path)
            return age > STALE_DAYS * 86400
        except OSError:
            return True

    async def ensure_db_downloaded(self) -> None:
        """
        Ensures a FRESH MaxMind database is available: refreshes stale copies
        (30 days) and retries failed downloads with backoff.
        """
        if os.path.exists(GEO_DB_PATH) and not self._is_stale(GEO_DB_PATH):
            logger.info("[+] GeoIP database is fresh (no download needed).")
            return

        logger.info("[*] Downloading MaxMind GeoLite2 Country database (offline lookup)...")
        os.makedirs(GEO_DB_DIR, exist_ok=True)
        tmp_path = GEO_DB_PATH + ".tmp"
        for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.get(GEO_DB_URL, follow_redirects=True)
                if resp.status_code == 200:
                    with open(tmp_path, "wb") as f:
                        f.write(resp.content)
                    os.replace(tmp_path, GEO_DB_PATH)
                    logger.info("[+] MaxMind GeoLite2 Country database downloaded successfully.")
                    return
                logger.warning("[!] Download failed with status code %s (attempt %d/%d).",
                               resp.status_code, attempt, MAX_DOWNLOAD_ATTEMPTS)
            except Exception as e:
                logger.warning("[!] Error downloading GeoIP database: %s (attempt %d/%d).",
                               e, attempt, MAX_DOWNLOAD_ATTEMPTS)
            if attempt < MAX_DOWNLOAD_ATTEMPTS:
                await asyncio.sleep(3)

        logger.warning("[!] GeoIP database unavailable; country lookups will report 'Unknown'.")

    def initialize_reader(self) -> None:
        """
        Initializes the MaxMind DB Reader.
        """
        if os.path.exists(GEO_DB_PATH):
            try:
                self.reader = maxminddb.open_database(GEO_DB_PATH)
                logger.info("[+] Offline GeoIP reader initialized.")
            except Exception as e:
                logger.warning("[!] Failed to parse GeoIP database: %s", e)

    def get_country_info(self, ip: str) -> Dict[str, str]:
        """
        Looks up country code and name for a given IP address.
        """
        result = {"country_code": "Unknown", "country_name": "Unknown"}
        if not self.reader:
            return result

        try:
            record = self.reader.get(ip)
            if record:
                country = record.get("country", {})
                result["country_code"] = country.get("iso_code", "Unknown")
                
                names = country.get("names", {})
                result["country_name"] = names.get("en", "Unknown")
        except Exception:
            pass
        return result

    def close(self) -> None:
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass

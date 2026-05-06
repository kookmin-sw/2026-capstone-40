"""Periodic scraping scheduler.

Reads URLs from a page list file, runs a full scrape cycle, records results
into per-domain manifests, and repeats at the configured interval.
"""

import logging
import time
from pathlib import Path

import schedule

from .config import ScraperConfig, SchedulerConfig
from .core import StealthScraper
from .storage import record_run, load_global_index, save_global_index

logger = logging.getLogger(__name__)


def load_page_list(path: str) -> list[str]:
    """Return non-empty, non-comment lines from *path*."""
    lines = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


class PeriodicScraper:
    def __init__(
        self,
        scheduler_config: SchedulerConfig,
        scraper_config: ScraperConfig,
    ):
        self.sched_cfg = scheduler_config
        self.scraper_cfg = scraper_config
        self.output_dir = Path(self.scraper_cfg.output_dir)

    def _run_cycle(self) -> None:
        page_list_path = self.sched_cfg.page_list_path
        try:
            urls = load_page_list(page_list_path)
        except FileNotFoundError:
            logger.error("page_list.txt not found: %s", page_list_path)
            return

        if not urls:
            logger.warning("Page list is empty — nothing to scrape.")
            return

        logger.info("Starting scrape cycle: %d URL(s)", len(urls))

        tracked_domains: list[str] = []
        for url in urls:
            logger.info("  Scraping: %s", url)
            scraper = StealthScraper(url, self.scraper_cfg)
            result = scraper.scrape()

            if result["status"] == "ok":
                logger.info(
                    "  OK  %s — assets: %d downloaded / %d found  [%s]",
                    result["domain"],
                    result.get("assets_downloaded", 0),
                    result.get("assets_found", 0),
                    result["timestamp"],
                )
            else:
                logger.warning(
                    "  ERR %s — %s", result.get("domain", url), result.get("error")
                )

            record_run(self.output_dir, result, self.sched_cfg.max_snapshots)
            tracked_domains.append(result["domain"])

            if self.sched_cfg.delay_between_urls > 0:
                time.sleep(self.sched_cfg.delay_between_urls)

        # Keep the top-level index up to date
        existing = load_global_index(self.output_dir).get("domains", [])
        save_global_index(self.output_dir, existing + tracked_domains)

        logger.info("Cycle complete.")

    def run_once(self) -> None:
        """Execute a single scrape cycle immediately."""
        self._run_cycle()

    def run_forever(self) -> None:
        """Run a cycle immediately, then repeat every `interval_minutes`."""
        interval = self.sched_cfg.interval_minutes
        logger.info(
            "Periodic scraper started — interval: %d min(s). Press Ctrl+C to stop.",
            interval,
        )
        self._run_cycle()
        schedule.every(interval).minutes.do(self._run_cycle)
        try:
            while True:
                schedule.run_pending()
                time.sleep(10)
        except KeyboardInterrupt:
            logger.info("Scraper stopped by user.")

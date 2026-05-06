import argparse
import logging

from src import PeriodicScraper, ScraperConfig, SchedulerConfig


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Periodic stealth web scraper. "
            "Reads URLs from page_list.txt and stores timestamped snapshots."
        )
    )
    parser.add_argument(
        "-l",
        "--page-list",
        default="page_list.txt",
        help="Path to the URL list file (default: page_list.txt)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scraped",
        help="Root output directory (default: scraped)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=60,
        help="Scrape interval in minutes (default: 60). Use 0 to run once and exit.",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=2.0,
        help="Delay between individual URL scrapes in seconds (default: 2.0)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30000,
        help="Page load timeout in ms (default: 30000)",
    )
    parser.add_argument(
        "-m",
        "--max-assets",
        type=int,
        default=50,
        help="Maximum assets to download per page (default: 50)",
    )
    parser.add_argument(
        "--max-snapshots",
        type=int,
        default=0,
        help="Keep at most N snapshots per domain; 0 keeps all (default: 0)",
    )
    parser.add_argument(
        "--user-agent",
        help="Custom user-agent string",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    scraper_config = ScraperConfig(
        output_dir=args.output,
        timeout=args.timeout,
        max_assets=args.max_assets,
    )
    if args.user_agent:
        scraper_config.user_agent = args.user_agent

    scheduler_config = SchedulerConfig(
        interval_minutes=args.interval,
        page_list_path=args.page_list,
        delay_between_urls=args.delay,
        max_snapshots=args.max_snapshots,
    )

    periodic = PeriodicScraper(scheduler_config, scraper_config)

    if args.interval == 0:
        periodic.run_once()
    else:
        periodic.run_forever()


if __name__ == "__main__":
    main()

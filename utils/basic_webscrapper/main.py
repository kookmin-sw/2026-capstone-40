import argparse

from src import StealthScraper, ScraperConfig


def main():
    parser = argparse.ArgumentParser(
        description="Stealth web scraper"
    )
    parser.add_argument("url", help="URL to scrape")
    parser.add_argument(
        "-o", "--output", default="scraped", help="Output directory (default: scraped)"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30000,
        help="Page timeout in ms (default: 30000)",
    )
    parser.add_argument(
        "-m",
        "--max-assets",
        type=int,
        default=50,
        help="Maximum assets to download (default: 50)",
    )
    parser.add_argument("--user-agent", help="Custom user agent string")

    parsed = parser.parse_args()

    scraper_config = ScraperConfig(
        output_dir=parsed.output,
        timeout=parsed.timeout,
        max_assets=parsed.max_assets,
    )
    if parsed.user_agent:
        scraper_config.user_agent = parsed.user_agent

    scraper = StealthScraper(parsed.url, scraper_config)
    scrape_result = scraper.scrape()

    print(f"Scraped: {scrape_result['domain']}")
    print(f"URL: {scrape_result['url']}")
    print(f"HTML: {scrape_result['html_path']}")
    print(f"Screenshot: {scrape_result['screenshot_path']}")
    print(f"Assets found: {scrape_result['assets_count']}")
    print(f"Output: {scrape_result['output_dir']}")


if __name__ == "__main__":
    main()

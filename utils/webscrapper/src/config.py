from dataclasses import dataclass, field


DEFAULT_HTTP_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

DEFAULT_BROWSER_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
]


@dataclass
class ScraperConfig:
    output_dir: str = "scraped"
    timeout: int = 30000
    max_assets: int = 50
    viewport_width: int = 1920
    viewport_height: int = 1080
    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    locale: str = "en-US"
    timezone_id: str = "America/New_York"
    extra_headers: dict = field(default_factory=lambda: dict(DEFAULT_HTTP_HEADERS))
    browser_args: list = field(default_factory=lambda: list(DEFAULT_BROWSER_ARGS))
    stealth_script: str = """
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });
        window.chrome = { runtime: {} };
        delete navigator.cdc_Asd5DqpdA;
    """


@dataclass
class SchedulerConfig:
    # How often to run the full scrape cycle (in minutes). 0 = run once and exit.
    interval_minutes: int = 60
    # Path to the file containing one URL per line.
    page_list_path: str = "page_list.txt"
    # Delay between individual URL scrapes in a single cycle (seconds).
    delay_between_urls: float = 2.0
    # Keep at most N snapshots per domain (0 = keep all).
    max_snapshots: int = 0

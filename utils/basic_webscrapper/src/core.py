from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import Optional

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext

from .config import ScraperConfig

ASSET_SELECTORS = [("link", "href"), ("script", "src"), ("img", "src")]


class StealthScraper:
    def __init__(self, url: str, config: Optional[ScraperConfig] = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.config = config or ScraperConfig()
        self.domain = urlparse(self.url).netloc
        self.output_dir = Path(self.config.output_dir)
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.context: Optional[BrowserContext] = None
        self.playwright = None

    def _launch_browser(self):
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=True,
            args=self.config.browser_args,
        )
        self.context = self.browser.new_context(
            viewport={
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            user_agent=self.config.user_agent,
            locale=self.config.locale,
            timezone_id=self.config.timezone_id,
            permissions=["geolocation", "notifications"],
            extra_http_headers=self.config.extra_headers,
        )
        self.context.add_init_script(self.config.stealth_script)
        self.page = self.context.new_page()
        self.page.set_default_timeout(self.config.timeout)

    def _shutdown_browser(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def _fetch_page_html(self) -> str:
        page_response = self.page.goto(self.url, wait_until="networkidle")
        if page_response and page_response.status >= 400:
            raise RuntimeError(f"HTTP error: {page_response.status}")
        return self.page.content()

    @staticmethod
    def extract_assets(html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        asset_urls = set()
        for tag_name, url_attribute in ASSET_SELECTORS:
            for element in soup.find_all(tag_name):
                raw_url = element.get(url_attribute)
                if not raw_url or raw_url.startswith("data:"):
                    continue
                if not raw_url.startswith("http"):
                    raw_url = urljoin(base_url, raw_url)
                if raw_url.startswith("http"):
                    asset_urls.add(raw_url)
        return list(asset_urls)

    def _save_screenshot(self, path: str):
        self.page.screenshot(path=path, full_page=True)

    def _download_asset(self, asset_url: str, save_path: Path) -> bool:
        try:
            response = self.browser.new_context().request.get(asset_url)
            if response.status == 200:
                save_path.write_bytes(response.body())
                return True
        except Exception:
            pass
        return False

    def scrape(self) -> dict:
        self._launch_browser()
        try:
            domain_folder = self.output_dir / self.domain.replace(".", "_")
            domain_folder.mkdir(parents=True, exist_ok=True)

            page_html = self._fetch_page_html()
            html_file_path = domain_folder / "index.html"
            html_file_path.write_text(page_html)

            screenshot_path = domain_folder / "screenshot.png"
            self._save_screenshot(str(screenshot_path))

            discovered_assets = self.extract_assets(page_html, self.url)
            assets_folder = domain_folder / "assets"
            assets_folder.mkdir(exist_ok=True)

            max_to_download = self.config.max_assets
            for index, asset_url in enumerate(discovered_assets[:max_to_download]):
                file_extension = Path(urlparse(asset_url).path).suffix or ".bin"
                asset_file_path = assets_folder / f"asset_{index}{file_extension}"
                self._download_asset(asset_url, asset_file_path)

            return {
                "domain": self.domain,
                "url": self.url,
                "html_path": str(html_file_path),
                "screenshot_path": str(screenshot_path),
                "assets_count": len(discovered_assets),
                "output_dir": str(domain_folder),
            }
        finally:
            self._shutdown_browser()

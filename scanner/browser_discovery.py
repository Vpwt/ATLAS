"""Playwright-powered browser API discovery."""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from scanner.models import Endpoint


async def discover_endpoints_with_playwright(
    start_url: str,
    capture_seconds: int = 60,
    include_third_party: bool = False,
) -> list[Endpoint]:
    """Open a browser for manual login/navigation and capture API requests.

    This is intentionally interactive: operator logs in and clicks through the
    target app while requests are observed and converted into Endpoint objects.
    """
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        raise RuntimeError(
            "Playwright is not installed. Install with: pip install playwright; playwright install"
        ) from e

    endpoints: dict[tuple[str, str], Endpoint] = {}
    start_host = urlsplit(start_url).netloc.lower()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        def on_request(req):
            url = req.url
            method = (req.method or "GET").upper()
            parsed = urlsplit(url)
            host = parsed.netloc.lower()
            if not include_third_party and host != start_host:
                return
            if parsed.scheme not in {"http", "https"}:
                return
            path = parsed.path or "/"
            key = (method, path)
            if key not in endpoints:
                endpoints[key] = Endpoint(
                    path=path,
                    method=method,
                    auth_required=True,
                    description="Captured from browser traffic",
                )

        page.on("request", on_request)
        await page.goto(start_url)
        print(f"Browser discovery started at {start_url}. Interact with the app for {capture_seconds} seconds...")
        await asyncio.sleep(max(5, capture_seconds))
        await browser.close()

    return sorted(endpoints.values(), key=lambda e: (e.path, e.method))

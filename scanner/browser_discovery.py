"""Playwright-powered browser API discovery."""
from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urlsplit

from scanner.models import Endpoint


async def discover_endpoints_with_playwright(
    start_url: str,
    capture_seconds: int = 60,
    include_third_party: bool = False,
    autonomous: bool = False,
    max_pages: int = 20,
    max_clicks_per_page: int = 6,
    login_url: str | None = None,
    username: str = "",
    password: str = "",
    username_selector: str = "",
    password_selector: str = "",
    submit_selector: str = "",
) -> list[Endpoint]:
    """Open a browser for manual login/navigation and capture API requests.

    Supports both manual exploration and an autonomous bounded crawler mode.
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

        context.on("request", on_request)

        if login_url and username and password and username_selector and password_selector and submit_selector:
            await _perform_login(
                page,
                login_url,
                username,
                password,
                username_selector,
                password_selector,
                submit_selector,
            )

        await page.goto(start_url)

        if autonomous:
            print(
                f"Autonomous browser discovery started at {start_url} "
                f"(max_pages={max_pages}, max_clicks_per_page={max_clicks_per_page})"
            )
            await _crawl_site(page, start_url, max_pages=max_pages, max_clicks_per_page=max_clicks_per_page)
        else:
            print(f"Browser discovery started at {start_url}. Interact with the app for {capture_seconds} seconds...")
            await asyncio.sleep(max(5, capture_seconds))

        await browser.close()

    return sorted(endpoints.values(), key=lambda e: (e.path, e.method))


async def _perform_login(
    page,
    login_url: str,
    username: str,
    password: str,
    username_selector: str,
    password_selector: str,
    submit_selector: str,
):
    await page.goto(login_url)
    await page.fill(username_selector, username)
    await page.fill(password_selector, password)
    await page.click(submit_selector)
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass


async def _crawl_site(page, start_url: str, max_pages: int = 20, max_clicks_per_page: int = 6):
    start_host = urlsplit(start_url).netloc.lower()
    visited: set[str] = set()
    queue: deque[str] = deque([start_url])

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(600)
        except Exception:
            continue

        # Collect same-origin anchor targets for bounded BFS.
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "nodes => nodes.map(n => n.href).filter(Boolean)",
            )
        except Exception:
            hrefs = []

        for href in hrefs:
            parsed = urlsplit(href)
            if parsed.netloc.lower() != start_host:
                continue
            if href not in visited and href not in queue and len(queue) + len(visited) < max_pages * 3:
                queue.append(href)

        # Trigger lazy XHR/fetch calls via bounded click interactions.
        click_selectors = [
            "button",
            "[role='button']",
            "a[href]",
            "input[type='submit']",
        ]
        clicks_done = 0
        for sel in click_selectors:
            if clicks_done >= max_clicks_per_page:
                break
            try:
                count = await page.locator(sel).count()
            except Exception:
                count = 0
            for i in range(min(count, max_clicks_per_page - clicks_done)):
                try:
                    locator = page.locator(sel).nth(i)
                    await locator.scroll_into_view_if_needed(timeout=1000)
                    await locator.click(timeout=1200)
                    await page.wait_for_timeout(300)
                    clicks_done += 1
                except Exception:
                    continue

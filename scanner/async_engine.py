"""Async orchestration helpers for running checks concurrently."""
from __future__ import annotations

import asyncio
from typing import Callable, Dict, List

from scanner.models import Finding


async def run_checks_async(
    checks_to_run: List[str],
    check_registry: Dict[str, Callable],
    run_one_check_sync: Callable[[str], List[Finding]],
    concurrency: int = 4,
) -> List[Finding]:
    """Run synchronous check functions concurrently using asyncio threads.

    This preserves compatibility with existing check modules while enabling
    much faster wall-clock scans for large endpoint sets.
    """
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _run(check_name: str) -> List[Finding]:
        if check_name not in check_registry:
            return []
        async with semaphore:
            return await asyncio.to_thread(run_one_check_sync, check_name)

    tasks = [asyncio.create_task(_run(name)) for name in checks_to_run]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: List[Finding] = []
    for result in results:
        if isinstance(result, Exception):
            continue
        findings.extend(result)
    return findings

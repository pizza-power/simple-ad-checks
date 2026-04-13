#!/usr/bin/env python3
"""
adchecker — BloodHound CE security report generator.

Config-driven (via .env), designed for unattended/cron execution.
Generates one self-contained HTML report per configured domain.
"""

from __future__ import annotations

import sys
import time

import config
from bhapi.client import BHSession
from checks import get_all_checks, CheckResult
from report.renderer import write_report


def _log(msg: str) -> None:
    print(f"[adchecker] {msg}", flush=True)


def run_domain(session: BHSession, domain: str) -> list[CheckResult]:
    """Execute every registered check against a single domain."""
    checks = get_all_checks()
    results: list[CheckResult] = []

    for check in checks:
        _log(f"  Running: {check.title} ...")
        t0 = time.monotonic()
        try:
            result = check.run(
                session,
                domain,
                large_group_threshold=config.BH_LARGE_GROUP_THRESHOLD,
            )
        except Exception as exc:
            _log(f"  ERROR in {check.check_id}: {exc}")
            result = CheckResult(
                check_id=check.check_id,
                title=check.title,
                description=check.description,
                headers=["Error"],
                rows=[[str(exc)]],
                severity="info",
            )
        elapsed = time.monotonic() - t0
        _log(f"  Done: {check.title} — {result.count} findings ({elapsed:.1f}s)")
        results.append(result)

    return results


def main() -> None:
    _log(f"Starting — {len(config.BH_DOMAINS)} domain(s) configured")
    _log(f"BloodHound CE: {config.BH_BASE_URL}")

    session = BHSession(
        base_url=config.BH_BASE_URL,
        token_id=config.BH_TOKEN_ID,
        token_key=config.BH_TOKEN_KEY,
    )

    for domain in config.BH_DOMAINS:
        _log(f"Processing domain: {domain}")
        results = run_domain(session, domain)
        path = write_report(domain, results, config.BH_REPORT_DIR)
        _log(f"Report written: {path}")

    _log("All domains complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _log("Interrupted.")
        sys.exit(130)
    except Exception as exc:
        _log(f"Fatal error: {exc}")
        sys.exit(1)

#!/usr/bin/env python3
"""
adchecker — BloodHound CE security report generator.

Config-driven (via .env), designed for unattended/cron execution.
Generates one self-contained HTML report per configured domain.
"""

from __future__ import annotations

import logging
import sys
import time

import config
from bhapi.client import BHSession
from checks import get_all_checks, CheckResult
from report.renderer import write_report

log = logging.getLogger("adchecker")


def _setup_logging() -> None:
    fmt = "[%(asctime)s] %(levelname)-7s %(name)s — %(message)s"
    logging.basicConfig(
        level=logging.DEBUG,
        format=fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    # Quiet down noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def run_domain(session: BHSession, domain: str) -> list[CheckResult]:
    """Execute every registered check against a single domain."""
    checks = get_all_checks()
    results: list[CheckResult] = []

    for check in checks:
        log.info("  Running check: %s ...", check.title)
        t0 = time.monotonic()
        try:
            result = check.run(
                session,
                domain,
                large_group_threshold=config.BH_LARGE_GROUP_THRESHOLD,
            )
        except Exception as exc:
            log.error("  FAILED: %s — %s", check.check_id, exc, exc_info=True)
            result = CheckResult(
                check_id=check.check_id,
                title=check.title,
                description=check.description,
                headers=["Error"],
                rows=[[str(exc)]],
                severity="info",
            )
        elapsed = time.monotonic() - t0
        log.info(
            "  Done: %s — %d finding(s) [%s] (%.1fs)",
            check.title, result.count, result.severity, elapsed,
        )
        results.append(result)

    return results


def main() -> None:
    _setup_logging()

    log.info("=" * 60)
    log.info("adchecker starting")
    log.info("=" * 60)
    log.info("Domains configured: %s", ", ".join(config.BH_DOMAINS))
    log.info("BloodHound CE URL:  %s", config.BH_BASE_URL)
    log.info("Report output dir:  %s", config.BH_REPORT_DIR)
    log.info("Large group threshold: %d", config.BH_LARGE_GROUP_THRESHOLD)

    session = BHSession(
        base_url=config.BH_BASE_URL,
        token_id=config.BH_TOKEN_ID,
        token_key=config.BH_TOKEN_KEY,
    )

    # Pre-flight: verify we can talk to the API and authenticate
    log.info("-" * 60)
    log.info("Pre-flight connectivity check ...")
    try:
        who = session.test_connection()
        log.info("Authenticated OK.")
    except ConnectionError as exc:
        log.error("CONNECTION FAILED:\n%s", exc)
        sys.exit(1)

    log.info("-" * 60)
    for domain in config.BH_DOMAINS:
        log.info("Processing domain: %s", domain)
        results = run_domain(session, domain)

        total = sum(r.count for r in results)
        log.info("Domain %s complete — %d total findings", domain, total)

        path = write_report(domain, results, config.BH_REPORT_DIR)
        log.info("Report written: %s", path)
        log.info("-" * 60)

    log.info("All domains complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(130)
    except Exception as exc:
        logging.getLogger("adchecker").error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)

#!/usr/bin/env python3
"""
upload.py — Upload SharpHound/BloodHound zip files to BloodHound CE.

Scans BH_UPLOAD_DIR (default ./data/) for .zip files and uploads each
one via the BloodHound CE file-upload API.  Results are appended to a
log file in the upload directory so you have a record of what was sent.

Usage:
    python upload.py
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import config
from bhapi.client import BHSession

log = logging.getLogger("adchecker.upload")

UPLOAD_LOG_NAME = "upload_history.log"
POLL_INTERVAL = 5  # seconds between status checks
POLL_TIMEOUT = 600  # give up after 10 minutes


def _setup_logging() -> None:
    fmt = "[%(asctime)s] %(levelname)-7s %(name)s — %(message)s"
    logging.basicConfig(
        level=logging.DEBUG,
        format=fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _append_upload_log(upload_dir: Path, filename: str, status: str) -> None:
    """Append a line to the upload history log."""
    log_path = upload_dir / UPLOAD_LOG_NAME
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a") as f:
        f.write(f"{ts}  {status:<20s}  {filename}\n")


def _wait_for_ingestion(session: BHSession, job_id: int) -> str:
    """Poll until the upload job reaches a terminal state. Returns status label."""
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        info = session.get_upload_status(job_id)
        code = info.get("status", -1)
        label = session.UPLOAD_STATUS_LABELS.get(code, f"Unknown({code})")

        if code in (2, 8):  # Complete or Partially Complete
            return label
        if code in (-1, 3, 4, 5):  # Invalid, Canceled, Timed Out, Failed
            msg = info.get("status_message", "")
            log.warning("Job %d ended with status: %s — %s", job_id, label, msg)
            return label

        log.info("  Job %d status: %s — waiting ...", job_id, label)
        time.sleep(POLL_INTERVAL)

    log.warning("Timed out waiting for job %d after %ds", job_id, POLL_TIMEOUT)
    return "Timeout (local)"


def upload_one(session: BHSession, zip_path: Path, upload_dir: Path) -> bool:
    """Upload a single zip file. Returns True on success."""
    filename = zip_path.name
    log.info("Starting upload job for %s ...", filename)

    try:
        job_id = session.start_upload()
        log.info("Upload job created: %d", job_id)

        session.upload_file(job_id, str(zip_path))
        log.info("File sent, ending upload job ...")

        session.end_upload(job_id)
        log.info("Waiting for BloodHound to process %s ...", filename)

        status = _wait_for_ingestion(session, job_id)
        log.info("Job %d finished: %s", job_id, status)

        _append_upload_log(upload_dir, filename, status)
        return status in ("Complete", "Partially Complete")

    except Exception as exc:
        log.error("Upload failed for %s — %s", filename, exc, exc_info=True)
        _append_upload_log(upload_dir, filename, f"ERROR: {exc}")
        return False


def main() -> None:
    _setup_logging()

    upload_dir = config.BH_UPLOAD_DIR
    log.info("=" * 60)
    log.info("adchecker upload")
    log.info("=" * 60)
    log.info("Upload directory:   %s", upload_dir.resolve())
    log.info("BloodHound CE URL:  %s", config.BH_BASE_URL)

    if not upload_dir.is_dir():
        log.error("Upload directory does not exist: %s", upload_dir)
        log.error("Create it and drop your SharpHound .zip files inside.")
        sys.exit(1)

    zip_files = sorted(upload_dir.glob("*.zip"))
    if not zip_files:
        log.info("No .zip files found in %s — nothing to upload.", upload_dir)
        sys.exit(0)

    log.info("Found %d zip file(s): %s", len(zip_files), ", ".join(f.name for f in zip_files))

    session = BHSession(
        base_url=config.BH_BASE_URL,
        token_id=config.BH_TOKEN_ID,
        token_key=config.BH_TOKEN_KEY,
    )

    log.info("-" * 60)
    log.info("Pre-flight connectivity check ...")
    try:
        session.test_connection()
    except ConnectionError as exc:
        log.error("CONNECTION FAILED:\n%s", exc)
        sys.exit(1)

    log.info("-" * 60)
    succeeded = 0
    failed = 0

    for zip_path in zip_files:
        log.info("-" * 60)
        if upload_one(session, zip_path, upload_dir):
            succeeded += 1
        else:
            failed += 1

    log.info("=" * 60)
    log.info(
        "Upload complete — %d succeeded, %d failed out of %d file(s).",
        succeeded, failed, len(zip_files),
    )
    log.info("Upload log: %s", (upload_dir / UPLOAD_LOG_NAME).resolve())

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(130)
    except Exception as exc:
        logging.getLogger("adchecker.upload").error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)

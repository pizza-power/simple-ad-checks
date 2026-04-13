"""
Configuration loader. Reads all settings from .env file — no CLI flags.
Designed for headless/cron usage.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _require(var: str) -> str:
    val = os.getenv(var)
    if not val:
        print(f"[ERROR] Missing required environment variable: {var}", file=sys.stderr)
        print(f"        Copy .env.example to .env and fill it in.", file=sys.stderr)
        sys.exit(1)
    return val


BH_BASE_URL: str = _require("BH_BASE_URL").rstrip("/")
BH_TOKEN_ID: str = _require("BH_TOKEN_ID")
BH_TOKEN_KEY: str = _require("BH_TOKEN_KEY")

BH_DOMAINS: list[str] = [
    d.strip().upper() for d in _require("BH_DOMAINS").split(",") if d.strip()
]

BH_REPORT_DIR: Path = Path(os.getenv("BH_REPORT_DIR", "./reports"))
BH_LARGE_GROUP_THRESHOLD: int = int(os.getenv("BH_LARGE_GROUP_THRESHOLD", "300"))

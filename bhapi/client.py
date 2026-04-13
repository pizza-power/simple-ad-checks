"""
BloodHound CE API client with HMAC signed-request authentication.

Based on the official SpecterOps reference implementation:
https://github.com/SpecterOps/bloodhound-docs/blob/main/docs/assets/apiclient.py
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any, Optional
from urllib.parse import quote, urlencode

import requests

log = logging.getLogger("adchecker.api")


class BHAPIError(Exception):
    """Raised when the BloodHound API returns a non-success response."""

    def __init__(self, method: str, url: str, status: int, body: str):
        self.method = method
        self.url = url
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status} {method} {url} — {body[:300]}")


def _clean_base_url(url: str) -> str:
    """
    Normalise the base URL so it points to the API root.
    Strips trailing slashes and common UI paths that users
    might copy from their browser address bar.
    """
    url = url.strip().rstrip("/")
    url = re.sub(r"/ui(/login)?/?$", "", url)
    url = re.sub(r"/#.*$", "", url)
    return url


class BHSession:
    """Authenticated session against a BloodHound CE instance."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2  # seconds, doubles each retry

    def __init__(self, base_url: str, token_id: str, token_key: str):
        self._base_url = _clean_base_url(base_url)
        self._token_id = token_id
        self._token_key = token_key
        self._http = requests.Session()
        log.info("API base URL: %s", self._base_url)

    # ------------------------------------------------------------------
    # Connectivity check
    # ------------------------------------------------------------------

    def test_connection(self) -> dict:
        """
        Hit the API self endpoint to verify connectivity and auth.
        Returns the user info dict on success, raises on failure.
        """
        log.info("Testing connection to %s ...", self._base_url)

        try:
            result = self.get("/api/v2/self")
            log.info("Authenticated successfully.")
            return result
        except BHAPIError as exc:
            if exc.status == 401:
                raise ConnectionError(
                    f"Authentication failed (HTTP 401). Check BH_TOKEN_ID and BH_TOKEN_KEY.\n"
                    f"  URL: {exc.url}\n  Response: {exc.body[:200]}"
                ) from exc
            raise ConnectionError(
                f"API returned HTTP {exc.status}. Is BH_BASE_URL correct?\n"
                f"  Tried: {exc.url}\n"
                f"  Response: {exc.body[:200]}\n"
                f"  Hint: BH_BASE_URL should be the root (e.g. http://host:8080), "
                f"not the login page."
            ) from exc
        except requests.ConnectionError as exc:
            raise ConnectionError(
                f"Cannot connect to {self._base_url}. Is the server running?\n"
                f"  Error: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get(self, uri: str, params: dict | None = None, timeout: int = 120) -> Any:
        # Match the official SpecterOps client pattern: bake query params
        # directly into the URI so the HMAC signature covers them exactly.
        if params:
            qs = urlencode(params)
            uri = f"{uri}?{qs}"
        return self._request("GET", uri, timeout=timeout)

    def post(self, uri: str, body: dict | None = None, timeout: int = 120) -> Any:
        return self._request("POST", uri, body=body, timeout=timeout)

    def cypher(self, query: str, include_properties: bool = True) -> dict:
        """Run a Cypher query and return the parsed JSON response."""
        log.debug("Cypher query: %s", query.strip()[:120])
        payload = {"query": query, "include_properties": include_properties}
        return self.post("/api/v2/graphs/cypher", body=payload)

    def search(self, query: str, search_type: str = "exact") -> dict:
        """Search the graph for a node by name."""
        return self.get("/api/v2/graph-search", params={"query": query, "type": search_type})

    def get_domains(self) -> list[dict]:
        """List available domains from the API."""
        return self.get("/api/v2/available-domains")

    def paginate(self, uri: str, page_size: int = 100) -> list[dict]:
        """Auto-paginate a list endpoint, returning all items."""
        items: list[dict] = []
        skip = 0
        while True:
            resp = self.get(uri, params={"skip": str(skip), "limit": str(page_size), "type": "list"})
            data = resp.get("data", [])
            items.extend(data)
            total = resp.get("count", 0)
            skip += page_size
            if skip >= total or not data:
                break
        return items

    # ------------------------------------------------------------------
    # HMAC request signing (per SpecterOps spec)
    # ------------------------------------------------------------------

    def _sign(self, method: str, uri: str, body: Optional[bytes]) -> tuple[dict[str, str], str]:
        """
        Sign a request per the BloodHound HMAC spec.
        Returns (headers_dict, datetime_formatted).

        The ``uri`` MUST include the query string if present, matching
        exactly what appears in the HTTP request line.
        """
        digester = hmac.new(self._token_key.encode(), None, hashlib.sha256)

        # OperationKey: method + URI (including query string)
        digester.update(f"{method}{uri}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey: RFC-3339 datetime truncated to the hour
        now = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(now[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing
        if body is not None:
            digester.update(body)

        headers = {
            "User-Agent": "adchecker/1.0",
            "Authorization": f"bhesignature {self._token_id}",
            "RequestDate": now,
            "Signature": base64.b64encode(digester.digest()),
            "Content-Type": "application/json",
        }
        return headers, now

    def _request(
        self,
        method: str,
        uri: str,
        body: dict | None = None,
        timeout: int = 120,
    ) -> Any:
        """
        Execute a signed request.  Query parameters must already be
        baked into ``uri`` (e.g. ``/api/v2/foo?bar=1``).  This matches
        the official SpecterOps client pattern and guarantees the HMAC
        signature covers the exact URI sent on the wire.
        """
        encoded_body = json.dumps(body).encode() if body else None
        url = f"{self._base_url}{uri}"
        backoff = self.RETRY_BACKOFF

        for attempt in range(1, self.MAX_RETRIES + 1):
            headers, _ = self._sign(method, uri, encoded_body)
            log.debug("%s %s (attempt %d/%d)", method, url, attempt, self.MAX_RETRIES)

            try:
                resp = self._http.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=encoded_body,
                    timeout=timeout,
                )
            except requests.ConnectionError as exc:
                log.error("Connection failed: %s %s — %s", method, url, exc)
                raise

            log.debug("Response: HTTP %d (%d bytes)", resp.status_code, len(resp.content))

            if resp.status_code == 429:
                if attempt < self.MAX_RETRIES:
                    log.warning("Rate limited (429), retrying in %ds ...", backoff)
                    time.sleep(backoff)
                    backoff *= 2
                    continue

            if resp.status_code >= 400:
                log.error(
                    "API error: HTTP %d %s %s — %s",
                    resp.status_code, method, url, resp.text[:300],
                )
                raise BHAPIError(method, url, resp.status_code, resp.text)

            try:
                data = resp.json()
            except ValueError:
                log.error("Non-JSON response from %s %s: %s", method, url, resp.text[:200])
                raise BHAPIError(method, url, resp.status_code, f"Non-JSON response: {resp.text[:200]}")

            return data.get("data", data)

        return {}

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
import time
from typing import Any, Optional

import requests


class BHSession:
    """Authenticated session against a BloodHound CE instance."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2  # seconds, doubles each retry

    def __init__(self, base_url: str, token_id: str, token_key: str):
        self._base_url = base_url
        self._token_id = token_id
        self._token_key = token_key
        self._http = requests.Session()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get(self, uri: str, params: dict | None = None, timeout: int = 120) -> Any:
        return self._request("GET", uri, params=params, timeout=timeout)

    def post(self, uri: str, body: dict | None = None, timeout: int = 120) -> Any:
        return self._request("POST", uri, body=body, timeout=timeout)

    def cypher(self, query: str, include_properties: bool = True) -> dict:
        """Run a Cypher query and return the parsed JSON response."""
        payload = {"query": query, "include_properties": include_properties}
        return self.post("/api/v2/graphs/cypher", body=payload)

    def search(self, query: str, search_type: str = "exact") -> dict:
        """Search the graph for a node by name."""
        return self.get("/api/v2/graph-search", params={"query": query, "type": search_type})

    def paginate(self, uri: str, page_size: int = 100) -> list[dict]:
        """Auto-paginate a list endpoint, returning all items."""
        items: list[dict] = []
        skip = 0
        while True:
            resp = self.get(uri, params={"skip": skip, "limit": page_size, "type": "list"})
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

    def _sign(self, method: str, uri: str, body: Optional[bytes]) -> dict[str, str]:
        digester = hmac.new(self._token_key.encode(), None, hashlib.sha256)

        # OperationKey: method + URI
        digester.update(f"{method}{uri}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey: RFC-3339 datetime truncated to the hour
        now = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(now[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing
        if body:
            digester.update(body)

        return {
            "User-Agent": "adchecker/1.0",
            "Authorization": f"bhesignature {self._token_id}",
            "RequestDate": now,
            "Signature": base64.b64encode(digester.digest()).decode(),
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        uri: str,
        body: dict | None = None,
        params: dict | None = None,
        timeout: int = 120,
    ) -> Any:
        encoded_body = json.dumps(body).encode() if body else None
        headers = self._sign(method, uri, encoded_body)

        url = f"{self._base_url}{uri}"
        backoff = self.RETRY_BACKOFF

        for attempt in range(1, self.MAX_RETRIES + 1):
            resp = self._http.request(
                method=method,
                url=url,
                headers=headers,
                data=encoded_body,
                params=params,
                timeout=timeout,
            )

            if resp.status_code == 429:
                if attempt < self.MAX_RETRIES:
                    time.sleep(backoff)
                    backoff *= 2
                    headers = self._sign(method, uri, encoded_body)
                    continue
                resp.raise_for_status()

            resp.raise_for_status()
            return resp.json().get("data", resp.json())

        return {}

"""
AS-REP Roastable Users check.

Finds all user accounts that do not require Kerberos pre-authentication,
making them vulnerable to offline AS-REP cracking.
"""

from __future__ import annotations

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

_CYPHER = """
MATCH (u:User {{domain: "{domain}"}})
WHERE u.dontreqpreauth = true
  AND u.enabled = true
RETURN u.name        AS name,
       u.description AS description
ORDER BY u.name
"""


@register
class ASREPRoastableCheck(BaseCheck):
    check_id = "asrep_roastable"
    title = "AS-REP Roastable Users"
    description = (
        "User accounts that do not require Kerberos pre-authentication. "
        "An attacker can request an AS-REP for these accounts without "
        "credentials and crack the response offline."
    )

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        query = _CYPHER.format(domain=domain)
        rows: list[list[str]] = []

        try:
            result = session.cypher(query)
        except Exception as exc:
            return CheckResult(
                check_id=self.check_id,
                title=self.title,
                description=self.description,
                headers=["User", "Description"],
                rows=[["ERROR", str(exc)]],
                severity="info",
            )

        nodes = result.get("nodes", {})
        for node_id, node in nodes.items():
            props = node.get("properties", {}) or {}
            kinds = node.get("kinds", [])
            if "User" not in kinds:
                continue
            name = props.get("name", node.get("label", node_id))
            desc = props.get("description", "") or ""
            rows.append([name, desc])

        rows.sort(key=lambda r: r[0])

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["User", "Description"],
            rows=rows,
            severity="high" if rows else "info",
        )

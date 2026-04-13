"""
Kerberoastable Users check.

Finds all enabled user accounts with a Service Principal Name (SPN) set,
making them vulnerable to offline Kerberos ticket cracking.
"""

from __future__ import annotations

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

_CYPHER = """
MATCH (u:User {{domain: "{domain}"}})
WHERE u.hasspn = true
  AND u.enabled = true
RETURN u.name        AS name,
       u.description AS description,
       u.admincount  AS admin_count
ORDER BY u.name
"""


@register
class KerberoastableCheck(BaseCheck):
    check_id = "kerberoastable"
    title = "Kerberoastable Users"
    description = (
        "User accounts with a Service Principal Name (SPN) set. "
        "These accounts are vulnerable to offline password cracking "
        "via Kerberoasting. Prioritise accounts with admincount=true."
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
                headers=["User", "Description", "Admin Count"],
                rows=[["ERROR", str(exc), ""]],
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
            admin = "Yes" if props.get("admincount") else "No"
            rows.append([name, desc, admin])

        rows.sort(key=lambda r: (r[2] != "Yes", r[0]))

        severity = "info"
        if rows:
            severity = "medium"
            if any(r[2] == "Yes" for r in rows):
                severity = "high"

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["User", "Description", "Admin Count"],
            rows=rows,
            severity=severity,
        )

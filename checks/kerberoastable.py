"""
Kerberoastable Users check.

Finds all enabled user accounts with a Service Principal Name (SPN) set,
making them vulnerable to offline Kerberos ticket cracking.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register, is_tier_zero
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.kerberoastable")

# Return full node so results land in 'nodes' dict with all properties.
_CYPHER = 'MATCH (u:User {{domain: "{domain}"}}) WHERE u.hasspn = true AND u.enabled = true RETURN u'


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
        log.info("Querying kerberoastable users for domain: %s", domain)

        try:
            result = session.cypher(query)
        except Exception as exc:
            log.error("Cypher query failed: %s", exc)
            return CheckResult(
                check_id=self.check_id,
                title=self.title,
                description=self.description,
                headers=["User", "Description", "Admin Count"],
                rows=[["ERROR", str(exc), ""]],
                severity="info",
            )

        nodes = result.get("nodes", {})
        log.info("  %d nodes returned", len(nodes))

        tier_zero: list[bool] = []
        for node_id, node in nodes.items():
            props = node.get("properties", {}) or {}
            name = props.get("name", node.get("label", node_id))
            desc = props.get("description", "") or ""
            admin = "Yes" if props.get("admincount") else "No"
            rows.append([name, desc, admin])
            tier_zero.append(is_tier_zero(props))

        paired = sorted(
            zip(rows, tier_zero),
            key=lambda p: (p[0][2] != "Yes", p[0][0]),
        )
        rows = [p[0] for p in paired]
        tier_zero = [p[1] for p in paired]

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
            extra={"tier_zero": tier_zero},
        )

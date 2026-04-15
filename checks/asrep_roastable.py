"""
AS-REP Roastable Users check.

Finds all user accounts that do not require Kerberos pre-authentication,
making them vulnerable to offline AS-REP cracking.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register, is_tier_zero
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.asrep_roastable")

# Return full node so results land in 'nodes' dict.
_CYPHER = 'MATCH (u:User {{domain: "{domain}"}}) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u'


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
        log.info("Querying AS-REP roastable users for domain: %s", domain)

        try:
            result = session.cypher(query)
        except Exception as exc:
            log.error("Cypher query failed: %s", exc)
            return CheckResult(
                check_id=self.check_id,
                title=self.title,
                description=self.description,
                headers=["User", "Description"],
                rows=[["ERROR", str(exc)]],
                severity="info",
            )

        nodes = result.get("nodes", {})
        log.info("  %d nodes returned", len(nodes))

        tier_zero: list[bool] = []
        for node_id, node in nodes.items():
            props = node.get("properties", {}) or {}
            name = props.get("name", node.get("label", node_id))
            desc = props.get("description", "") or ""
            rows.append([name, desc])
            tier_zero.append(is_tier_zero(props))

        paired = sorted(zip(rows, tier_zero), key=lambda p: p[0][0])
        rows = [p[0] for p in paired]
        tier_zero = [p[1] for p in paired]

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["User", "Description"],
            rows=rows,
            severity="high" if rows else "info",
            extra={"tier_zero": tier_zero},
        )

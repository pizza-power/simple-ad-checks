"""
Large Groups with Admin Rights check.

Finds groups whose membership exceeds a configurable threshold that also
hold local-admin rights on computers.  Large groups with admin rights
dramatically widen the attack surface.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.large_group_admin")

_CYPHER = """
MATCH (g:Group {{domain: "{domain}"}})-[:AdminTo]->(c:Computer)
WITH g, count(DISTINCT c) AS admin_to_count
MATCH (g)<-[:MemberOf*1..]-(m)
WITH g, admin_to_count, count(DISTINCT m) AS member_count
WHERE member_count >= {threshold}
RETURN g.name         AS group_name,
       g.description  AS description,
       member_count,
       admin_to_count
ORDER BY member_count DESC
"""


@register
class LargeGroupAdminCheck(BaseCheck):
    check_id = "large_group_admin"
    title = "Large Groups with Admin Rights"
    description = (
        "Groups with a large membership that hold local administrator "
        "rights on one or more computers. This means hundreds of users "
        "potentially have admin access, dramatically increasing risk."
    )

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        threshold = kwargs.get("large_group_threshold", 300)
        query = _CYPHER.format(domain=domain, threshold=threshold)
        rows: list[list[str]] = []
        log.info("Querying large groups (>=%d members) with admin rights for: %s", threshold, domain)

        try:
            result = session.cypher(query)
        except Exception as exc:
            log.error("Cypher query failed: %s", exc)
            return CheckResult(
                check_id=self.check_id,
                title=self.title,
                description=self.description,
                headers=["Group", "Description", "Members", "Admin On # Computers"],
                rows=[["ERROR", str(exc), "", ""]],
                severity="info",
            )

        nodes = result.get("nodes", {})
        literals = result.get("literals", [])

        if literals:
            for row_data in literals:
                val = row_data.get("value") if isinstance(row_data, dict) else None
                if isinstance(val, dict):
                    rows.append([
                        str(val.get("group_name", "")),
                        str(val.get("description", "") or ""),
                        str(val.get("member_count", "")),
                        str(val.get("admin_to_count", "")),
                    ])
        elif nodes:
            for node_id, node in nodes.items():
                props = node.get("properties", {}) or {}
                kinds = node.get("kinds", [])
                if "Group" not in kinds:
                    continue
                rows.append([
                    props.get("name", node.get("label", node_id)),
                    props.get("description", "") or "",
                    "N/A",
                    "N/A",
                ])

        rows.sort(key=lambda r: int(r[2]) if r[2].isdigit() else 0, reverse=True)

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Group", "Description", "Members", "Admin On # Computers"],
            rows=rows,
            severity="critical" if rows else "info",
        )

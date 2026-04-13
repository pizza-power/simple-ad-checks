"""
Large Groups with Admin Rights check.

Finds groups whose membership exceeds a configurable threshold that also
hold local-admin or high-privilege rights on computers. Uses direct
MemberOf (single-hop) since BH CE may not support variable-length paths.

Falls back gracefully if AdminTo edges don't exist in the graph.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.large_group_admin")

# Step 1: Find large groups by direct membership count.
_LARGE_GROUPS_CYPHER = """
MATCH (g:Group {{domain: "{domain}"}})<-[:MemberOf]-(m)
WITH g.name AS group_name, g.description AS description, count(m) AS member_count
WHERE member_count >= {threshold}
RETURN group_name, description, member_count
ORDER BY member_count DESC
"""

# Step 2: For each large group, check if it has AdminTo edges.
_ADMIN_CHECK_CYPHER = """
MATCH (g:Group {{name: "{group_name}"}})-[:AdminTo]->(c:Computer)
RETURN count(c) AS admin_count
"""


def _parse_literal_rows(literals: list, keys: list[str]) -> list[dict]:
    """Parse flat literal list into rows based on expected column count."""
    num_cols = len(keys)
    rows = []
    for i in range(0, len(literals), num_cols):
        chunk = literals[i:i + num_cols]
        row = {}
        for item in chunk:
            if isinstance(item, dict):
                row[item.get("key", "")] = item.get("value")
        rows.append(row)
    return rows


@register
class LargeGroupAdminCheck(BaseCheck):
    check_id = "large_group_admin"
    title = "Large Groups with Admin Rights"
    description = (
        "Groups with a large membership that hold local administrator "
        "rights on one or more computers. This means hundreds of users "
        "potentially have admin access, dramatically increasing risk. "
        "If AdminTo data is not available, shows all large groups."
    )

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        threshold = kwargs.get("large_group_threshold", 300)
        rows: list[list[str]] = []

        # Step 1: Find large groups
        query = _LARGE_GROUPS_CYPHER.format(domain=domain, threshold=threshold)
        log.info(
            "Querying large groups (>=%d members) for: %s",
            threshold, domain,
        )

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

        literals = result.get("literals", [])
        log.info("  %d literals returned", len(literals))

        large_groups = _parse_literal_rows(
            literals, ["group_name", "description", "member_count"],
        )

        # Step 2: For each large group, try to count AdminTo edges
        for lg in large_groups:
            group_name = lg.get("group_name", "")
            description = str(lg.get("description", "") or "")
            member_count = str(lg.get("member_count", ""))

            admin_count = "N/A (no AdminTo data)"
            try:
                admin_query = _ADMIN_CHECK_CYPHER.format(group_name=group_name)
                admin_result = session.cypher(admin_query)
                admin_literals = admin_result.get("literals", [])
                if admin_literals:
                    for lit in admin_literals:
                        if isinstance(lit, dict) and lit.get("key") == "admin_count":
                            admin_count = str(lit.get("value", 0))
                            break
            except Exception as exc:
                log.warning(
                    "AdminTo query failed for %s (may not be collected): %s",
                    group_name, exc,
                )

            rows.append([group_name, description, member_count, admin_count])

        rows.sort(
            key=lambda r: int(r[2]) if r[2].isdigit() else 0,
            reverse=True,
        )

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Group", "Description", "Members", "Admin On # Computers"],
            rows=rows,
            severity="critical" if rows else "info",
        )

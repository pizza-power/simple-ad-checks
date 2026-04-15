"""
Large Groups with Admin Rights check.

Finds groups whose membership exceeds a configurable threshold that also
hold local-admin rights on computers.  Only shows groups that actually
have AdminTo edges — if no AdminTo data was collected by SharpHound,
the check reports that clearly.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.large_group_admin")

# Single query: find groups that have AdminTo edges AND count their
# direct members, filtering to groups above the threshold.
_CYPHER = """
MATCH (g:Group {{domain: "{domain}"}})-[:AdminTo]->(c:Computer)
WITH g, count(DISTINCT c) AS admin_to_count
MATCH (g)<-[:MemberOf]-(m)
WITH g.name AS group_name, g.description AS description,
     g.system_tags AS group_t0,
     count(DISTINCT m) AS member_count, admin_to_count
WHERE member_count >= {threshold}
RETURN group_name, description, member_count, admin_to_count, group_t0
ORDER BY member_count DESC
"""

# Simpler fallback if the above fails (e.g. variable-length or
# multi-MATCH issues in BH CE Cypher).
_CYPHER_FALLBACK = """
MATCH (g:Group {{domain: "{domain}"}})-[:AdminTo]->(c:Computer)
WITH g.name AS group_name, g.system_tags AS group_t0,
     count(DISTINCT c) AS admin_to_count
RETURN group_name, admin_to_count, group_t0
ORDER BY admin_to_count DESC
LIMIT 50
"""

# Quick probe: do any AdminTo edges exist at all?
_ADMIN_PROBE = "MATCH ()-[:AdminTo]->() RETURN count(*) AS total LIMIT 1"


def _parse_literal_rows(literals: list, num_columns: int) -> list[dict]:
    """Parse flat literal list into rows based on expected column count."""
    rows = []
    for i in range(0, len(literals), num_columns):
        chunk = literals[i:i + num_columns]
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
        "potentially have admin access, dramatically increasing risk."
    )

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        threshold = kwargs.get("large_group_threshold", 300)
        rows: list[list[str]] = []
        tier_zero: list[bool] = []

        # Probe: check if AdminTo edges exist at all
        log.info("Probing for AdminTo edges in the graph ...")
        try:
            probe = session.cypher(_ADMIN_PROBE)
            probe_lits = probe.get("literals", [])
            total_admin = 0
            for lit in probe_lits:
                if isinstance(lit, dict) and lit.get("key") == "total":
                    total_admin = lit.get("value", 0)
            log.info("  AdminTo edges in graph: %s", total_admin)
        except Exception as exc:
            log.warning("AdminTo probe failed: %s", exc)
            total_admin = 0

        if not total_admin:
            log.info("  No AdminTo edges found — local admin data was likely not collected by SharpHound.")
            return CheckResult(
                check_id=self.check_id,
                title=self.title,
                description=self.description,
                headers=["Status"],
                rows=[[
                    "No AdminTo data available. Local admin collection may not have been "
                    "performed by SharpHound. Re-run collection with the 'LocalAdmin' "
                    "method to populate this check."
                ]],
                severity="info",
            )

        # Primary query: large groups with admin rights
        query = _CYPHER.format(domain=domain, threshold=threshold)
        log.info(
            "Querying large groups (>=%d members) with admin rights for: %s",
            threshold, domain,
        )

        try:
            result = session.cypher(query)
            literals = result.get("literals", [])
            log.info("  %d literals returned", len(literals))

            parsed = _parse_literal_rows(literals, 5)
            for lr in parsed:
                admin_ct = lr.get("admin_to_count", 0)
                if isinstance(admin_ct, (int, float)) and admin_ct == 0:
                    continue
                rows.append([
                    str(lr.get("group_name", "")),
                    str(lr.get("description", "") or ""),
                    str(lr.get("member_count", "")),
                    str(admin_ct),
                ])
                t0_val = lr.get("group_t0", "") or ""
                tier_zero.append("admin_tier_0" in str(t0_val))
        except Exception as exc:
            log.warning("Primary query failed, trying fallback: %s", exc)

            # Fallback: just list groups with AdminTo, no member count join
            try:
                result = session.cypher(_CYPHER_FALLBACK.format(domain=domain))
                literals = result.get("literals", [])
                parsed = _parse_literal_rows(literals, 3)
                for lr in parsed:
                    admin_ct = lr.get("admin_to_count", 0)
                    if isinstance(admin_ct, (int, float)) and admin_ct == 0:
                        continue
                    rows.append([
                        str(lr.get("group_name", "")),
                        "",
                        "(see BloodHound)",
                        str(admin_ct),
                    ])
                    t0_val = lr.get("group_t0", "") or ""
                    tier_zero.append("admin_tier_0" in str(t0_val))
            except Exception as exc2:
                log.error("Fallback query also failed: %s", exc2)
                rows.append(["ERROR", str(exc2), "", ""])
                tier_zero.append(False)

        paired = sorted(
            zip(rows, tier_zero),
            key=lambda p: int(p[0][2]) if p[0][2].isdigit() else 0,
            reverse=True,
        )
        rows = [p[0] for p in paired]
        tier_zero = [p[1] for p in paired]

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Group", "Description", "Members", "Admin On # Computers"],
            rows=rows,
            severity="critical" if rows else "info",
            extra={"tier_zero": tier_zero},
        )

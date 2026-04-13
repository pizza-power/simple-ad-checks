"""
Outbound Object Control check.

For each of the four well-known large groups (Everyone, Authenticated Users,
Domain Users, Domain Computers), queries BloodHound for every object they
have outbound control over, including the specific permission edge and
target object metadata.
"""

from __future__ import annotations

import logging

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

log = logging.getLogger("adchecker.checks.outbound_control")

GROUPS = [
    "EVERYONE",
    "AUTHENTICATED USERS",
    "DOMAIN USERS",
    "DOMAIN COMPUTERS",
]

EXCLUDE_EDGES = ["MemberOf", "Contains"]

_CYPHER_TEMPLATE = """
MATCH (g:Group {{name: "{group_fqdn}"}})-[r]->(target)
WHERE NOT type(r) IN {exclude}
RETURN g.name AS source, type(r) AS permission, target.name AS target_name,
       labels(target) AS target_type, target.enabled AS target_enabled
"""

RETURN_COLUMNS = ["source", "permission", "target_name", "target_type", "target_enabled"]


def _parse_literal_rows(literals: list, num_columns: int) -> list[dict]:
    """
    BloodHound returns RETURN-ed properties as a flat list of
    {key, value} literals. Chunk them into rows.
    """
    rows = []
    for i in range(0, len(literals), num_columns):
        chunk = literals[i:i + num_columns]
        row = {}
        for item in chunk:
            if isinstance(item, dict):
                row[item.get("key", "")] = item.get("value")
        rows.append(row)
    return rows


def _object_kind(labels) -> str:
    if not labels:
        return "Unknown"
    if isinstance(labels, str):
        return labels
    skip = {"Base", "AD"}
    kinds = [l for l in labels if l not in skip]
    return ", ".join(kinds) if kinds else "Unknown"


def _enabled_status(enabled) -> str:
    if enabled is None:
        return ""
    return "Enabled" if enabled else "DISABLED"


@register
class OutboundControlCheck(BaseCheck):
    check_id = "outbound_control"
    title = "Outbound Object Control"
    description = (
        "Lists every object that the large default groups "
        "(Everyone, Authenticated Users, Domain Users, Domain Computers) "
        "have direct control over, along with the specific permission and "
        "target object type."
    )

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        rows: list[list[str]] = []
        exclude_str = str(EXCLUDE_EDGES).replace("'", '"')

        for group in GROUPS:
            fqdn = f"{group}@{domain}"
            query = _CYPHER_TEMPLATE.format(group_fqdn=fqdn, exclude=exclude_str)
            log.info("Querying outbound control for: %s", fqdn)

            try:
                result = session.cypher(query)
            except Exception as exc:
                log.error("Cypher query failed for %s: %s", fqdn, exc)
                rows.append([fqdn, "ERROR", str(exc), "", ""])
                continue

            nodes = result.get("nodes", {})
            edges = result.get("edges", [])
            literals = result.get("literals", [])
            log.info(
                "  %s: %d nodes, %d edges, %d literals",
                fqdn, len(nodes), len(edges), len(literals),
            )

            # Strategy 1: Parse from literals (RETURN of specific properties)
            if literals:
                literal_rows = _parse_literal_rows(literals, len(RETURN_COLUMNS))
                for lr in literal_rows:
                    rows.append([
                        lr.get("source", fqdn),
                        lr.get("permission", "Unknown"),
                        lr.get("target_name", "Unknown"),
                        _object_kind(lr.get("target_type")),
                        _enabled_status(lr.get("target_enabled")),
                    ])
                continue

            # Strategy 2: Parse from nodes/edges (RETURN of full objects)
            if edges:
                for edge in edges:
                    source_id = edge.get("source", "")
                    target_id = edge.get("target", "")
                    permission = edge.get("label", edge.get("kind", "Unknown"))

                    source_node = nodes.get(source_id, {})
                    target_node = nodes.get(target_id, {})

                    source_name = (
                        source_node.get("label", "")
                        or (source_node.get("properties", {}) or {}).get("name", fqdn)
                    )
                    target_name = (
                        target_node.get("label", "")
                        or (target_node.get("properties", {}) or {}).get("name", target_id)
                    )
                    target_labels = target_node.get("kinds", [])
                    target_props = target_node.get("properties", {}) or {}
                    enabled = target_props.get("enabled")

                    rows.append([
                        source_name,
                        permission,
                        target_name,
                        _object_kind(target_labels),
                        _enabled_status(enabled),
                    ])
                continue

            log.info("  %s: no outbound control edges (clean)", fqdn)

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Source Group", "Permission", "Target Object", "Target Type", "Status"],
            rows=rows,
            severity="high" if rows else "info",
        )

"""
Outbound Object Control check.

For each of the four well-known large groups (Everyone, Authenticated Users,
Domain Users, Domain Computers), queries BloodHound for every object they
have outbound control over, including the specific permission edge and
target object metadata.
"""

from __future__ import annotations

from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

GROUPS = [
    "EVERYONE",
    "AUTHENTICATED USERS",
    "DOMAIN USERS",
    "DOMAIN COMPUTERS",
]

_CYPHER = """
MATCH (g:Group)-[r]->(target)
WHERE g.name = $group_name
  AND NOT type(r) IN ["MemberOf", "Contains"]
RETURN g.name        AS source,
       type(r)       AS permission,
       target.name   AS target_name,
       labels(target) AS target_labels,
       target.enabled AS target_enabled
"""

# The BH CE Cypher endpoint doesn't support named parameters,
# so we inline the value safely.
_CYPHER_TEMPLATE = """
MATCH (g:Group {{name: "{group_fqdn}"}})-[r]->(target)
WHERE NOT type(r) IN ["MemberOf", "Contains"]
RETURN g.name         AS source,
       type(r)        AS permission,
       target.name    AS target_name,
       labels(target) AS target_labels,
       target.enabled AS target_enabled
"""


def _object_kind(labels: list[str] | None) -> str:
    """Derive a human-friendly kind string from graph labels."""
    if not labels:
        return "Unknown"
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

        for group in GROUPS:
            fqdn = f"{group}@{domain}"
            query = _CYPHER_TEMPLATE.format(group_fqdn=fqdn)

            try:
                result = session.cypher(query)
            except Exception as exc:
                rows.append([fqdn, "ERROR", str(exc), "", ""])
                continue

            nodes = result.get("nodes", {})
            edges = result.get("edges", [])

            if not edges:
                continue

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

        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Source Group", "Permission", "Target Object", "Target Type", "Status"],
            rows=rows,
            severity="high" if rows else "info",
        )

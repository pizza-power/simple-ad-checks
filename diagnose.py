#!/usr/bin/env python3
"""
Diagnostic script — probes the BloodHound CE API to discover
how your graph data is actually structured so we can fix the queries.

Run: python diagnose.py
Output is written to both stdout and diagnose_output.txt
"""

import json
import logging
import sys

import config
from bhapi.client import BHSession

_outfile = open("diagnose_output.txt", "w")


def _print(msg: str = "") -> None:
    print(msg)
    _outfile.write(msg + "\n")
    _outfile.flush()


logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("diagnose")


def section(title: str) -> None:
    _print(f"\n{'='*60}")
    _print(f"  {title}")
    _print(f"{'='*60}\n")


def try_cypher(session: BHSession, label: str, query: str) -> dict | None:
    """Run a Cypher query, print results, return raw data."""
    _print(f"--- {label} ---")
    _print(f"  Query: {query.strip()[:200]}")
    try:
        result = session.cypher(query, include_properties=True)
        nodes = result.get("nodes", {})
        edges = result.get("edges", [])
        literals = result.get("literals", [])
        _print(f"  Result: {len(nodes)} nodes, {len(edges)} edges, {len(literals)} literals")

        if nodes:
            for nid, node in list(nodes.items())[:5]:
                _print(f"    Node [{nid}]: kinds={node.get('kinds')}, label={node.get('label')}")
                props = node.get("properties", {})
                if props:
                    for k, v in list(props.items())[:12]:
                        _print(f"      {k} = {v}")
        if edges:
            for edge in edges[:5]:
                _print(f"    Edge: {edge.get('source')} --[{edge.get('label', edge.get('kind'))}]--> {edge.get('target')}")
        if literals:
            for lit in literals[:5]:
                _print(f"    Literal: {json.dumps(lit)[:300]}")

        return result
    except Exception as exc:
        _print(f"  ERROR: {exc}")
        return None


def main() -> None:
    domain = config.BH_DOMAINS[0]

    session = BHSession(
        base_url=config.BH_BASE_URL,
        token_id=config.BH_TOKEN_ID,
        token_key=config.BH_TOKEN_KEY,
    )

    section("1. CONNECTIVITY")
    try:
        who = session.test_connection()
        _print("Auth OK.")
    except Exception as exc:
        _print(f"FAILED: {exc}")
        sys.exit(1)

    section("2. DOMAIN DISCOVERY")
    _print("What domains exist in the graph?")
    try_cypher(session, "All domains",
        'MATCH (d:Domain) RETURN d.name, d.objectid, d.distinguishedname LIMIT 10')

    section("3. SEARCH FOR TARGET GROUPS (via Cypher)")
    _print(f"Configured domain: {domain}")
    _print("Looking for the four target groups via Cypher...\n")

    for group_name in ["EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "DOMAIN COMPUTERS"]:
        fqdn = f"{group_name}@{domain}"
        try_cypher(session, f"Find {group_name}",
            f'MATCH (g:Group) WHERE g.name = "{fqdn}" RETURN g.name, g.objectid, g.domain LIMIT 1')
        try_cypher(session, f"Fuzzy find {group_name} (case-insensitive)",
            f'MATCH (g:Group) WHERE g.name CONTAINS "{group_name}" RETURN g.name, g.objectid, g.domain LIMIT 3')

    section("4. SAMPLE GROUP DATA (all properties)")
    _print("Fetching a Group node to see every property name...")
    try_cypher(session, "First group",
        'MATCH (g:Group) RETURN g LIMIT 1')

    section("5. SAMPLE USER DATA (all properties)")
    _print("Fetching a User node to see every property name...")
    try_cypher(session, "First user",
        'MATCH (u:User) RETURN u LIMIT 1')

    section("6. CHECK KERBEROAST PROPERTY NAMES")
    _print("Testing hasspn / dontreqpreauth...")
    try_cypher(session, "User with hasspn=true",
        'MATCH (u:User) WHERE u.hasspn = true RETURN u.name, u.hasspn LIMIT 3')
    try_cypher(session, "User with hasspn (any value)",
        'MATCH (u:User) WHERE u.hasspn IS NOT NULL RETURN u.name, u.hasspn LIMIT 3')
    try_cypher(session, "User with dontreqpreauth=true",
        'MATCH (u:User) WHERE u.dontreqpreauth = true RETURN u.name LIMIT 3')
    try_cypher(session, "User with dontreqpreauth (any value)",
        'MATCH (u:User) WHERE u.dontreqpreauth IS NOT NULL RETURN u.name, u.dontreqpreauth LIMIT 3')

    section("7. DOMAIN PROPERTY FORMAT")
    _print("How is domain stored on nodes?")
    try_cypher(session, "User domain property",
        'MATCH (u:User) RETURN u.name, u.domain LIMIT 5')
    try_cypher(session, "Group domain property",
        'MATCH (g:Group) RETURN g.name, g.domain LIMIT 5')

    section("8. OUTBOUND CONTROL TEST")
    _print("Any outbound edges from any Group (excluding MemberOf/Contains)...")
    try_cypher(session, "Any group outbound edges",
        '''MATCH (g:Group)-[r]->(target)
           WHERE NOT type(r) IN ["MemberOf", "Contains"]
           RETURN g.name, type(r), target.name LIMIT 10''')

    section("9. ADMIN RIGHTS TEST")
    _print("AdminTo edges...")
    try_cypher(session, "Any AdminTo edge",
        'MATCH (g:Group)-[:AdminTo]->(c:Computer) RETURN g.name, c.name LIMIT 5')

    section("10. GROUP MEMBERSHIP COUNT")
    _print("Direct members (single-hop MemberOf)...")
    try_cypher(session, "Group member counts (>=50)",
        '''MATCH (g:Group)<-[:MemberOf]-(m)
           WITH g.name AS group_name, count(m) AS member_count
           WHERE member_count >= 50
           RETURN group_name, member_count
           ORDER BY member_count DESC LIMIT 10''')

    section("11. EDGE TYPES IN GRAPH")
    _print("What edge types exist?")
    try_cypher(session, "All edge types from groups",
        '''MATCH (g:Group)-[r]->()
           RETURN DISTINCT type(r) AS edge_type
           ORDER BY edge_type LIMIT 30''')

    section("DONE")
    _print("Output saved to diagnose_output.txt")
    _print("Share that file so the queries can be fixed.")


if __name__ == "__main__":
    main()

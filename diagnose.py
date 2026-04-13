#!/usr/bin/env python3
"""
Diagnostic script — probes the BloodHound CE API to discover
how your graph data is actually structured so we can fix the queries.

Run: python diagnose.py
"""

import json
import logging
import sys

import config
from bhapi.client import BHSession

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("diagnose")


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def try_cypher(session: BHSession, label: str, query: str) -> dict | None:
    """Run a Cypher query, print results, return raw data."""
    print(f"--- {label} ---")
    print(f"  Query: {query.strip()[:200]}")
    try:
        result = session.cypher(query, include_properties=True)
        nodes = result.get("nodes", {})
        edges = result.get("edges", [])
        literals = result.get("literals", [])
        print(f"  Result: {len(nodes)} nodes, {len(edges)} edges, {len(literals)} literals")

        if nodes:
            for nid, node in list(nodes.items())[:3]:
                print(f"    Node [{nid}]: kinds={node.get('kinds')}, label={node.get('label')}")
                props = node.get("properties", {})
                if props:
                    for k, v in list(props.items())[:8]:
                        print(f"      {k} = {v}")
        if edges:
            for edge in edges[:3]:
                print(f"    Edge: {edge.get('source')} --[{edge.get('label', edge.get('kind'))}]--> {edge.get('target')}")
        if literals:
            for lit in literals[:3]:
                print(f"    Literal: {json.dumps(lit)[:200]}")

        return result
    except Exception as exc:
        print(f"  ERROR: {exc}")
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
        print(f"Auth OK.")
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    section("2. DOMAIN DISCOVERY")
    print("What domains exist in the graph?")
    try_cypher(session, "All domains",
        'MATCH (d:Domain) RETURN d.name, d.objectid, d.distinguishedname LIMIT 10')

    section("3. SEARCH FOR TARGET GROUPS")
    print(f"Configured domain: {domain}")
    print("Searching for the four target groups...\n")

    for group_name in ["EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "DOMAIN COMPUTERS"]:
        fqdn = f"{group_name}@{domain}"
        print(f"Searching for: {fqdn}")
        try:
            result = session.search(fqdn, search_type="fuzzy")
            if isinstance(result, dict):
                for nid, node in result.items():
                    label = node.get("label", {}).get("text", "") if isinstance(node.get("label"), dict) else node.get("label", "")
                    props = node.get("data", {})
                    name = props.get("name", label)
                    objectid = props.get("objectid", nid)
                    print(f"  FOUND: name={name}, objectid={objectid}")
                if not result:
                    print(f"  NOT FOUND")
            else:
                print(f"  Response: {str(result)[:200]}")
        except Exception as exc:
            print(f"  ERROR: {exc}")
        print()

    section("4. SAMPLE GROUP DATA")
    print("Fetching any Group node to see property names...")
    try_cypher(session, "First group",
        'MATCH (g:Group) RETURN g LIMIT 1')

    section("5. SAMPLE USER DATA")
    print("Fetching any User node to see property names...")
    try_cypher(session, "First user",
        'MATCH (u:User) RETURN u LIMIT 1')

    section("6. CHECK PROPERTY NAMES")
    print("Testing if hasspn / dontreqpreauth exist on users...")
    try_cypher(session, "User with hasspn",
        'MATCH (u:User) WHERE u.hasspn = true RETURN u.name LIMIT 3')

    try_cypher(session, "User with has_spn (alt name)",
        'MATCH (u:User) WHERE u.has_spn = true RETURN u.name LIMIT 3')
    print()

    try_cypher(session, "User with dontreqpreauth",
        'MATCH (u:User) WHERE u.dontreqpreauth = true RETURN u.name LIMIT 3')

    try_cypher(session, "User with dont_req_preauth (alt name)",
        'MATCH (u:User) WHERE u.dont_req_preauth = true RETURN u.name LIMIT 3')

    section("7. CHECK DOMAIN PROPERTY FORMAT")
    print("How is the domain stored on nodes?")
    try_cypher(session, "User domain property",
        'MATCH (u:User) RETURN u.name, u.domain LIMIT 3')

    section("8. OUTBOUND CONTROL TEST")
    print("Testing a simple outbound edge query (no domain filter)...")
    try_cypher(session, "Any group with outbound edges",
        '''MATCH (g:Group)-[r]->(target)
           WHERE NOT type(r) IN ["MemberOf", "Contains"]
           RETURN g.name, type(r), target.name LIMIT 5''')

    section("9. ADMIN RIGHTS TEST")
    print("Testing AdminTo edges (simpler query, no variable-length paths)...")
    try_cypher(session, "Any AdminTo edge",
        'MATCH (g:Group)-[:AdminTo]->(c:Computer) RETURN g.name, c.name LIMIT 5')

    section("10. GROUP MEMBERSHIP COUNT")
    print("Testing simple member count (no variable-length path)...")
    try_cypher(session, "Group member counts",
        '''MATCH (g:Group)<-[:MemberOf]-(m)
           WITH g.name AS group_name, count(m) AS member_count
           WHERE member_count >= 50
           RETURN group_name, member_count
           ORDER BY member_count DESC LIMIT 10''')

    section("DONE")
    print("Copy/paste the output above and share it — it will show")
    print("exactly how to fix the queries.")


if __name__ == "__main__":
    main()

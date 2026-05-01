"""Neo4j writer for Aruba/Cisco switch topology facts."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json
from typing import Any

from neo4j import GraphDatabase, Driver

from sariel.connectors.network_switches import (
    AclRuleFact,
    InterfaceFact,
    RouteFact,
    SwitchFacts,
    interface_id,
    route_id,
    subnet_id,
    switch_id,
    vlan_id,
)


class NetworkSwitchGraphWriter:
    """Writes switch topology facts into Neo4j with idempotent MERGE operations."""

    def __init__(self, uri: str, username: str, password: str):
        self.driver: Driver = GraphDatabase.driver(uri, auth=(username, password))
        self.driver.verify_connectivity()
        self.ensure_schema()

    def close(self) -> None:
        self.driver.close()

    def ensure_schema(self) -> None:
        statements = [
            "CREATE CONSTRAINT sariel_switch_id IF NOT EXISTS FOR (n:Switch) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT sariel_vlan_id IF NOT EXISTS FOR (n:Vlan) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT sariel_interface_id IF NOT EXISTS FOR (n:SwitchInterface) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT sariel_subnet_cidr IF NOT EXISTS FOR (n:Subnet) REQUIRE n.cidr IS UNIQUE",
            "CREATE CONSTRAINT sariel_route_id IF NOT EXISTS FOR (n:Route) REQUIRE n.id IS UNIQUE",
            "CREATE INDEX sariel_acl_name IF NOT EXISTS FOR ()-[r:ACL_RULE]-() ON (r.acl_name)",
            "CREATE INDEX sariel_can_reach_protocol IF NOT EXISTS FOR ()-[r:CAN_REACH]-() ON (r.protocol)",
        ]
        with self.driver.session() as session:
            for statement in statements:
                session.run(statement)

    def write_facts(self, facts: SwitchFacts) -> None:
        now = datetime.utcnow().isoformat()
        with self.driver.session() as session:
            session.execute_write(_write_switch, facts, now)
            session.execute_write(_write_vlans, facts, now)
            session.execute_write(_write_interfaces, facts, now)
            session.execute_write(_write_routes, facts, now)
            session.execute_write(_write_acls, facts, now)
            session.execute_write(_derive_reachability, facts, now)


def _write_switch(tx, facts: SwitchFacts, now: str) -> None:
    tx.run(
        """
        MERGE (s:Switch:NetworkDevice:SarielNode {id: $id})
        SET s.name = $name,
            s.label = $name,
            s.vendor = $vendor,
            s.mgmt_ip = $mgmt_ip,
            s.source = 'network_switch',
            s.updated_at = $now
        """,
        id=switch_id(facts.device_name),
        name=facts.device_name,
        vendor=facts.vendor,
        mgmt_ip=facts.mgmt_ip,
        now=now,
    )


def _write_vlans(tx, facts: SwitchFacts, now: str) -> None:
    rows = []
    for vlan in facts.vlans:
        rows.append({
            "id": vlan_id(facts.device_name, vlan.vlan_id),
            "switch_id": switch_id(facts.device_name),
            "vlan_id": vlan.vlan_id,
            "name": vlan.name,
            "svi_interface": vlan.svi_interface,
            "ip_cidr": vlan.ip_cidr,
            "network_cidr": vlan.network_cidr,
            "now": now,
        })
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (v:Vlan:NetworkControl:SarielNode {id: row.id})
        SET v.vlan_id = row.vlan_id,
            v.name = coalesce(row.name, 'VLAN ' + toString(row.vlan_id)),
            v.label = coalesce(row.name, 'VLAN ' + toString(row.vlan_id)),
            v.svi_interface = row.svi_interface,
            v.ip_cidr = row.ip_cidr,
            v.network_cidr = row.network_cidr,
            v.source = 'network_switch',
            v.updated_at = row.now
        WITH row, v
        MATCH (s:Switch {id: row.switch_id})
        MERGE (s)-[:HAS_VLAN]->(v)
        FOREACH (_ IN CASE WHEN row.network_cidr IS NULL THEN [] ELSE [1] END |
            MERGE (sub:Subnet:SarielNode {cidr: row.network_cidr})
            SET sub.id = 'subnet:' + replace(row.network_cidr, '/', '-'),
                sub.label = row.network_cidr,
                sub.source = 'network_switch',
                sub.updated_at = row.now
            MERGE (v)-[:ROUTES_SUBNET]->(sub)
        )
        """,
        rows=rows,
    )


def _write_interfaces(tx, facts: SwitchFacts, now: str) -> None:
    rows = []
    for intf in facts.interfaces:
        rows.append({
            "id": interface_id(facts.device_name, intf.name),
            "switch_id": switch_id(facts.device_name),
            **_clean(asdict(intf)),
            "now": now,
        })
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (i:SwitchInterface:NetworkInterface:SarielNode {id: row.id})
        SET i.name = row.name,
            i.label = row.name,
            i.description = row.description,
            i.mode = row.mode,
            i.access_vlan = row.access_vlan,
            i.trunk_vlans = row.trunk_vlans,
            i.native_vlan = row.native_vlan,
            i.ip_cidr = row.ip_cidr,
            i.network_cidr = row.network_cidr,
            i.shutdown = row.shutdown,
            i.inbound_acl = row.inbound_acl,
            i.outbound_acl = row.outbound_acl,
            i.vrf = row.vrf,
            i.source = 'network_switch',
            i.updated_at = row.now
        WITH row, i
        MATCH (s:Switch {id: row.switch_id})
        MERGE (s)-[:HAS_INTERFACE]->(i)
        FOREACH (_ IN CASE WHEN row.access_vlan IS NULL THEN [] ELSE [1] END |
            MERGE (v:Vlan {id: row.switch_id + ':vlan:' + toString(row.access_vlan)})
            MERGE (i)-[:ACCESS_VLAN]->(v)
        )
        FOREACH (vlan IN coalesce(row.trunk_vlans, []) |
            MERGE (v:Vlan {id: row.switch_id + ':vlan:' + toString(vlan)})
            MERGE (i)-[:TRUNKS_VLAN]->(v)
        )
        FOREACH (_ IN CASE WHEN row.network_cidr IS NULL THEN [] ELSE [1] END |
            MERGE (sub:Subnet:SarielNode {cidr: row.network_cidr})
            SET sub.id = 'subnet:' + replace(row.network_cidr, '/', '-'),
                sub.label = row.network_cidr,
                sub.source = 'network_switch',
                sub.updated_at = row.now
            MERGE (i)-[:IN_SUBNET]->(sub)
        )
        """,
        rows=rows,
    )


def _write_routes(tx, facts: SwitchFacts, now: str) -> None:
    rows = []
    for route in facts.routes:
        rows.append({
            "id": route_id(facts.device_name, route.destination, route.next_hop, route.interface),
            "switch_id": switch_id(facts.device_name),
            **_clean(asdict(route)),
            "now": now,
        })
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (r:Route:NetworkControl:SarielNode {id: row.id})
        SET r.destination = row.destination,
            r.label = row.destination,
            r.next_hop = row.next_hop,
            r.interface = row.interface,
            r.protocol = row.protocol,
            r.distance = row.distance,
            r.metric = row.metric,
            r.evidence = row.evidence,
            r.source = 'network_switch',
            r.updated_at = row.now
        WITH row, r
        MATCH (s:Switch {id: row.switch_id})
        MERGE (s)-[:HAS_ROUTE]->(r)
        MERGE (dst:Subnet:SarielNode {cidr: row.destination})
        SET dst.id = 'subnet:' + replace(row.destination, '/', '-'),
            dst.label = row.destination,
            dst.source = 'network_switch',
            dst.updated_at = row.now
        MERGE (r)-[:ROUTES_TO]->(dst)
        """,
        rows=rows,
    )


def _write_acls(tx, facts: SwitchFacts, now: str) -> None:
    rows = []
    for rule in facts.acl_rules:
        if rule.action == "remark":
            continue
        rows.append({
            **_clean(asdict(rule)),
            "switch_id": switch_id(facts.device_name),
            "now": now,
        })
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (s:Switch {id: row.switch_id})
        MERGE (src:Subnet:SarielNode {cidr: row.src})
        SET src.id = 'subnet:' + replace(row.src, '/', '-'), src.label = row.src
        MERGE (dst:Subnet:SarielNode {cidr: row.dst})
        SET dst.id = 'subnet:' + replace(row.dst, '/', '-'), dst.label = row.dst
        MERGE (src)-[r:ACL_RULE {switch_id: row.switch_id, acl_name: row.acl_name, sequence: row.sequence}]->(dst)
        SET r.action = row.action,
            r.protocol = row.protocol,
            r.src_port = row.src_port,
            r.dst_port = row.dst_port,
            r.established = row.established,
            r.log = row.log,
            r.evidence = row.evidence,
            r.source = 'network_switch',
            r.updated_at = row.now
        """,
        rows=rows,
    )


def _derive_reachability(tx, facts: SwitchFacts, now: str) -> None:
    # Connected VLAN/SVI/routed-interface networks on the same L3 switch can route to each other.
    connected = sorted({n for n in facts.routed_networks if n})
    connected_rows = [
        {
            "src": src,
            "dst": dst,
            "switch_id": switch_id(facts.device_name),
            "switch_name": facts.device_name,
            "now": now,
        }
        for src in connected
        for dst in connected
        if src != dst
    ]
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (src:Subnet:SarielNode {cidr: row.src})
        SET src.id = 'subnet:' + replace(row.src, '/', '-'), src.label = row.src
        MERGE (dst:Subnet:SarielNode {cidr: row.dst})
        SET dst.id = 'subnet:' + replace(row.dst, '/', '-'), dst.label = row.dst
        MERGE (src)-[r:CAN_REACH {via_switch: row.switch_id, source: 'connected_routes'}]->(dst)
        SET r.protocol = 'ip',
            r.action = 'allow',
            r.confidence = 0.85,
            r.evidence = 'same L3 switch connected networks',
            r.updated_at = row.now
        """,
        rows=connected_rows,
    )

    # Static routes mean connected networks can attempt to reach the route destination through this switch.
    route_rows = []
    for route in facts.routes:
        for src in connected:
            if src != route.destination:
                route_rows.append({
                    "src": src,
                    "dst": route.destination,
                    "switch_id": switch_id(facts.device_name),
                    "next_hop": route.next_hop,
                    "interface": route.interface,
                    "evidence": route.evidence,
                    "now": now,
                })
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (src:Subnet:SarielNode {cidr: row.src})
        SET src.id = 'subnet:' + replace(row.src, '/', '-'), src.label = row.src
        MERGE (dst:Subnet:SarielNode {cidr: row.dst})
        SET dst.id = 'subnet:' + replace(row.dst, '/', '-'), dst.label = row.dst
        MERGE (src)-[r:CAN_REACH {via_switch: row.switch_id, source: 'static_route', destination: row.dst}]->(dst)
        SET r.protocol = 'ip',
            r.action = 'allow',
            r.confidence = 0.75,
            r.next_hop = row.next_hop,
            r.interface = row.interface,
            r.evidence = row.evidence,
            r.updated_at = row.now
        """,
        rows=route_rows,
    )

    # Permit ACLs create service-specific reachability. Denies are preserved as ACL_RULE, not CAN_REACH.
    acl_rows = []
    for rule in facts.acl_rules:
        if rule.action != "permit":
            continue
        acl_rows.append({
            **_clean(asdict(rule)),
            "switch_id": switch_id(facts.device_name),
            "now": now,
        })
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (src:Subnet:SarielNode {cidr: row.src})
        SET src.id = 'subnet:' + replace(row.src, '/', '-'), src.label = row.src
        MERGE (dst:Subnet:SarielNode {cidr: row.dst})
        SET dst.id = 'subnet:' + replace(row.dst, '/', '-'), dst.label = row.dst
        MERGE (src)-[r:CAN_REACH {via_switch: row.switch_id, source: 'acl_permit', acl_name: row.acl_name, sequence: row.sequence}]->(dst)
        SET r.protocol = row.protocol,
            r.port = row.dst_port,
            r.src_port = row.src_port,
            r.action = 'allow',
            r.confidence = 0.9,
            r.evidence = row.evidence,
            r.updated_at = row.now
        """,
        rows=acl_rows,
    )


def _clean(value: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            out[key] = item
        else:
            out[key] = item
    return out

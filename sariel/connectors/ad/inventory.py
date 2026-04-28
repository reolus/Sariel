from __future__ import annotations

from datetime import datetime
from typing import Any

from ldap3 import ALL, Connection, Server, SUBTREE

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge,
    CanonicalNode,
    Cloud,
    EdgeType,
    NodeType,
    NormalizedSnapshot,
)


class ActiveDirectoryConnector(BaseConnector):
    """
    Active Directory inventory connector.

    Ingests:
    - computer objects
    - user objects
    - group objects
    - group membership edges

    Notes:
    - Uses LDAP/LDAPS.
    - Requires a read-only domain account.
    """

    cloud = Cloud.AWS

    def __init__(
        self,
        server_uri: str,
        bind_user: str,
        bind_password: str,
        base_dn: str,
        account_id: str = "ad",
        use_ssl: bool = True,
    ):
        self.server_uri = server_uri
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.base_dn = base_dn
        self.account_id = account_id
        self.use_ssl = use_ssl
        self._conn: Connection | None = None

    def authenticate(self) -> None:
        server = Server(self.server_uri, use_ssl=self.use_ssl, get_info=ALL)
        conn = Connection(
            server,
            user=self.bind_user,
            password=self.bind_password,
            auto_bind=True,
        )
        self._conn = conn

    def fetch_raw(self) -> dict:
        assert self._conn is not None

        raw: dict[str, Any] = {
            "computers": [],
            "users": [],
            "groups": [],
        }

        self._conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=[
                "cn",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "lastLogonTimestamp",
                "distinguishedName",
                "objectSid",
                "memberOf",
            ],
        )
        raw["computers"] = [_entry_to_dict(e) for e in self._conn.entries]

        self._conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=user)(!(objectClass=computer)))",
            search_scope=SUBTREE,
            attributes=[
                "cn",
                "sAMAccountName",
                "userPrincipalName",
                "distinguishedName",
                "objectSid",
                "memberOf",
                "userAccountControl",
            ],
        )
        raw["users"] = [_entry_to_dict(e) for e in self._conn.entries]

        self._conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=group))",
            search_scope=SUBTREE,
            attributes=[
                "cn",
                "sAMAccountName",
                "distinguishedName",
                "objectSid",
                "member",
                "groupType",
            ],
        )
        raw["groups"] = [_entry_to_dict(e) for e in self._conn.entries]

        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []

        dn_to_id: dict[str, str] = {}

        for comp in raw.get("computers", []):
            try:
                dn = _first(comp, "distinguishedName")
                hostname = _first(comp, "dNSHostName") or _first(comp, "cn")
                canonical_id = f"ad://{self.account_id}/computer/{_safe(hostname or dn)}"
                dn_to_id[dn.lower()] = canonical_id

                nodes.append(
                    CanonicalNode(
                        canonical_id=canonical_id,
                        node_type=NodeType.EC2_INSTANCE,
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=hostname or _first(comp, "cn") or canonical_id,
                        properties={
                            "source": "active_directory",
                            "ad_object_type": "computer",
                            "hostname": hostname,
                            "fqdn": hostname,
                            "cn": _first(comp, "cn"),
                            "distinguished_name": dn,
                            "object_sid": _first(comp, "objectSid"),
                            "os": _first(comp, "operatingSystem"),
                            "os_version": _first(comp, "operatingSystemVersion"),
                            "last_logon_timestamp": _first(comp, "lastLogonTimestamp"),
                            "domain_joined": True,
                            "has_public_ip": False,
                            "managed": True,
                        },
                        scanned_at=now,
                    )
                )
            except Exception as exc:
                errors.append(f"AD computer normalization failed: {exc}")

        for user in raw.get("users", []):
            try:
                dn = _first(user, "distinguishedName")
                sam = _first(user, "sAMAccountName")
                upn = _first(user, "userPrincipalName")
                canonical_id = f"ad://{self.account_id}/user/{_safe(sam or upn or dn)}"
                dn_to_id[dn.lower()] = canonical_id

                nodes.append(
                    CanonicalNode(
                        canonical_id=canonical_id,
                        node_type=NodeType.IAM_USER,
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=upn or sam or canonical_id,
                        properties={
                            "source": "active_directory",
                            "ad_object_type": "user",
                            "sam_account_name": sam,
                            "upn": upn,
                            "cn": _first(user, "cn"),
                            "distinguished_name": dn,
                            "object_sid": _first(user, "objectSid"),
                            "user_account_control": _first(user, "userAccountControl"),
                        },
                        scanned_at=now,
                    )
                )
            except Exception as exc:
                errors.append(f"AD user normalization failed: {exc}")

        for group in raw.get("groups", []):
            try:
                dn = _first(group, "distinguishedName")
                sam = _first(group, "sAMAccountName")
                canonical_id = f"ad://{self.account_id}/group/{_safe(sam or dn)}"
                dn_to_id[dn.lower()] = canonical_id

                nodes.append(
                    CanonicalNode(
                        canonical_id=canonical_id,
                        node_type=NodeType.IAM_ROLE,
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=sam or _first(group, "cn") or canonical_id,
                        properties={
                            "source": "active_directory",
                            "ad_object_type": "group",
                            "sam_account_name": sam,
                            "cn": _first(group, "cn"),
                            "distinguished_name": dn,
                            "object_sid": _first(group, "objectSid"),
                            "group_type": _first(group, "groupType"),
                            "is_privileged": _is_privileged_group(sam or _first(group, "cn")),
                            "is_overpermissioned": _is_privileged_group(sam or _first(group, "cn")),
                        },
                        scanned_at=now,
                    )
                )
            except Exception as exc:
                errors.append(f"AD group normalization failed: {exc}")

        # group membership edges
        for group in raw.get("groups", []):
            group_dn = _first(group, "distinguishedName")
            group_id = dn_to_id.get(group_dn.lower()) if group_dn else None
            if not group_id:
                continue

            members = _list(group.get("member"))
            for member_dn in members:
                member_id = dn_to_id.get(str(member_dn).lower())
                if not member_id:
                    continue

                edges.append(
                    CanonicalEdge(
                        from_id=member_id,
                        to_id=group_id,
                        edge_type=EdgeType.MEMBER_OF,
                        properties={"source": "active_directory"},
                        scanned_at=now,
                    )
                )

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source="active_directory",
            scanned_at=now,
            errors=errors,
        )


def _entry_to_dict(entry) -> dict:
    return entry.entry_attributes_as_dict


def _first(obj: dict, key: str) -> str:
    value = obj.get(key)
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _list(value) -> list:
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def _safe(value: str) -> str:
    return str(value or "").strip().lower().replace("\\", "_").replace("/", "_").replace(" ", "_")


def _is_privileged_group(name: str) -> bool:
    name = (name or "").lower()
    privileged = [
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "server operators",
        "backup operators",
        "dnsadmins",
        "group policy creator owners",
    ]
    return any(p in name for p in privileged)
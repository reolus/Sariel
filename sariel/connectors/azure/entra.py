"""
Entra ID Connector — Users, Groups, Service Principals, RBAC role assignments,
Conditional Access policies.
Uses Microsoft Graph API v1.0.
"""
from __future__ import annotations
import logging
from datetime import datetime
from typing import Any, Optional

import requests

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge, CanonicalNode, Cloud, EdgeType,
    NodeType, NormalizedSnapshot,
)

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ARM_BASE = "https://management.azure.com"

# Azure built-in privileged roles by well-known role definition IDs
PRIVILEGED_ROLE_IDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
}


class EntraConnector(BaseConnector):
    cloud = Cloud.AZURE

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str = ""):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.account_id = tenant_id
        self._graph_token: Optional[str] = None
        self._arm_token: Optional[str] = None

    def authenticate(self) -> None:
        self._graph_token = self._get_token("https://graph.microsoft.com/.default")
        if self.subscription_id:
            self._arm_token = self._get_token("https://management.azure.com/.default")
        logger.info("Entra authentication successful for tenant %s", self.tenant_id)

    def _get_token(self, scope: str) -> str:
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope,
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _graph_get(self, path: str, params: Optional[dict] = None) -> list[dict]:
        """Paginate through a Graph API endpoint, return all results."""
        headers = {"Authorization": f"Bearer {self._graph_token}"}
        url = f"{GRAPH_BASE}{path}"
        results = []
        while url:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                import time; time.sleep(retry_after)
                resp = requests.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # nextLink already includes params
        return results

    def _arm_get(self, path: str) -> list[dict]:
        """Paginate through ARM API, return all results."""
        headers = {"Authorization": f"Bearer {self._arm_token}"}
        url = f"{ARM_BASE}{path}"
        results = []
        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("nextLink")
        return results

    def fetch_raw(self) -> dict:
        raw: dict[str, Any] = {}

        # Users ($select to minimize data transfer and API quota)
        raw["users"] = self._graph_get(
            "/users",
            params={"$select": "id,userPrincipalName,displayName,accountEnabled,userType,signInActivity,createdDateTime"},
        )

        # MFA registration details
        try:
            raw["auth_methods"] = self._graph_get(
                "/reports/authenticationMethods/userRegistrationDetails",
                params={"$select": "id,userPrincipalName,isMfaRegistered,isMfaCapable,defaultMfaMethod"},
            )
        except Exception as e:
            logger.warning("Could not fetch MFA registration details: %s", e)
            raw["auth_methods"] = []

        # Groups
        raw["groups"] = self._graph_get(
            "/groups",
            params={"$select": "id,displayName,groupTypes,isAssignableToRole,membershipRule"},
        )

        # Group members
        raw["group_members"] = {}
        for group in raw["groups"]:
            try:
                members = self._graph_get(f"/groups/{group['id']}/members",
                                          params={"$select": "id,@odata.type"})
                raw["group_members"][group["id"]] = members
            except Exception as e:
                logger.warning("Could not fetch members of group %s: %s", group["id"], e)

        # Service Principals (filter to non-Microsoft-managed)
        raw["service_principals"] = self._graph_get(
            "/servicePrincipals",
            params={"$select": "id,displayName,appId,servicePrincipalType,accountEnabled",
                    "$filter": "accountEnabled eq true"},
        )

        # Conditional Access policies
        try:
            raw["ca_policies"] = self._graph_get(
                "/identity/conditionalAccess/policies",
                params={"$select": "id,displayName,state,conditions,grantControls"},
            )
        except Exception as e:
            logger.warning("CA policy fetch requires Policy.Read.All: %s", e)
            raw["ca_policies"] = []

        # Azure RBAC role assignments (subscription scope via ARM)
        raw["role_assignments"] = []
        raw["role_definitions"] = []
        if self.subscription_id and self._arm_token:
            try:
                raw["role_assignments"] = self._arm_get(
                    f"/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                )
                raw["role_definitions"] = self._arm_get(
                    f"/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
                )
            except Exception as e:
                logger.error("ARM RBAC fetch failed: %s", e)

        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []
        now = datetime.utcnow()

        # Build MFA lookup
        mfa_map: dict[str, dict] = {}
        for reg in raw.get("auth_methods", []):
            mfa_map[reg.get("id", "")] = reg

        # Users
        for user in raw.get("users", []):
            oid = user.get("id", "")
            if not oid:
                continue
            canonical_id = f"entra://{self.tenant_id}/users/{oid}"
            upn = user.get("userPrincipalName", "")
            is_guest = user.get("userType", "Member") == "Guest"

            mfa_info = mfa_map.get(oid, {})
            mfa_registered = mfa_info.get("isMfaRegistered", False)
            mfa_enforced = mfa_info.get("isMfaCapable", False)

            last_sign_in = ""
            sign_in = user.get("signInActivity") or {}
            last_sign_in = str(sign_in.get("lastSignInDateTime", ""))

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.ENTRA_USER,
                cloud=Cloud.AZURE,
                account_id=self.tenant_id,
                label=upn or user.get("displayName", oid),
                properties={
                    "object_id": oid,
                    "upn": upn,
                    "display_name": user.get("displayName", ""),
                    "tenant_id": self.tenant_id,
                    "account_enabled": user.get("accountEnabled", True),
                    "is_guest": is_guest,
                    "mfa_registered": mfa_registered,
                    "mfa_enforced": mfa_enforced,
                    "last_sign_in": last_sign_in,
                    "created_at": str(user.get("createdDateTime", "")),
                },
                scanned_at=now,
            ))

        # Groups
        group_canonical_map: dict[str, str] = {}
        for group in raw.get("groups", []):
            oid = group.get("id", "")
            if not oid:
                continue
            canonical_id = f"entra://{self.tenant_id}/groups/{oid}"
            group_canonical_map[oid] = canonical_id
            is_role_assignable = group.get("isAssignableToRole", False)

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.ENTRA_GROUP,
                cloud=Cloud.AZURE,
                account_id=self.tenant_id,
                label=group.get("displayName", oid),
                properties={
                    "object_id": oid,
                    "display_name": group.get("displayName", ""),
                    "tenant_id": self.tenant_id,
                    "is_role_assignable": is_role_assignable,
                    "group_types": group.get("groupTypes", []),
                },
                scanned_at=now,
            ))

        # Group membership edges
        for group_oid, members in raw.get("group_members", {}).items():
            group_canonical = group_canonical_map.get(group_oid)
            if not group_canonical:
                continue
            for member in members:
                member_oid = member.get("id", "")
                odata_type = member.get("@odata.type", "")
                if "user" in odata_type.lower():
                    member_canonical = f"entra://{self.tenant_id}/users/{member_oid}"
                elif "servicePrincipal" in odata_type:
                    member_canonical = f"entra://{self.tenant_id}/servicePrincipals/{member_oid}"
                elif "group" in odata_type.lower():
                    member_canonical = f"entra://{self.tenant_id}/groups/{member_oid}"
                else:
                    continue
                edges.append(CanonicalEdge(
                    from_id=member_canonical,
                    to_id=group_canonical,
                    edge_type=EdgeType.MEMBER_OF,
                    scanned_at=now,
                ))

        # Service Principals
        sp_canonical_map: dict[str, str] = {}
        for sp in raw.get("service_principals", []):
            oid = sp.get("id", "")
            if not oid:
                continue
            canonical_id = f"entra://{self.tenant_id}/servicePrincipals/{oid}"
            sp_canonical_map[oid] = canonical_id
            sp_type = sp.get("servicePrincipalType", "")
            is_managed_identity = sp_type == "ManagedIdentity"

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.ENTRA_SERVICE_PRINCIPAL,
                cloud=Cloud.AZURE,
                account_id=self.tenant_id,
                label=sp.get("displayName", oid),
                properties={
                    "object_id": oid,
                    "app_id": sp.get("appId", ""),
                    "display_name": sp.get("displayName", ""),
                    "tenant_id": self.tenant_id,
                    "sp_type": sp_type,
                    "is_managed_identity": is_managed_identity,
                    "account_enabled": sp.get("accountEnabled", True),
                },
                scanned_at=now,
            ))

        # Role definitions
        role_def_map: dict[str, dict] = {}
        for role_def in raw.get("role_definitions", []):
            props = role_def.get("properties", {})
            role_def_id = role_def.get("name", "")  # GUID
            canonical_id = f"azure://{self.subscription_id}/roleDefinitions/{role_def_id}"
            role_def_map[role_def_id] = {
                "canonical_id": canonical_id,
                "name": props.get("roleName", role_def_id),
            }
            actions = props.get("permissions", [{}])[0].get("actions", []) if props.get("permissions") else []
            not_actions = props.get("permissions", [{}])[0].get("notActions", []) if props.get("permissions") else []
            is_privileged = (
                role_def_id in PRIVILEGED_ROLE_IDS
                or "*" in actions
                or "Microsoft.Authorization/roleAssignments/write" in actions
            )
            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AZURE_ROLE_DEFINITION,
                cloud=Cloud.AZURE,
                account_id=self.subscription_id,
                label=props.get("roleName", role_def_id),
                properties={
                    "role_definition_id": role_def_id,
                    "role_name": props.get("roleName", ""),
                    "role_type": props.get("type", ""),
                    "actions": actions,
                    "not_actions": not_actions,
                    "is_privileged": is_privileged,
                },
                scanned_at=now,
            ))

        # Role assignments → ASSIGNED_ROLE edges
        for assignment in raw.get("role_assignments", []):
            props = assignment.get("properties", {})
            principal_id = props.get("principalId", "")
            role_def_id = props.get("roleDefinitionId", "").split("/")[-1]
            scope = props.get("scope", "")
            principal_type = props.get("principalType", "")

            if not principal_id or not role_def_id:
                continue

            role_def_info = role_def_map.get(role_def_id, {})
            role_canonical = role_def_info.get("canonical_id",
                f"azure://{self.subscription_id}/roleDefinitions/{role_def_id}")

            # Determine principal canonical ID
            if principal_type == "User":
                principal_canonical = f"entra://{self.tenant_id}/users/{principal_id}"
            elif principal_type == "ServicePrincipal":
                principal_canonical = f"entra://{self.tenant_id}/servicePrincipals/{principal_id}"
            elif principal_type == "Group":
                principal_canonical = f"entra://{self.tenant_id}/groups/{principal_id}"
            else:
                principal_canonical = f"entra://{self.tenant_id}/principals/{principal_id}"

            edges.append(CanonicalEdge(
                from_id=principal_canonical,
                to_id=role_canonical,
                edge_type=EdgeType.ASSIGNED_ROLE,
                properties={
                    "scope": scope,
                    "scope_level": _classify_scope(scope, self.subscription_id),
                    "role_def_id": role_def_id,
                },
                scanned_at=now,
            ))

        # Conditional Access policies
        # Map which users are covered by MFA-enforcing policies
        mfa_covered_users: set[str] = set()
        for policy in raw.get("ca_policies", []):
            state = policy.get("state", "")
            if state != "enabled":
                continue
            grant = policy.get("grantControls") or {}
            controls = grant.get("builtInControls", [])
            requires_mfa = "mfa" in [c.lower() for c in controls]
            if not requires_mfa:
                continue

            conditions = policy.get("conditions") or {}
            users_cond = conditions.get("users") or {}
            # Include all users unless explicitly excluded
            include_all = "All" in users_cond.get("includeUsers", [])
            include_groups = users_cond.get("includeGroups", [])

            if include_all:
                # Mark all users as covered
                for user in raw.get("users", []):
                    mfa_covered_users.add(user.get("id", ""))

            ca_canonical = f"entra://{self.tenant_id}/caPolicies/{policy['id']}"
            nodes.append(CanonicalNode(
                canonical_id=ca_canonical,
                node_type=NodeType.CONDITIONAL_ACCESS_POLICY,
                cloud=Cloud.AZURE,
                account_id=self.tenant_id,
                label=policy.get("displayName", policy["id"]),
                properties={
                    "policy_id": policy["id"],
                    "state": state,
                    "requires_mfa": requires_mfa,
                    "include_all_users": include_all,
                },
                scanned_at=now,
            ))

            if include_all:
                for user in raw.get("users", []):
                    oid = user.get("id", "")
                    user_canonical = f"entra://{self.tenant_id}/users/{oid}"
                    edges.append(CanonicalEdge(
                        from_id=user_canonical,
                        to_id=ca_canonical,
                        edge_type=EdgeType.CONDITIONAL_ACCESS,
                        scanned_at=now,
                    ))

        return NormalizedSnapshot(
            cloud=Cloud.AZURE,
            account_id=self.tenant_id,
            nodes=nodes,
            edges=edges,
            raw_source="",
            scanned_at=now,
            errors=errors,
        )


def _classify_scope(scope: str, subscription_id: str) -> str:
    """Return: subscription | resource_group | resource"""
    parts = [p for p in scope.split("/") if p]
    if len(parts) == 2:
        return "subscription"
    if len(parts) == 4 and "resourcegroups" in scope.lower():
        return "resource_group"
    return "resource"

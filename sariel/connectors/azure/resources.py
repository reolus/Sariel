"""
Azure Resource Connector — VMs, NSGs, Storage Accounts, Key Vaults.
Uses azure-mgmt-* SDKs with a service principal.
"""
from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge, CanonicalNode, Cloud, EdgeType,
    NodeType, NormalizedSnapshot, Sensitivity,
)

logger = logging.getLogger(__name__)

INTERNET_CANONICAL_ID = "internet://0.0.0.0/0"


def _azure_canonical(subscription_id: str, resource_id: str) -> str:
    """Normalize Azure resource IDs to a stable canonical form (lowercase)."""
    return f"azure://{subscription_id}{resource_id.lower()}"


class AzureResourceConnector(BaseConnector):
    cloud = Cloud.AZURE

    def __init__(self, subscription_id: str, tenant_id: str, client_id: str, client_secret: str):
        self.account_id = subscription_id
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._credential = None

    def authenticate(self) -> None:
        try:
            from azure.identity import ClientSecretCredential
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            # Validate by fetching a token
            from azure.mgmt.resource import SubscriptionClient
            sub_client = SubscriptionClient(self._credential)
            _ = next(iter(sub_client.subscriptions.list()), None)
            logger.info("Azure authentication successful for subscription %s", self.subscription_id)
        except Exception as e:
            raise RuntimeError(f"Azure authentication failed: {e}") from e

    def fetch_raw(self) -> dict:
        raw: dict = {
            "vms": [],
            "nsgs": [],
            "storage_accounts": [],
            "key_vaults": [],
        }
        try:
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.keyvault import KeyVaultManagementClient

            compute = ComputeManagementClient(self._credential, self.subscription_id)
            network = NetworkManagementClient(self._credential, self.subscription_id)
            storage = StorageManagementClient(self._credential, self.subscription_id)
            kv = KeyVaultManagementClient(self._credential, self.subscription_id)

            raw["vms"] = [vm.as_dict() for vm in compute.virtual_machines.list_all()]
            raw["nsgs"] = [nsg.as_dict() for nsg in network.network_security_groups.list_all()]
            raw["storage_accounts"] = [sa.as_dict() for sa in storage.storage_accounts.list()]
            raw["key_vaults"] = [vault.as_dict() for vault in kv.vaults.list()]

        except ImportError:
            logger.error("azure-mgmt packages not installed. Run: pip install azure-mgmt-compute azure-mgmt-network azure-mgmt-storage azure-mgmt-keyvault azure-identity")
        except Exception as e:
            logger.error("Azure resource fetch failed: %s", e)
        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []
        now = datetime.utcnow()

        # Internet sentinel
        nodes.append(CanonicalNode(
            canonical_id=INTERNET_CANONICAL_ID,
            node_type=NodeType.INTERNET,
            cloud=Cloud.AZURE,
            account_id="global",
            label="Internet (0.0.0.0/0)",
            scanned_at=now,
        ))

        # NSGs
        nsg_id_map: dict[str, str] = {}
        for nsg in raw.get("nsgs", []):
            resource_id = nsg.get("id", "")
            canonical_id = _azure_canonical(self.subscription_id, resource_id)
            nsg_id_map[resource_id.lower()] = canonical_id

            rules = nsg.get("security_rules", []) + nsg.get("default_security_rules", [])
            inbound_rules = []
            exposes_internet = False

            for rule in rules:
                if rule.get("direction", "").upper() != "INBOUND":
                    continue
                if rule.get("access", "").upper() != "ALLOW":
                    continue
                src = rule.get("source_address_prefix", "")
                dest_port = rule.get("destination_port_range", "")
                protocol = rule.get("protocol", "*")

                if src in ("*", "Internet", "0.0.0.0/0"):
                    exposes_internet = True
                    edges.append(CanonicalEdge(
                        from_id=INTERNET_CANONICAL_ID,
                        to_id=canonical_id,
                        edge_type=EdgeType.EXPOSES_PORT,
                        properties={
                            "port_range": dest_port,
                            "protocol": protocol,
                            "cidr": src,
                            "rule_name": rule.get("name", ""),
                            "priority": rule.get("priority", 0),
                        },
                        scanned_at=now,
                    ))
                inbound_rules.append({
                    "name": rule.get("name", ""),
                    "priority": rule.get("priority", 0),
                    "protocol": protocol,
                    "source": src,
                    "dest_port": dest_port,
                    "access": rule.get("access", ""),
                })

            location = nsg.get("location", "")
            rg = _extract_resource_group(resource_id)
            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AZURE_NSG,
                cloud=Cloud.AZURE,
                account_id=self.subscription_id,
                label=nsg.get("name", resource_id),
                properties={
                    "resource_id": resource_id,
                    "resource_group": rg,
                    "location": location,
                    "inbound_rules": inbound_rules,
                    "exposes_internet": exposes_internet,
                },
                scanned_at=now,
            ))

        # VMs
        for vm in raw.get("vms", []):
            resource_id = vm.get("id", "")
            canonical_id = _azure_canonical(self.subscription_id, resource_id)
            name = vm.get("name", resource_id)
            location = vm.get("location", "")
            rg = _extract_resource_group(resource_id)
            tags = vm.get("tags") or {}

            # Public IP detection
            has_public_ip = False
            public_ip = None
            for nic_ref in vm.get("network_profile", {}).get("network_interfaces", []):
                nic_id = (nic_ref.get("id") or "").lower()
                # Public IP would need separate NIC fetch; mark for enrichment
                # For MVP we flag based on NSG association
                pass

            # Managed identity
            identity = vm.get("identity") or {}
            identity_type = identity.get("type", "None")
            principal_id = identity.get("principal_id", "")
            user_assigned = identity.get("user_assigned_identities") or {}

            # NSG association via NIC (simplified: match by resource group)
            nsg_associations = []
            for nic_ref in vm.get("network_profile", {}).get("network_interfaces", []):
                nic_id = (nic_ref.get("id") or "").lower()
                # Check if any NSG is in same resource group
                for nsg_id_lower, nsg_canonical in nsg_id_map.items():
                    if rg.lower() in nsg_id_lower:
                        nsg_associations.append(nsg_canonical)

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AZURE_VM,
                cloud=Cloud.AZURE,
                account_id=self.subscription_id,
                label=name,
                properties={
                    "resource_id": resource_id,
                    "resource_group": rg,
                    "location": location,
                    "vm_size": vm.get("hardware_profile", {}).get("vm_size", ""),
                    "os_type": vm.get("storage_profile", {}).get("os_disk", {}).get("os_type", ""),
                    "has_public_ip": has_public_ip,
                    "public_ip": public_ip,
                    "identity_type": identity_type,
                    "system_assigned_principal_id": principal_id,
                    "tags": tags,
                },
                scanned_at=now,
            ))

            # NSG edges
            for nsg_canonical in nsg_associations:
                edges.append(CanonicalEdge(
                    from_id=nsg_canonical,
                    to_id=canonical_id,
                    edge_type=EdgeType.ATTACHED_TO_NSG,
                    scanned_at=now,
                ))

            # Managed identity edge (resolved later by Entra connector)
            if principal_id:
                mi_canonical = f"entra://{self.tenant_id}/servicePrincipals/{principal_id}"
                edges.append(CanonicalEdge(
                    from_id=canonical_id,
                    to_id=mi_canonical,
                    edge_type=EdgeType.HAS_MANAGED_IDENTITY,
                    properties={"identity_type": "SystemAssigned"},
                    scanned_at=now,
                ))
            for ua_id, ua_data in user_assigned.items():
                ua_principal_id = (ua_data or {}).get("principal_id", "")
                if ua_principal_id:
                    mi_canonical = f"entra://{self.tenant_id}/servicePrincipals/{ua_principal_id}"
                    edges.append(CanonicalEdge(
                        from_id=canonical_id,
                        to_id=mi_canonical,
                        edge_type=EdgeType.HAS_MANAGED_IDENTITY,
                        properties={"identity_type": "UserAssigned", "resource_id": ua_id},
                        scanned_at=now,
                    ))

        # Storage Accounts
        for sa in raw.get("storage_accounts", []):
            resource_id = sa.get("id", "")
            canonical_id = _azure_canonical(self.subscription_id, resource_id)
            name = sa.get("name", "")
            rg = _extract_resource_group(resource_id)
            tags = sa.get("tags") or {}

            network_rules = sa.get("network_rule_set") or {}
            allow_public = network_rules.get("default_action", "Allow") == "Allow"
            sensitivity = _infer_sensitivity(name, tags)

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AZURE_STORAGE_ACCOUNT,
                cloud=Cloud.AZURE,
                account_id=self.subscription_id,
                label=name,
                properties={
                    "resource_id": resource_id,
                    "resource_group": rg,
                    "location": sa.get("location", ""),
                    "allow_public_access": allow_public,
                    "sku": sa.get("sku", {}).get("name", ""),
                    "sensitivity": sensitivity.value,
                    "tls_version": sa.get("minimum_tls_version", ""),
                    "is_hns_enabled": sa.get("is_hns_enabled", False),
                    "tags": tags,
                },
                scanned_at=now,
            ))

        # Key Vaults
        for vault in raw.get("key_vaults", []):
            resource_id = vault.get("id", "")
            canonical_id = _azure_canonical(self.subscription_id, resource_id)
            name = vault.get("name", "")
            rg = _extract_resource_group(resource_id)
            props = vault.get("properties") or {}
            tags = vault.get("tags") or {}

            # Determine access model: "rbac" or "access_policy"
            enable_rbac = props.get("enable_rbac_authorization", False)
            access_model = "rbac" if enable_rbac else "access_policy"
            public_access = props.get("public_network_access", "Enabled")
            sensitivity = _infer_sensitivity(name, tags)

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AZURE_KEY_VAULT,
                cloud=Cloud.AZURE,
                account_id=self.subscription_id,
                label=name,
                properties={
                    "resource_id": resource_id,
                    "resource_group": rg,
                    "location": vault.get("location", ""),
                    "access_model": access_model,
                    "public_network_access": public_access,
                    "soft_delete_enabled": props.get("enable_soft_delete", True),
                    "sku": props.get("sku", {}).get("name", ""),
                    "sensitivity": sensitivity.value,
                    "tags": tags,
                },
                scanned_at=now,
            ))

            # For access_policy vaults, write CAN_ACCESS_VAULT edges directly
            if access_model == "access_policy":
                for policy in props.get("access_policies", []):
                    principal_oid = policy.get("object_id", "")
                    if not principal_oid:
                        continue
                    perms = policy.get("permissions", {})
                    secret_perms = perms.get("secrets", [])
                    key_perms = perms.get("keys", [])
                    principal_canonical = f"entra://{self.tenant_id}/principals/{principal_oid}"
                    edges.append(CanonicalEdge(
                        from_id=principal_canonical,
                        to_id=canonical_id,
                        edge_type=EdgeType.CAN_ACCESS_VAULT,
                        properties={
                            "access_model": "access_policy",
                            "secret_permissions": secret_perms,
                            "key_permissions": key_perms,
                        },
                        scanned_at=now,
                    ))

        return NormalizedSnapshot(
            cloud=Cloud.AZURE,
            account_id=self.subscription_id,
            nodes=nodes,
            edges=edges,
            raw_source="",
            scanned_at=now,
            errors=errors,
        )


def _extract_resource_group(resource_id: str) -> str:
    parts = resource_id.lower().split("/")
    try:
        idx = parts.index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


SENSITIVITY_KEYWORDS = {
    Sensitivity.CRITICAL: ["secret", "credential", "password", "key", "cert", "prod-secret"],
    Sensitivity.HIGH: ["prod", "production", "customer", "finance", "pci", "hipaa"],
    Sensitivity.MEDIUM: ["staging", "internal", "config"],
    Sensitivity.LOW: ["dev", "test", "sandbox", "log"],
    Sensitivity.PUBLIC: ["public", "static", "cdn"],
}


def _infer_sensitivity(name: str, tags: dict) -> Sensitivity:
    name_lower = name.lower()
    tag_val = tags.get("Sensitivity", tags.get("sensitivity", tags.get("DataClassification", "")))
    if tag_val:
        try:
            return Sensitivity(tag_val.lower())
        except ValueError:
            pass
    for sensitivity, keywords in SENSITIVITY_KEYWORDS.items():
        if any(kw in name_lower for kw in keywords):
            return sensitivity
    return Sensitivity.UNKNOWN

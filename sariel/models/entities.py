"""Sariel canonical entity models — shared across all layers."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from datetime import datetime


class Cloud(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    ONPREM = "onprem"


class NodeType(str, Enum):
    EC2_INSTANCE = "EC2Instance"
    AZURE_VM = "AzureVM"
    ONPREM_HOST = "OnPremHost"          # physical/virtual server not in cloud
    NETWORK_SEGMENT = "NetworkSegment"  # subnet / firewall zone
    SECURITY_GROUP = "SecurityGroup"
    AZURE_NSG = "AzureNSG"
    INTERNET = "Internet"
    IAM_USER = "IAMUser"
    IAM_ROLE = "IAMRole"
    ENTRA_USER = "EntraUser"
    ENTRA_SERVICE_PRINCIPAL = "EntraServicePrincipal"
    ENTRA_GROUP = "EntraGroup"
    AZURE_ROLE_DEFINITION = "AzureRoleDefinition"
    DATA_STORE = "DataStore"
    AZURE_STORAGE_ACCOUNT = "AzureStorageAccount"
    AZURE_KEY_VAULT = "AzureKeyVault"
    AWS_SECRET = "AWSSecret"
    VULNERABILITY = "Vulnerability"
    AWS_ACCOUNT = "AWSAccount"
    AZURE_SUBSCRIPTION = "AzureSubscription"
    CONDITIONAL_ACCESS_POLICY = "ConditionalAccessPolicy"


class EdgeType(str, Enum):
    EXPOSES_PORT = "EXPOSES_PORT"
    ATTACHED_TO = "ATTACHED_TO"
    ATTACHED_TO_NSG = "ATTACHED_TO_NSG"
    HAS_VULN = "HAS_VULN"
    HAS_ROLE = "HAS_ROLE"
    CAN_ASSUME = "CAN_ASSUME"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_ACCESS_VAULT = "CAN_ACCESS_VAULT"
    ASSIGNED_ROLE = "ASSIGNED_ROLE"
    HAS_MANAGED_IDENTITY = "HAS_MANAGED_IDENTITY"
    MEMBER_OF = "MEMBER_OF"
    SAME_IDENTITY = "SAME_IDENTITY"
    FEDERATED_TRUST = "FEDERATED_TRUST"
    CONDITIONAL_ACCESS = "CONDITIONAL_ACCESS"
    BELONGS_TO = "BELONGS_TO"
    CAN_REACH = "CAN_REACH"
    IN_SUBNET = "IN_SUBNET"
    RUNS_SERVICE = "RUNS_SERVICE"


class Sensitivity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class Exposure(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    ISOLATED = "isolated"


# Abstract base labels applied alongside specific node types in Neo4j
BASE_LABELS: dict[NodeType, list[str]] = {
    NodeType.EC2_INSTANCE: ["ComputeAsset"],
    NodeType.AZURE_VM: ["ComputeAsset"],
    NodeType.ONPREM_HOST: ["ComputeAsset"],
    NodeType.NETWORK_SEGMENT: ["NetworkControl"],
    NodeType.SECURITY_GROUP: ["NetworkControl"],
    NodeType.AZURE_NSG: ["NetworkControl"],
    NodeType.IAM_USER: ["IdentityPrincipal"],
    NodeType.IAM_ROLE: ["IdentityPrincipal"],
    NodeType.ENTRA_USER: ["IdentityPrincipal"],
    NodeType.ENTRA_SERVICE_PRINCIPAL: ["IdentityPrincipal"],
    NodeType.ENTRA_GROUP: ["IdentityPrincipal"],
    NodeType.DATA_STORE: ["DataStoreBase"],
    NodeType.AZURE_STORAGE_ACCOUNT: ["DataStoreBase"],
    NodeType.AZURE_KEY_VAULT: ["DataStoreBase"],
    NodeType.AWS_ACCOUNT: ["CloudAccount"],
    NodeType.AZURE_SUBSCRIPTION: ["CloudAccount"],
}


@dataclass
class CanonicalNode:
    canonical_id: str
    node_type: NodeType
    cloud: Cloud
    account_id: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    extra_labels: list[str] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def all_labels(self) -> list[str]:
        base = BASE_LABELS.get(self.node_type, [])
        return [self.node_type.value] + base + self.extra_labels


@dataclass
class CanonicalEdge:
    from_id: str
    to_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    scanned_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NormalizedSnapshot:
    cloud: Cloud
    account_id: str
    nodes: list[CanonicalNode]
    edges: list[CanonicalEdge]
    raw_source: str
    scanned_at: datetime = field(default_factory=datetime.utcnow)
    errors: list[str] = field(default_factory=list)

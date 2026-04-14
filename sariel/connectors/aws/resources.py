"""
AWS Resource Connector — EC2, Security Groups, S3, IAM, Secrets Manager.
Uses boto3. Requires AWS credentials in environment or instance profile.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge, CanonicalNode, Cloud, EdgeType,
    NodeType, NormalizedSnapshot, Sensitivity,
)

logger = logging.getLogger(__name__)

INTERNET_CANONICAL_ID = "internet://0.0.0.0/0"
HIGH_RISK_PORTS = {22, 80, 443, 3389, 8080, 8443, 5432, 3306, 6379, 27017}


def _arn(account_id: str, resource_type: str, resource_id: str, region: str = "") -> str:
    if region:
        return f"arn:aws:{resource_type}:{region}:{account_id}:{resource_id}"
    return f"arn:aws:{resource_type}::{account_id}:{resource_id}"


class AWSResourceConnector(BaseConnector):
    cloud = Cloud.AWS

    def __init__(self, account_id: str, region: str = "us-east-1", role_arn: str = ""):
        self.account_id = account_id
        self.region = region
        self.role_arn = role_arn
        self._session: Optional[boto3.Session] = None

    def authenticate(self) -> None:
        if self.role_arn:
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="sariel-scan",
            )["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        else:
            self._session = boto3.Session(region_name=self.region)
        # Validate credentials
        self._session.client("sts").get_caller_identity()
        logger.info("AWS authentication successful for account %s", self.account_id)

    def _client(self, service: str):
        return self._session.client(service, region_name=self.region)

    def fetch_raw(self) -> dict:
        raw: dict[str, Any] = {}

        # EC2 instances
        try:
            ec2 = self._client("ec2")
            paginator = ec2.get_paginator("describe_instances")
            instances = []
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    instances.extend(reservation["Instances"])
            raw["ec2_instances"] = instances
        except ClientError as e:
            logger.error("Failed to fetch EC2 instances: %s", e)
            raw["ec2_instances"] = []

        # Security Groups
        try:
            ec2 = self._client("ec2")
            paginator = ec2.get_paginator("describe_security_groups")
            sgs = []
            for page in paginator.paginate():
                sgs.extend(page["SecurityGroups"])
            raw["security_groups"] = sgs
        except ClientError as e:
            logger.error("Failed to fetch security groups: %s", e)
            raw["security_groups"] = []

        # IAM users
        try:
            iam = self._client("iam")
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
            # Enrich with MFA status
            mfa_map: dict[str, bool] = {}
            for user in users:
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                    mfa_map[user["UserName"]] = len(mfa_devices) > 0
                except ClientError:
                    mfa_map[user["UserName"]] = False
            raw["iam_users"] = users
            raw["iam_mfa_map"] = mfa_map
        except ClientError as e:
            logger.error("Failed to fetch IAM users: %s", e)
            raw["iam_users"] = []
            raw["iam_mfa_map"] = {}

        # IAM roles
        try:
            iam = self._client("iam")
            paginator = iam.get_paginator("list_roles")
            roles = []
            for page in paginator.paginate():
                roles.extend(page["Roles"])
            # Attach inline + managed policies for each role
            enriched = []
            for role in roles:
                try:
                    attached = iam.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]
                    inline_names = iam.list_role_policies(RoleName=role["RoleName"])["PolicyNames"]
                    inline_docs = {}
                    for pname in inline_names:
                        doc = iam.get_role_policy(RoleName=role["RoleName"], PolicyName=pname)
                        inline_docs[pname] = doc["PolicyDocument"]
                    role["AttachedPolicies"] = attached
                    role["InlinePolicies"] = inline_docs
                    enriched.append(role)
                except ClientError as e:
                    logger.warning("Could not enrich role %s: %s", role["RoleName"], e)
                    enriched.append(role)
            raw["iam_roles"] = enriched
        except ClientError as e:
            logger.error("Failed to fetch IAM roles: %s", e)
            raw["iam_roles"] = []

        # S3 buckets
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            enriched_buckets = []
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    try:
                        s3.get_public_access_block(Bucket=name)
                        bucket["PublicAccessBlocked"] = True
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                            bucket["PublicAccessBlocked"] = False
                        else:
                            bucket["PublicAccessBlocked"] = None
                    tags_resp = s3.get_bucket_tagging(Bucket=name) if True else {}
                    bucket["Tags"] = tags_resp.get("TagSet", []) if tags_resp else []
                except ClientError:
                    bucket["PublicAccessBlocked"] = None
                    bucket["Tags"] = []
                enriched_buckets.append(bucket)
            raw["s3_buckets"] = enriched_buckets
        except ClientError as e:
            logger.error("Failed to fetch S3 buckets: %s", e)
            raw["s3_buckets"] = []

        # Secrets Manager secrets (metadata only — never values)
        try:
            sm = self._client("secretsmanager")
            paginator = sm.get_paginator("list_secrets")
            secrets = []
            for page in paginator.paginate():
                secrets.extend(page["SecretList"])
            raw["secrets"] = secrets
        except ClientError as e:
            logger.warning("Failed to fetch Secrets Manager secrets: %s", e)
            raw["secrets"] = []

        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []
        now = datetime.utcnow()

        # Internet sentinel node (one per graph)
        nodes.append(CanonicalNode(
            canonical_id=INTERNET_CANONICAL_ID,
            node_type=NodeType.INTERNET,
            cloud=Cloud.AWS,
            account_id="global",
            label="Internet (0.0.0.0/0)",
            scanned_at=now,
        ))

        # Security Groups
        sg_id_map: dict[str, str] = {}  # sg_id -> canonical_id
        for sg in raw.get("security_groups", []):
            sg_id = sg["GroupId"]
            canonical_id = _arn(self.account_id, "ec2", f"security-group/{sg_id}", self.region)
            sg_id_map[sg_id] = canonical_id

            # Analyze inbound rules
            inbound_rules = []
            exposes_internet = False
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", -1)
                to_port = rule.get("ToPort", -1)
                protocol = rule.get("IpProtocol", "-1")
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        exposes_internet = True
                        # Create EXPOSES_PORT edge to internet
                        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                        edges.append(CanonicalEdge(
                            from_id=INTERNET_CANONICAL_ID,
                            to_id=canonical_id,
                            edge_type=EdgeType.EXPOSES_PORT,
                            properties={
                                "port_from": from_port,
                                "port_to": to_port,
                                "protocol": protocol,
                                "cidr": cidr,
                                "port_range": port_range,
                            },
                            scanned_at=now,
                        ))
                    inbound_rules.append({
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                        "cidr": cidr,
                    })

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.SECURITY_GROUP,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=sg.get("GroupName", sg_id),
                properties={
                    "sg_id": sg_id,
                    "description": sg.get("Description", ""),
                    "vpc_id": sg.get("VpcId", ""),
                    "region": self.region,
                    "inbound_rules": inbound_rules,
                    "exposes_internet": exposes_internet,
                },
                scanned_at=now,
            ))

        # EC2 Instances
        instance_sg_map: dict[str, list[str]] = {}
        for inst in raw.get("ec2_instances", []):
            if inst.get("State", {}).get("Name") not in ("running", "stopped"):
                continue
            inst_id = inst["InstanceId"]
            canonical_id = _arn(self.account_id, "ec2", f"instance/{inst_id}", self.region)

            public_ip = inst.get("PublicIpAddress")
            has_public_ip = public_ip is not None

            # Collect SG associations
            sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
            instance_sg_map[canonical_id] = sg_ids

            # IAM instance profile
            profile = inst.get("IamInstanceProfile", {})
            profile_arn = profile.get("Arn", "")

            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.EC2_INSTANCE,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=tags.get("Name", inst_id),
                properties={
                    "instance_id": inst_id,
                    "region": self.region,
                    "public_ip": public_ip,
                    "has_public_ip": has_public_ip,
                    "private_ip": inst.get("PrivateIpAddress"),
                    "state": inst.get("State", {}).get("Name"),
                    "instance_type": inst.get("InstanceType"),
                    "ami_id": inst.get("ImageId"),
                    "vpc_id": inst.get("VpcId"),
                    "subnet_id": inst.get("SubnetId"),
                    "instance_profile_arn": profile_arn,
                    "tags": tags,
                },
                scanned_at=now,
            ))

            # SG attachment edges
            for sg_id in sg_ids:
                if sg_id in sg_id_map:
                    edges.append(CanonicalEdge(
                        from_id=sg_id_map[sg_id],
                        to_id=canonical_id,
                        edge_type=EdgeType.ATTACHED_TO,
                        scanned_at=now,
                    ))

        # IAM Roles
        role_arn_map: dict[str, str] = {}  # role_name -> canonical_id
        for role in raw.get("iam_roles", []):
            role_arn_val = role["Arn"]
            role_arn_map[role["RoleName"]] = role_arn_val

            # Determine if over-permissioned
            is_overpermissioned = _check_overpermissioned(role)

            # Parse federated principals from trust policy
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust_policy, str):
                try:
                    trust_policy = json.loads(trust_policy)
                except json.JSONDecodeError:
                    trust_policy = {}
            federated_principals = _extract_federated_principals(trust_policy)

            nodes.append(CanonicalNode(
                canonical_id=role_arn_val,
                node_type=NodeType.IAM_ROLE,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=role["RoleName"],
                properties={
                    "role_name": role["RoleName"],
                    "role_id": role["RoleId"],
                    "region": self.region,
                    "assume_role_policy": json.dumps(trust_policy),
                    "is_overpermissioned": is_overpermissioned,
                    "federated_principals": federated_principals,
                    "attached_policies": [p["PolicyArn"] for p in role.get("AttachedPolicies", [])],
                    "description": role.get("Description", ""),
                },
                scanned_at=now,
            ))

        # IAM Users
        mfa_map = raw.get("iam_mfa_map", {})
        for user in raw.get("iam_users", []):
            user_arn = user["Arn"]
            nodes.append(CanonicalNode(
                canonical_id=user_arn,
                node_type=NodeType.IAM_USER,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=user["UserName"],
                properties={
                    "username": user["UserName"],
                    "user_id": user["UserId"],
                    "region": self.region,
                    "mfa_enabled": mfa_map.get(user["UserName"], False),
                    "password_last_used": str(user.get("PasswordLastUsed", "")),
                    "create_date": str(user.get("CreateDate", "")),
                },
                scanned_at=now,
            ))

        # Link EC2 instance profiles to IAM roles
        for inst_canonical_id, sg_ids in instance_sg_map.items():
            # Get the instance node to read profile_arn
            inst_node = next(
                (n for n in nodes if n.canonical_id == inst_canonical_id), None
            )
            if inst_node:
                profile_arn = inst_node.properties.get("instance_profile_arn", "")
                if profile_arn:
                    # Instance profile ARN pattern: arn:aws:iam::ACCOUNT:instance-profile/ROLE
                    role_name = profile_arn.split("/")[-1]
                    role_arn_val = role_arn_map.get(role_name)
                    if role_arn_val:
                        edges.append(CanonicalEdge(
                            from_id=inst_canonical_id,
                            to_id=role_arn_val,
                            edge_type=EdgeType.HAS_ROLE,
                            scanned_at=now,
                        ))

        # S3 Buckets as DataStore nodes
        for bucket in raw.get("s3_buckets", []):
            name = bucket["Name"]
            canonical_id = f"arn:aws:s3:::{name}"
            tags = {t["Key"]: t["Value"] for t in bucket.get("Tags", [])}
            sensitivity = _infer_sensitivity(name, tags)

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.DATA_STORE,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=name,
                properties={
                    "bucket_name": name,
                    "store_type": "s3",
                    "region": self.region,
                    "sensitivity": sensitivity.value,
                    "public_access_blocked": bucket.get("PublicAccessBlocked"),
                    "tags": tags,
                },
                scanned_at=now,
            ))

        # Secrets Manager secrets (metadata only)
        for secret in raw.get("secrets", []):
            canonical_id = secret.get("ARN", f"arn:aws:secretsmanager:{self.region}:{self.account_id}:secret:{secret['Name']}")
            name = secret.get("Name", "")
            secret_type = _classify_secret(name, secret.get("Description", ""))

            nodes.append(CanonicalNode(
                canonical_id=canonical_id,
                node_type=NodeType.AWS_SECRET,
                cloud=Cloud.AWS,
                account_id=self.account_id,
                label=name,
                properties={
                    "secret_name": name,
                    "region": self.region,
                    "secret_type": secret_type,
                    "description": secret.get("Description", ""),
                    "last_changed": str(secret.get("LastChangedDate", "")),
                },
                scanned_at=now,
            ))

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source="",
            scanned_at=now,
            errors=errors,
        )


def _check_overpermissioned(role: dict) -> bool:
    """Return True if any attached or inline policy grants wildcard actions."""
    for policy_doc in role.get("InlinePolicies", {}).values():
        if isinstance(policy_doc, dict):
            for stmt in policy_doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "*" in actions or "iam:*" in actions:
                    return True
    return False


def _extract_federated_principals(trust_policy: dict) -> list[str]:
    """
    Extract OIDC/SAML federated principals from a role trust policy.
    Used to detect cross-cloud federation (Entra → AWS).
    """
    principals = []
    for stmt in trust_policy.get("Statement", []):
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            federated = principal.get("Federated")
            if federated:
                if isinstance(federated, list):
                    principals.extend(federated)
                else:
                    principals.append(federated)
            # Also check conditions for OIDC subject claims
            conditions = stmt.get("Condition", {})
            for condition_type, condition_map in conditions.items():
                for condition_key, condition_val in condition_map.items():
                    if "sub" in condition_key.lower() or "subject" in condition_key.lower():
                        if isinstance(condition_val, list):
                            principals.extend(condition_val)
                        else:
                            principals.append(str(condition_val))
    return principals


SENSITIVITY_KEYWORDS = {
    Sensitivity.CRITICAL: ["secret", "prod-secret", "credential", "password", "private-key", "ssn", "pii"],
    Sensitivity.HIGH: ["prod", "production", "customer", "user-data", "pci", "hipaa", "finance"],
    Sensitivity.MEDIUM: ["staging", "stage", "internal", "config"],
    Sensitivity.LOW: ["dev", "development", "test", "sandbox", "logs", "analytics"],
    Sensitivity.PUBLIC: ["public", "static", "assets", "cdn"],
}


def _infer_sensitivity(name: str, tags: dict) -> Sensitivity:
    name_lower = name.lower()
    tag_sensitivity = tags.get("Sensitivity", tags.get("sensitivity", tags.get("data-classification", "")))
    if tag_sensitivity:
        try:
            return Sensitivity(tag_sensitivity.lower())
        except ValueError:
            pass
    for sensitivity, keywords in SENSITIVITY_KEYWORDS.items():
        if any(kw in name_lower for kw in keywords):
            return sensitivity
    return Sensitivity.UNKNOWN


def _classify_secret(name: str, description: str) -> str:
    """Classify a secret to detect potential cross-cloud credentials."""
    combined = f"{name} {description}".lower()
    if any(kw in combined for kw in ["azure", "entra", "tenant_id", "client_secret", "client_id"]):
        return "entra_service_principal"
    if any(kw in combined for kw in ["gcp", "google", "service_account"]):
        return "gcp_service_account"
    if any(kw in combined for kw in ["database", "db_password", "rds", "postgres", "mysql"]):
        return "database_credential"
    if any(kw in combined for kw in ["api_key", "api-key", "apikey"]):
        return "api_key"
    return "generic"

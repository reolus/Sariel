"""Unit tests for AWS connector normalization logic."""
import pytest
from unittest.mock import MagicMock, patch
from sariel.connectors.aws.resources import (
    AWSResourceConnector, _check_overpermissioned,
    _extract_federated_principals, _infer_sensitivity, _classify_secret,
)
from sariel.models.entities import Cloud, NodeType, EdgeType


SAMPLE_RAW = {
    "ec2_instances": [
        {
            "InstanceId": "i-0abc123",
            "State": {"Name": "running"},
            "PublicIpAddress": "54.1.2.3",
            "PrivateIpAddress": "10.0.1.5",
            "InstanceType": "t3.medium",
            "ImageId": "ami-0abc123",
            "VpcId": "vpc-001",
            "SubnetId": "sub-001",
            "SecurityGroups": [{"GroupId": "sg-001", "GroupName": "web-sg"}],
            "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/WebRole"},
            "Tags": [{"Key": "Name", "Value": "web-server-01"}],
        }
    ],
    "security_groups": [
        {
            "GroupId": "sg-001",
            "GroupName": "web-sg",
            "Description": "Web server SG",
            "VpcId": "vpc-001",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ],
    "iam_users": [
        {
            "UserId": "AIDAUSER001",
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "CreateDate": "2022-01-01",
        }
    ],
    "iam_mfa_map": {"alice": False},
    "iam_roles": [
        {
            "RoleId": "AROAROLE001",
            "RoleName": "WebRole",
            "Arn": "arn:aws:iam::123456789012:role/WebRole",
            "AssumeRolePolicyDocument": {"Statement": []},
            "AttachedPolicies": [],
            "InlinePolicies": {},
        }
    ],
    "s3_buckets": [
        {"Name": "prod-secrets-bucket", "Tags": [], "PublicAccessBlocked": True},
        {"Name": "public-static-assets", "Tags": [], "PublicAccessBlocked": False},
    ],
    "secrets": [],
}


@pytest.fixture
def connector():
    c = AWSResourceConnector(account_id="123456789012", region="us-east-1")
    return c


class TestNormalizeRaw:
    def test_internet_sentinel_created(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        internet_nodes = [n for n in snap.nodes if n.canonical_id == "internet://0.0.0.0/0"]
        assert len(internet_nodes) == 1

    def test_ec2_instance_node_created(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        ec2_nodes = [n for n in snap.nodes if n.node_type == NodeType.EC2_INSTANCE]
        assert len(ec2_nodes) == 1
        assert ec2_nodes[0].label == "web-server-01"
        assert ec2_nodes[0].properties["has_public_ip"] is True
        assert ec2_nodes[0].properties["public_ip"] == "54.1.2.3"

    def test_security_group_node_created(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        sg_nodes = [n for n in snap.nodes if n.node_type == NodeType.SECURITY_GROUP]
        assert len(sg_nodes) == 1
        assert sg_nodes[0].properties["exposes_internet"] is True

    def test_exposes_port_edge_to_internet(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        expose_edges = [e for e in snap.edges if e.edge_type == EdgeType.EXPOSES_PORT]
        assert len(expose_edges) == 1
        assert expose_edges[0].from_id == "internet://0.0.0.0/0"
        assert expose_edges[0].properties["port_from"] == 443

    def test_iam_user_node_created(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        user_nodes = [n for n in snap.nodes if n.node_type == NodeType.IAM_USER]
        assert len(user_nodes) == 1
        assert user_nodes[0].properties["mfa_enabled"] is False

    def test_s3_sensitivity_inferred(self, connector):
        snap = connector.normalize_raw(SAMPLE_RAW)
        ds_nodes = [n for n in snap.nodes if n.node_type == NodeType.DATA_STORE]
        sensitivity_map = {n.label: n.properties["sensitivity"] for n in ds_nodes}
        assert sensitivity_map["prod-secrets-bucket"] == "critical"
        assert sensitivity_map["public-static-assets"] == "public"


class TestHelpers:
    def test_overpermissioned_wildcard_action(self):
        role = {
            "InlinePolicies": {
                "admin": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }
        assert _check_overpermissioned(role) is True

    def test_not_overpermissioned_scoped_action(self):
        role = {
            "InlinePolicies": {
                "s3read": {
                    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
                }
            }
        }
        assert _check_overpermissioned(role) is False

    def test_federated_principals_extraction(self):
        trust_policy = {
            "Statement": [
                {
                    "Principal": {"Federated": "arn:aws:iam::123:oidc-provider/sts.windows.net/tenant-id"},
                    "Condition": {
                        "StringEquals": {
                            "sts:RoleSessionName": "sariel",
                            "token.actions.githubusercontent.com:sub": "some-entra-object-id",
                        }
                    },
                }
            ]
        }
        principals = _extract_federated_principals(trust_policy)
        assert "arn:aws:iam::123:oidc-provider/sts.windows.net/tenant-id" in principals
        assert "some-entra-object-id" in principals

    def test_classify_secret_entra(self):
        assert _classify_secret("azure-sp-credentials", "client_id and client_secret for Entra") == "entra_service_principal"

    def test_classify_secret_generic(self):
        assert _classify_secret("my-api-token", "") == "api_key"

    @pytest.mark.parametrize("name,expected", [
        ("prod-secrets", "critical"),
        ("customer-data", "high"),
        ("staging-config", "medium"),
        ("dev-logs", "low"),
        ("public-assets", "public"),
        ("some-bucket", "unknown"),
    ])
    def test_sensitivity_inference(self, name, expected):
        result = _infer_sensitivity(name, {})
        assert result.value == expected

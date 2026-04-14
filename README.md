# Sariel — Cloud Attack Path Detection

Context-aware security platform that ingests AWS + Azure/Entra data, builds a
unified graph, detects real-world attack paths, and prioritizes the handful of
risks that actually matter.

## Quick Start

```bash
# 1. Start infrastructure
cp .env.example .env
# Edit .env with your credentials
docker-compose up neo4j postgres redis -d

# 2. Install dependencies
pip install -e ".[azure,llm]"

# 3. Initialize databases
python scripts/init_db.py

# 4. Start API
uvicorn sariel.api.main:app --reload

# 5. Start scheduler (separate terminal)
python -m sariel.scheduler.jobs
```

## Run everything with Docker

```bash
docker-compose up
```

API will be available at http://localhost:8000
Docs at http://localhost:8000/docs
Neo4j browser at http://localhost:7474

## Key Endpoints

| Endpoint | Description |
|---|---|
| `GET /risks?min_score=50` | Ranked attack paths |
| `GET /risks?severity=CRITICAL&cloud=aws` | Filtered by severity + cloud |
| `GET /paths/{id}` | Full path detail with nodes, edges, fixes |
| `GET /paths/{id}?with_explanation=true` | With LLM explanation |
| `GET /assets?node_type=EC2Instance&has_public_ip=true` | Asset inventory |
| `GET /assets/search?q=prod` | Asset search |
| `GET /admin/health` | Health check |
| `POST /admin/scan/trigger` | Trigger path analysis |

## Architecture

```
AWS connectors ─┐
                ├─► Task Queue ─► Normalization ─► Neo4j Graph ─► Attack Path Engine ─► Postgres
Azure connectors┘                                                       ↑
Entra connector ──────────────────────────────────────────────── Scoring Engine
                                                                        ↓
                                                               FastAPI ─► REST API
```

## Attack Path Patterns

| Pattern | Description |
|---|---|
| `public_vuln_data_access` | Internet-reachable compute + exploitable CVE → sensitive data |
| `identity_abuse` | No-MFA user → over-permissioned role → sensitive data |
| `overpermissioned_role` | Public compute with wildcard role → sensitive data |
| `entra_group_escalation` | Role-assignable Entra group → privileged RBAC role |
| `cross_cloud_federation` | Azure Managed Identity federated to AWS IAM → sensitive data |

## Risk Score Formula

```
RiskScore = 100 × E × X × P × S

E = Exposure        (public=1.0, internal=0.4, isolated=0.1)
X = Exploitability  (CVSS exploitScore/3.9, or pattern baseline)
P = Privilege gain  (admin=1.0, write=0.7, read=0.4)
S = Sensitivity     (critical=1.0, high=0.7, medium=0.4, public=0.05)
```

Scores ≥ 70 = CRITICAL. Scores ≥ 40 = HIGH. Scores < 10 = suppressed.

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## AWS IAM Policy (minimum required)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
        "iam:ListUsers", "iam:ListRoles", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListMFADevices",
        "s3:ListAllMyBuckets", "s3:GetBucketTagging", "s3:GetPublicAccessBlock",
        "secretsmanager:ListSecrets",
        "inspector2:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

## Azure Permissions

- ARM service principal: **Reader** at subscription scope
- Entra app registration: `Directory.Read.All`, `RoleManagement.Read.All`, `Policy.Read.All`

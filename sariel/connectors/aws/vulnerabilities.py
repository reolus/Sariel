"""
AWS Vulnerability Connector — pulls from AWS Inspector v2 and enriches with NVD.
"""
from __future__ import annotations
import logging
import time
from datetime import datetime
from typing import Optional

import boto3
import requests
from botocore.exceptions import ClientError

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge, CanonicalNode, Cloud, EdgeType,
    NodeType, NormalizedSnapshot,
)

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class AWSVulnConnector(BaseConnector):
    cloud = Cloud.AWS

    def __init__(self, account_id: str, region: str = "us-east-1", role_arn: str = ""):
        self.account_id = account_id
        self.region = region
        self.role_arn = role_arn
        self._session: Optional[boto3.Session] = None
        self._nvd_cache: dict[str, dict] = {}

    def authenticate(self) -> None:
        if self.role_arn:
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=self.role_arn, RoleSessionName="sariel-vuln-scan"
            )["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        else:
            self._session = boto3.Session(region_name=self.region)

    def _client(self, service: str):
        return self._session.client(service, region_name=self.region)

    def fetch_raw(self) -> dict:
        raw: dict = {"findings": [], "instance_map": {}}
        try:
            inspector = self._client("inspector2")
            paginator = inspector.get_paginator("list_findings")
            findings = []
            for page in paginator.paginate(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                    "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
                }
            ):
                findings.extend(page["findings"])
            raw["findings"] = findings
        except ClientError as e:
            logger.error("Inspector v2 not available or access denied: %s", e)
        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []
        now = datetime.utcnow()
        seen_cves: set[str] = set()

        for finding in raw.get("findings", []):
            try:
                vuln_pkg = finding.get("packageVulnerabilityDetails", {})
                cve_id = vuln_pkg.get("vulnerabilityId", "")
                if not cve_id:
                    continue

                # Which EC2 instances does this affect?
                affected_instances = []
                for resource in finding.get("resources", []):
                    if resource.get("type") == "AWS_EC2_INSTANCE":
                        inst_id = resource.get("id", "")
                        if inst_id:
                            inst_canonical = (
                                f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{inst_id}"
                            )
                            affected_instances.append(inst_canonical)

                cvss_score = 0.0
                cvss_exploitability = 0.0
                for score_obj in finding.get("cvssScore", []):
                    if score_obj.get("source") in ("NVD", "NIST"):
                        cvss_score = float(score_obj.get("score", 0))
                        break
                # Fallback to finding severity
                if cvss_score == 0:
                    severity_map = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
                    cvss_score = severity_map.get(finding.get("severity", "LOW"), 2.5)

                # NVD enrichment for exploit availability
                has_exploit = False
                nvd_data = self._fetch_nvd(cve_id)
                if nvd_data:
                    cvss_exploitability = nvd_data.get("exploitability_score", 0.0)
                    has_exploit = nvd_data.get("has_exploit", False)
                else:
                    # Estimate from CVSS
                    cvss_exploitability = min(cvss_score * 0.4, 3.9)

                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    nodes.append(CanonicalNode(
                        canonical_id=f"cve://{cve_id}",
                        node_type=NodeType.VULNERABILITY,
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=cve_id,
                        properties={
                            "cve_id": cve_id,
                            "cvss_score": cvss_score,
                            "cvss_exploitability_score": cvss_exploitability,
                            "has_exploit": has_exploit,
                            "severity": finding.get("severity", ""),
                            "affected_package": vuln_pkg.get("vulnerablePackages", [{}])[0].get("name", "") if vuln_pkg.get("vulnerablePackages") else "",
                            "fixed_version": vuln_pkg.get("vulnerablePackages", [{}])[0].get("fixedInVersion", "") if vuln_pkg.get("vulnerablePackages") else "",
                            "description": finding.get("description", "")[:500],
                        },
                        scanned_at=now,
                    ))

                for inst_canonical in affected_instances:
                    edges.append(CanonicalEdge(
                        from_id=inst_canonical,
                        to_id=f"cve://{cve_id}",
                        edge_type=EdgeType.HAS_VULN,
                        properties={
                            "detected_at": str(finding.get("firstObservedAt", now)),
                            "source": "aws_inspector",
                        },
                        scanned_at=now,
                    ))

            except Exception as e:
                errors.append(f"Failed to process finding: {e}")

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source="",
            scanned_at=now,
            errors=errors,
        )

    def _fetch_nvd(self, cve_id: str) -> Optional[dict]:
        """Fetch CVE details from NVD API v2. Cached per run."""
        if cve_id in self._nvd_cache:
            return self._nvd_cache[cve_id]
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                timeout=10,
                headers={"User-Agent": "Sariel-Security-Scanner/1.0"},
            )
            if resp.status_code == 429:
                logger.warning("NVD rate limited — sleeping 10s")
                time.sleep(10)
                resp = requests.get(NVD_API_URL, params={"cveId": cve_id}, timeout=10)

            if resp.status_code != 200:
                return None

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            exploitability_score = 0.0
            cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss_v3:
                primary = next((m for m in cvss_v3 if m.get("type") == "Primary"), cvss_v3[0])
                exploitability_score = float(
                    primary.get("cvssData", {}).get("exploitabilityScore", 0)
                )

            # Check for known exploits via weaknesses
            weaknesses = cve_data.get("weaknesses", [])
            has_exploit = any(
                "exploit" in str(w).lower() for w in weaknesses
            )

            result = {
                "exploitability_score": exploitability_score,
                "has_exploit": has_exploit,
            }
            self._nvd_cache[cve_id] = result
            return result

        except Exception as e:
            logger.warning("NVD fetch failed for %s: %s", cve_id, e)
            return None

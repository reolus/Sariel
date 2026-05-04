from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from neo4j import Driver


DEFAULT_ACK_DAYS = 180


@dataclass
class AcknowledgementResult:
    target_id: str
    target_name: str | None
    hidden_attack_paths: int
    expires_at: str | None


class AcknowledgementService:
    def __init__(self, driver: Driver):
        self.driver = driver

    def acknowledge_target(
        self,
        *,
        target_ref: str,
        acknowledged_by: str,
        reason: str,
        days: int = DEFAULT_ACK_DAYS,
    ) -> AcknowledgementResult:
        query = """
        MATCH (target:ComputeAsset)
        WHERE target.canonical_id = $target_ref
           OR toLower(target.hostname) = toLower($target_ref)
           OR toLower(target.label) = toLower($target_ref)
           OR toLower(target.sys_name) = toLower($target_ref)
           OR target.private_ip = $target_ref
           OR target.ip_key = $target_ref

        WITH target
        LIMIT 1

        SET
          target.acknowledged = true,
          target.hidden = true,
          target.acknowledged_at = datetime(),
          target.acknowledged_by = $acknowledged_by,
          target.acknowledgement_reason = $reason,
          target.acknowledgement_scope = 'target',
          target.ack_expires_at = datetime() + duration({days: $days})

        WITH target

        OPTIONAL MATCH (ap:AttackPath)
        WHERE ap.target_id = target.canonical_id
           OR ap.target_ip = target.private_ip
           OR toLower(ap.target) = toLower(target.hostname)
           OR toLower(ap.target) = toLower(target.label)

        SET
          ap.acknowledged = true,
          ap.hidden = true,
          ap.acknowledged_at = datetime(),
          ap.acknowledged_by = $acknowledged_by,
          ap.acknowledgement_reason = $reason,
          ap.acknowledgement_scope = 'inherited_from_target',
          ap.acknowledged_parent_id = target.canonical_id,
          ap.ack_expires_at = target.ack_expires_at

        RETURN
          target.canonical_id AS target_id,
          coalesce(target.hostname, target.label, target.private_ip) AS target_name,
          count(ap) AS hidden_attack_paths,
          toString(target.ack_expires_at) AS expires_at
        """

        with self.driver.session() as session:
            row = session.run(
                query,
                target_ref=target_ref,
                acknowledged_by=acknowledged_by,
                reason=reason,
                days=days,
            ).single()

        if row is None:
            raise ValueError(f"No target found for {target_ref}")

        return AcknowledgementResult(
            target_id=row["target_id"],
            target_name=row["target_name"],
            hidden_attack_paths=row["hidden_attack_paths"],
            expires_at=row["expires_at"],
        )

    def unacknowledge_target(self, *, target_ref: str) -> dict[str, Any]:
        query = """
        MATCH (target:ComputeAsset)
        WHERE target.canonical_id = $target_ref
           OR toLower(target.hostname) = toLower($target_ref)
           OR toLower(target.label) = toLower($target_ref)
           OR toLower(target.sys_name) = toLower($target_ref)
           OR target.private_ip = $target_ref
           OR target.ip_key = $target_ref

        WITH target
        LIMIT 1

        REMOVE
          target.acknowledged,
          target.hidden,
          target.acknowledged_at,
          target.acknowledged_by,
          target.acknowledgement_reason,
          target.acknowledgement_scope,
          target.ack_expires_at

        WITH target

        OPTIONAL MATCH (ap:AttackPath)
        WHERE ap.acknowledged_parent_id = target.canonical_id

        REMOVE
          ap.acknowledged,
          ap.hidden,
          ap.acknowledged_at,
          ap.acknowledged_by,
          ap.acknowledgement_reason,
          ap.acknowledgement_scope,
          ap.acknowledged_parent_id,
          ap.ack_expires_at

        RETURN
          target.canonical_id AS target_id,
          coalesce(target.hostname, target.label, target.private_ip) AS target_name,
          count(ap) AS restored_attack_paths
        """

        with self.driver.session() as session:
            row = session.run(query, target_ref=target_ref).single()

        if row is None:
            raise ValueError(f"No target found for {target_ref}")

        return dict(row)

    def list_acknowledged_targets(self) -> list[dict[str, Any]]:
        query = """
        MATCH (target:ComputeAsset)
        WHERE coalesce(target.acknowledged, false) = true
          AND (
            target.ack_expires_at IS NULL
            OR target.ack_expires_at > datetime()
          )

        OPTIONAL MATCH (ap:AttackPath)
        WHERE ap.acknowledged_parent_id = target.canonical_id

        RETURN
          target.canonical_id AS target_id,
          coalesce(target.hostname, target.label, target.private_ip) AS target_name,
          target.private_ip AS target_ip,
          target.acknowledged_by AS acknowledged_by,
          target.acknowledgement_reason AS reason,
          toString(target.acknowledged_at) AS acknowledged_at,
          toString(target.ack_expires_at) AS expires_at,
          count(ap) AS hidden_attack_paths
        ORDER BY target.ack_expires_at ASC
        """

        with self.driver.session() as session:
            return [dict(row) for row in session.run(query)]
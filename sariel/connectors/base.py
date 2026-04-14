"""Abstract base connector — all cloud connectors implement this interface."""
from __future__ import annotations
import abc
import json
import logging
from datetime import datetime
from typing import Optional

import boto3

from sariel.models.entities import Cloud, NormalizedSnapshot

logger = logging.getLogger(__name__)


class BaseConnector(abc.ABC):
    """
    Pull data from a cloud source, normalize it, and return a snapshot.

    Subclasses implement: authenticate(), fetch_raw(), normalize_raw().
    The orchestrate() method ties them together and handles raw storage.
    """

    cloud: Cloud
    account_id: str

    @abc.abstractmethod
    def authenticate(self) -> None:
        """Establish authenticated session. Raise on failure."""

    @abc.abstractmethod
    def fetch_raw(self) -> dict:
        """Pull raw data from the cloud API. Return as a dict."""

    @abc.abstractmethod
    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        """Convert raw API responses to canonical nodes and edges."""

    def store_raw(self, raw: dict, bucket: str) -> str:
        """
        Write raw snapshot to S3 for audit trail.
        Returns the S3 key.
        """
        ts = datetime.utcnow().strftime("%Y/%m/%d/%H%M%S")
        key = f"raw/{self.cloud.value}/{self.account_id}/{ts}.json"
        try:
            s3 = boto3.client("s3")
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(raw, default=str),
                ContentType="application/json",
            )
            logger.info("Stored raw snapshot: s3://%s/%s", bucket, key)
        except Exception as exc:
            logger.warning("Failed to store raw snapshot: %s", exc)
            key = f"local://{key}"  # fallback label for non-S3 environments
        return key

    def orchestrate(self, raw_bucket: Optional[str] = None) -> NormalizedSnapshot:
        """
        Full connector run:
        1. Authenticate
        2. Fetch raw
        3. Store raw (optional)
        4. Normalize
        5. Return snapshot
        """
        logger.info("[%s] Starting connector run for account %s", self.cloud.value, self.account_id)
        self.authenticate()

        raw = self.fetch_raw()
        logger.info("[%s] Fetched raw data (%d top-level keys)", self.cloud.value, len(raw))

        raw_key = "none"
        if raw_bucket:
            raw_key = self.store_raw(raw, raw_bucket)

        snapshot = self.normalize_raw(raw)
        snapshot.raw_source = raw_key
        logger.info(
            "[%s] Normalized snapshot: %d nodes, %d edges, %d errors",
            self.cloud.value,
            len(snapshot.nodes),
            len(snapshot.edges),
            len(snapshot.errors),
        )
        return snapshot

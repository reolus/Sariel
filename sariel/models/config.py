"""Sariel runtime configuration via environment variables."""
from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Neo4j
    neo4j_uri: str = Field("bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field("neo4j", env="NEO4J_USER")
    neo4j_password: str = Field("sariel-dev", env="NEO4J_PASSWORD")

    # Postgres
    postgres_dsn: str = Field(
        "postgresql+asyncpg://sariel:sariel-dev@localhost:5432/sariel",
        env="POSTGRES_DSN",
    )

    # Redis
    redis_url: str = Field("redis://localhost:6379/0", env="REDIS_URL")
    cache_ttl_seconds: int = Field(900, env="CACHE_TTL_SECONDS")

    # AWS
    aws_account_id: str = Field("", env="AWS_ACCOUNT_ID")
    aws_region: str = Field("us-east-1", env="AWS_REGION")
    aws_role_arn: str = Field("", env="AWS_ROLE_ARN")  # for cross-account

    # Azure
    azure_tenant_id: str = Field("", env="AZURE_TENANT_ID")
    azure_client_id: str = Field("", env="AZURE_CLIENT_ID")
    azure_client_secret: str = Field("", env="AZURE_CLIENT_SECRET")
    azure_subscription_id: str = Field("", env="AZURE_SUBSCRIPTION_ID")

    # LLM explainer (optional)
    openai_api_key: str = Field("", env="OPENAI_API_KEY")
    anthropic_api_key: str = Field("", env="ANTHROPIC_API_KEY")
    llm_provider: str = Field("anthropic", env="LLM_PROVIDER")  # anthropic | openai | none

    # S3 raw storage
    raw_bucket: str = Field("sariel-raw-snapshots", env="RAW_BUCKET")

    # Risk thresholds
    score_critical_threshold: float = Field(70.0, env="SCORE_CRITICAL_THRESHOLD")
    score_high_threshold: float = Field(40.0, env="SCORE_HIGH_THRESHOLD")
    score_suppress_below: float = Field(10.0, env="SCORE_SUPPRESS_BELOW")

    # API
    api_key_header: str = Field("X-Sariel-Key", env="API_KEY_HEADER")
    api_keys: list[str] = Field(default_factory=list, env="API_KEYS")

    # Scheduler
    poll_interval_hours: int = Field(6, env="POLL_INTERVAL_HOURS")
    identity_poll_interval_hours: int = Field(1, env="IDENTITY_POLL_INTERVAL_HOURS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()

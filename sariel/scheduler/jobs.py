"""
Scheduler — APScheduler jobs for polling connectors and running analysis.
Runs as a standalone process alongside the API.
"""
from __future__ import annotations
import asyncio
import logging
import uuid
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from neo4j import GraphDatabase

from sariel.connectors.aws.resources import AWSResourceConnector
from sariel.connectors.aws.vulnerabilities import AWSVulnConnector
from sariel.connectors.azure.resources import AzureResourceConnector
from sariel.connectors.azure.entra import EntraConnector
from sariel.connectors.fortinet.inventory import FortinetReachabilityConnector
from sariel.connectors.solarwinds.inventory import SolarWindsInventoryConnector
from sariel.connectors.manageengine.inventory import ManageEngineInventoryConnector
from sariel.engine.runner import AttackPathRunner
from sariel.explainer.llm import LLMExplainer
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings
from sariel.scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)


async def job_aws_ingest():
    """Pull AWS resources + IAM + vulns, write to graph."""
    settings = get_settings()
    if not settings.aws_account_id:
        logger.info("AWS account ID not configured — skipping AWS ingest")
        return

    logger.info("Starting AWS ingest job")
    snapshot_id = str(uuid.uuid4())

    writer = GraphWriter(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    writer.connect()

    try:
        # Resources
        resource_conn = AWSResourceConnector(
            account_id=settings.aws_account_id,
            region=settings.aws_region,
            role_arn=settings.aws_role_arn,
        )
        snapshot = resource_conn.orchestrate(raw_bucket=settings.raw_bucket or None)
        stats = writer.write_snapshot(snapshot)
        logger.info("AWS resources written: %s", stats)

        # Vulnerabilities
        vuln_conn = AWSVulnConnector(
            account_id=settings.aws_account_id,
            region=settings.aws_region,
            role_arn=settings.aws_role_arn,
        )
        vuln_snapshot = vuln_conn.orchestrate(raw_bucket=settings.raw_bucket or None)
        vuln_stats = writer.write_snapshot(vuln_snapshot)
        logger.info("AWS vulns written: %s", vuln_stats)

    except Exception as e:
        logger.error("AWS ingest failed: %s", e, exc_info=True)
    finally:
        writer.close()

    # Trigger path analysis after ingest
    await job_run_analysis(snapshot_id=snapshot_id)


async def job_azure_ingest():
    """Pull Azure resources + Entra, write to graph."""
    settings = get_settings()
    if not settings.azure_tenant_id:
        logger.info("Azure tenant ID not configured — skipping Azure ingest")
        return

    logger.info("Starting Azure ingest job")
    snapshot_id = str(uuid.uuid4())

    writer = GraphWriter(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    writer.connect()

    try:
        # Azure resources
        if settings.azure_subscription_id:
            resource_conn = AzureResourceConnector(
                subscription_id=settings.azure_subscription_id,
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
            )
            snapshot = resource_conn.orchestrate()
            stats = writer.write_snapshot(snapshot)
            logger.info("Azure resources written: %s", stats)

        # Entra ID
        entra_conn = EntraConnector(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
            subscription_id=settings.azure_subscription_id,
        )
        entra_snapshot = entra_conn.orchestrate()
        entra_stats = writer.write_snapshot(entra_snapshot)
        logger.info("Entra data written: %s", entra_stats)

    except Exception as e:
        logger.error("Azure ingest failed: %s", e, exc_info=True)
    finally:
        writer.close()

    await job_run_analysis(snapshot_id=snapshot_id)


async def job_onprem_ingest():
    """Pull Fortinet, SolarWinds, and ManageEngine data, write to graph, then link."""
    import os as _os
    settings = get_settings()
    snapshot_id = str(uuid.uuid4())
    logger.info("Starting on-prem ingest (snapshot_id=%s)", snapshot_id)
    writer = GraphWriter(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    writer.connect()
    try:
        # Fortinet
        for key, value in _os.environ.items():
            if key.startswith("FORTINET_") and key.endswith("_URL") and value:
                name_part = key[len("FORTINET_"):-len("_URL")].lower().replace("_", "-")
                token = _os.environ.get(key.replace("_URL", "_TOKEN"), "")
                vdom = _os.environ.get(key.replace("_URL", "_VDOM"), "root")
                if not token:
                    continue
                try:
                    conn = FortinetReachabilityConnector(base_url=value, api_token=token, account_id=settings.onprem_account_id, device_name=name_part, vdom=vdom, verify_ssl=settings.fortinet_verify_ssl)
                    conn.authenticate()
                    writer.write_snapshot(conn.normalize_raw(conn.fetch_raw()))
                    logger.info("Fortinet %s ingested", name_part)
                except Exception as e:
                    logger.error("Fortinet %s failed: %s", name_part, e)
        # SolarWinds
        if settings.solarwinds_base_url:
            try:
                sw = SolarWindsInventoryConnector(base_url=settings.solarwinds_base_url, username=settings.solarwinds_username, password=settings.solarwinds_password, account_id=settings.onprem_account_id, verify_ssl=settings.solarwinds_verify_ssl)
                sw.authenticate()
                writer.write_snapshot(sw.normalize_raw(sw.fetch_raw()))
                logger.info("SolarWinds ingested")
            except Exception as e:
                logger.error("SolarWinds failed: %s", e)
        # ManageEngine
        if settings.manageengine_base_url:
            try:
                me = ManageEngineInventoryConnector(base_url=settings.manageengine_base_url, auth_header=settings.manageengine_auth_header, account_id=settings.onprem_account_id, verify_ssl=settings.manageengine_verify_ssl)
                me.authenticate()
                writer.write_snapshot(me.normalize_raw(me.fetch_raw()))
                logger.info("ManageEngine ingested")
            except Exception as e:
                logger.error("ManageEngine failed: %s", e)
        await job_post_ingest_enrich()
    finally:
        writer.close()


async def job_post_ingest_enrich():
    """Run OS normalization, port enrichment, and network linking after ingestion."""
    import sys, os as _os
    sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..", ".."))
    from scripts.post_ingest_link import run_post_ingest_enrichment
    settings = get_settings()
    try:
        summary = run_post_ingest_enrichment(neo4j_uri=settings.neo4j_uri, neo4j_user=settings.neo4j_user, neo4j_password=settings.neo4j_password, account_id=settings.onprem_account_id)
        logger.info("Post-ingest enrichment: %s", summary)
    except Exception as e:
        logger.error("Post-ingest enrichment failed: %s", e, exc_info=True)


async def job_run_analysis(snapshot_id: str | None = None):
    """Run attack path analysis and update scores."""
    settings = get_settings()
    logger.info("Starting attack path analysis (snapshot_id=%s)", snapshot_id)

    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    scoring = ScoringEngine(
        critical_threshold=settings.score_critical_threshold,
        high_threshold=settings.score_high_threshold,
        suppress_below=settings.score_suppress_below,
    )
    runner = AttackPathRunner(
        neo4j_driver=driver,
        pg_dsn=settings.postgres_dsn,
        scoring_engine=scoring,
    )

    try:
        summary = await runner.run_all_patterns(snapshot_id=snapshot_id)
        logger.info("Analysis complete: %s", summary)

        # Generate LLM explanations for high/critical paths
        provider = settings.llm_provider
        api_key = settings.anthropic_api_key if provider == "anthropic" else settings.openai_api_key
        if provider != "none" and api_key:
            explainer = LLMExplainer(provider=provider, api_key=api_key)
            paths = await runner.get_paths(min_score=settings.score_high_threshold)
            explanations = await explainer.explain_batch(paths)
            logger.info("Generated %d LLM explanations", len(explanations))

    except Exception as e:
        logger.error("Analysis job failed: %s", e, exc_info=True)
    finally:
        driver.close()


def create_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler()

    # AWS ingest — every N hours
    scheduler.add_job(
        job_aws_ingest,
        trigger=IntervalTrigger(hours=settings.poll_interval_hours),
        id="aws_ingest",
        name="AWS Resource + Vuln Ingest",
        replace_existing=True,
        misfire_grace_time=300,
    )

    # Azure ingest — every N hours (Entra identity every 1h)
    scheduler.add_job(
        job_azure_ingest,
        trigger=IntervalTrigger(hours=settings.identity_poll_interval_hours),
        id="azure_ingest",
        name="Azure Resource + Entra Ingest",
        replace_existing=True,
        misfire_grace_time=300,
    )

    # On-prem ingest — Fortinet + SolarWinds + ManageEngine + post-link
    scheduler.add_job(
        job_onprem_ingest,
        trigger=IntervalTrigger(hours=settings.poll_interval_hours),
        id="onprem_ingest",
        name="On-Prem Ingest + Network Linking",
        replace_existing=True,
        misfire_grace_time=600,
    )

    return scheduler


async def run_scheduler():
    """Entry point for the scheduler process."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    logger.info("Sariel scheduler starting")

    # Run an initial ingest on startup
    await job_aws_ingest()
    await job_azure_ingest()
    await job_onprem_ingest()

    scheduler = create_scheduler()
    scheduler.start()

    try:
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Sariel scheduler shutting down")
        scheduler.shutdown()


if __name__ == "__main__":
    asyncio.run(run_scheduler())

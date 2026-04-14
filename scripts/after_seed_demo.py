import asyncio
from neo4j import GraphDatabase
from sariel.engine.runner import AttackPathRunner
from sariel.models.config import get_settings

s = get_settings()
driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))

runner = AttackPathRunner(driver, s.postgres_dsn)

asyncio.run(runner.run_all_patterns())

# curl http://localhost:8000/risks
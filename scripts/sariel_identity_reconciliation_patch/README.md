# Sariel Identity Reconciliation Patch

This patch fixes the split-graph problem where vulnerability data is attached to one asset node while `CAN_REACH` exists on a different host node representing the same machine.

## Files

- `sariel/normalization/host_identity.py`  
  Normalizes hostname, FQDN, and IP identity keys.

- `sariel/normalization/graph_reconciler.py`  
  Repairs existing Neo4j data by adding host identity keys, repairing missing vulnerability `name`, creating `SAME_AS` relationships, and copying `HAS_VULN` relationships to reachable host nodes.

- `sariel/ingest/reconcile_graph.py`  
  CLI runner.

- `sariel/connectors/nessus/nessus.py`  
  Small forward fix so future vulnerability nodes get a `name` property.

- `cypher/identity_health_check.cypher`  
  Quick Neo4j checks.

- `cypher/attack_map_reconciled.cypher`  
  Attack-map query after reconciliation.

## Install

From your Sariel repo root:

```bash
unzip sariel_identity_reconciliation_patch.zip -d /tmp/sariel_identity_patch
cp -r /tmp/sariel_identity_patch/sariel/* /etc/docker/Sariel/sariel/
```

## Run dry-run

```bash
cd /etc/docker/Sariel
source .venv/bin/activate
python -m sariel.ingest.reconcile_graph --dry-run
```

## Apply repair

```bash
python -m sariel.ingest.reconcile_graph
```

## Verify

Run the contents of:

```text
cypher/identity_health_check.cypher
```

The important line is:

```text
Hosts with vuln and reachability
```

That value should no longer be zero.

## Attack map

After reconciliation, run:

```cypher
MATCH (src)
WHERE toLower(coalesce(src.label, src.hostname, src.name, '')) CONTAINS toLower($nodeName)
MATCH p = (src)-[:CAN_REACH*1..4]->(target)
MATCH vulnPath = (target)-[:HAS_VULN]->(v:Vulnerability)
WHERE coalesce(v.severity, vulnPath.severity) IN ['CRITICAL', 'HIGH']
RETURN p, vulnPath
LIMIT 100;
```

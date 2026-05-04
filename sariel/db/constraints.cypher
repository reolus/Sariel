CREATE CONSTRAINT compute_asset_canonical_id IF NOT EXISTS
FOR (n:ComputeAsset)
REQUIRE n.canonical_id IS UNIQUE;

CREATE CONSTRAINT attack_path_canonical_id IF NOT EXISTS
FOR (ap:AttackPath)
REQUIRE ap.canonical_id IS UNIQUE;

CREATE INDEX attack_path_hidden IF NOT EXISTS
FOR (ap:AttackPath)
ON (ap.hidden);

CREATE INDEX attack_path_ack_parent IF NOT EXISTS
FOR (ap:AttackPath)
ON (ap.acknowledged_parent_id);

CREATE INDEX compute_asset_hidden IF NOT EXISTS
FOR (n:ComputeAsset)
ON (n.hidden);
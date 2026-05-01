# Network switch ingestion

Sariel can ingest Aruba and Cisco switch configuration to create graph evidence for real network reachability. The switch connector parses VLANs, SVIs/routed interfaces, static routes, ACLs, access ports, trunk ports, and connected subnets.

## Install

```bash
pip install -e ".[network]"
```

The base project includes `PyYAML`. The `network` extra adds Netmiko for live switch collection.

## Offline test with saved configs

Use this first. Place configs in a directory named `<switch-name>.cfg`, matching the inventory name.

```bash
python -m sariel.ingest.network_switches \
  --inventory examples/network_switches/switches.yaml \
  --offline-config-dir examples/network_switches
```

## Live collection

```bash
python -m sariel.ingest.network_switches \
  --inventory examples/network_switches/switches.yaml
```

## What it writes

Nodes:
- `Switch`
- `SwitchInterface`
- `Vlan`
- `Subnet`
- `Route`

Relationships:
- `HAS_INTERFACE`
- `HAS_VLAN`
- `ACCESS_VLAN`
- `TRUNKS_VLAN`
- `IN_SUBNET`
- `ROUTES_SUBNET`
- `HAS_ROUTE`
- `ROUTES_TO`
- `ACL_RULE`
- `CAN_REACH`

`CAN_REACH` is created from:
- connected routed interfaces / SVIs on the same L3 switch
- static routes
- permit ACL entries

Deny ACL entries are preserved as `ACL_RULE` evidence. They are not converted into `CAN_REACH` because a deny is not reachability. A shocking revelation, apparently.

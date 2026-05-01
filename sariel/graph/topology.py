def ensure_subnet(tx, subnet):
    tx.run("""
        MERGE (:Subnet {cidr: $subnet})
    """, subnet=subnet)


def link_host_to_subnet(tx, host_id, subnet):
    tx.run("""
        MATCH (h:ComputeAsset {id: $host_id})
        MERGE (s:Subnet {cidr: $subnet})
        MERGE (h)-[:IN_SUBNET]->(s)
    """, host_id=host_id, subnet=subnet)


def connect_same_subnet(tx):
    tx.run("""
        MATCH (a:ComputeAsset)-[:IN_SUBNET]->(s:Subnet)<-[:IN_SUBNET]-(b:ComputeAsset)
        WHERE a <> b
        MERGE (a)-[:CAN_REACH]->(b)
    """)


def connect_subnets(tx, src_subnet, dst_subnet):
    tx.run("""
        MATCH (s1:Subnet {cidr: $src})
        MATCH (s2:Subnet {cidr: $dst})
        MERGE (s1)-[:CAN_REACH]->(s2)
    """, src=src_subnet, dst=dst_subnet)


def expand_subnet_reachability(tx):
    tx.run("""
        MATCH (a:ComputeAsset)-[:IN_SUBNET]->(s1:Subnet)-[:CAN_REACH]->(s2:Subnet)<-[:IN_SUBNET]-(b:ComputeAsset)
        MERGE (a)-[:CAN_REACH]->(b)
    """)

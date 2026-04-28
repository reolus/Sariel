from sariel.connectors.ad import ActiveDirectoryConnector
from sariel.connectors.dns import DNSInventoryConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings


def write_snapshot(snapshot):
    settings = get_settings()
    writer = GraphWriter(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()

    print(snapshot.raw_source, stats)
    for err in snapshot.errors[:50]:
        print(" -", err)


def csv_list(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def main():
    settings = get_settings()

    if settings.dns_hostnames or settings.dns_reverse_cidrs:
        dns = DNSInventoryConnector(
            account_id="dns",
            hostnames=csv_list(settings.dns_hostnames),
            reverse_cidrs=csv_list(settings.dns_reverse_cidrs),
        )
        write_snapshot(dns.orchestrate())

    if settings.ad_server_uri:
        ad = ActiveDirectoryConnector(
            server_uri=settings.ad_server_uri,
            bind_user=settings.ad_bind_user,
            bind_password=settings.ad_bind_password,
            base_dn=settings.ad_base_dn,
            account_id="active-directory",
            use_ssl=settings.ad_use_ssl,
        )
        write_snapshot(ad.orchestrate())


if __name__ == "__main__":
    main()
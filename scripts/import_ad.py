from sariel.connectors.ad import ActiveDirectoryConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings

def main()
    settings = get_settings()

    ad = ActiveDirectoryConnector(
        server_uri=settings.ad_server_uri,
        bind_user=settings.ad_bind_user,
        bind_password=settings.ad_bind_password,
        base_dn=settings.ad_base_dn,
        account_id=active-directory,
        use_ssl=settings.ad_use_ssl,
    )

    snapshot = ad.orchestrate()

    writer = GraphWriter(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
    )

    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()

    print(AD Import, stats)

if __name__ == __main__
    main()
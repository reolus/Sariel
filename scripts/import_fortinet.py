from sariel.connectors.fortinet import FortinetReachabilityConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings


def main():
    settings = get_settings()

    connector = FortinetReachabilityConnector(
        base_url=settings.fortinet_base_url,
        api_token=settings.fortinet_api_token,
        account_id="fortinet",
        vdom=settings.fortinet_vdom,
        verify_ssl=settings.fortinet_verify_ssl,
    )

    snapshot = connector.orchestrate()

    writer = GraphWriter(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
    )
    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()

    print("Fortinet import:", stats)

    if snapshot.errors:
        print("Errors:")
        for err in snapshot.errors[:100]:
            print(" -", err)


if __name__ == "__main__":
    main()
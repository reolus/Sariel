from sariel.connectors.manageengine.inventory import ManageEngineInventoryConnector
from sariel.connectors.solarwinds.inventory import SolarWindsInventoryConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings


def write_snapshot(snapshot):
    s = get_settings()
    writer = GraphWriter(s.neo4j_uri, s.neo4j_user, s.neo4j_password)
    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()
    print(snapshot.raw_source, stats)
    for err in snapshot.errors:
        print(" -", err)


def main():
    s = get_settings()

    if getattr(s, "manageengine_base_url", ""):
        me = ManageEngineInventoryConnector(
            base_url=s.manageengine_base_url,
            auth_header=s.manageengine_auth_header,
            account_id=getattr(s, "onprem_account_id", "onprem"),
            verify_ssl=getattr(s, "manageengine_verify_ssl", True),
        )
        write_snapshot(me.orchestrate())

    if getattr(s, "solarwinds_base_url", ""):
        sw = SolarWindsInventoryConnector(
            base_url=s.solarwinds_base_url,
            username=s.solarwinds_username,
            password=s.solarwinds_password,
            account_id=getattr(s, "onprem_account_id", "onprem"),
            verify_ssl=getattr(s, "solarwinds_verify_ssl", False),
        )
        write_snapshot(sw.orchestrate())


if __name__ == "__main__":
    main()
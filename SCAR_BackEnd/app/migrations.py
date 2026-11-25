"""Small additive migration for databases created by the earlier backend schema."""

from sqlalchemy import DateTime, Float, Integer, String, Text, inspect, text
from sqlalchemy.engine import Engine

from app.models import TelemetryRecord


def upgrade_security_event_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    if not inspector.has_table("security_events"):
        return

    existing = {column["name"] for column in inspector.get_columns("security_events")}
    additions = {
        "severity_value": Integer(),
        "sensor_agent_id": String(100),
        "sensor_agent_name": String(100),
        "sensor_agent_ip": String(45),
        "sensor_ip": String(45),
        "ai_severity_label": String(20),
        "agent_name": String(100),
        "model_version": String(100),
        "risk_score": Float(),
        "category": String(100),
        "confidence": Float(),
        "explanation": Text(),
        "recommended_action": Text(),
        "created_at": DateTime(),
        "drone_id": String(50),
        "boot_id": String(64),
        "event_sequence": Integer(),
        "schema_version": String(20),
        "disposition": String(30),
        "sensor_id": String(100),
        "src_port": Integer(),
        "dst_port": Integer(),
        "protocol": String(20),
        "zeek_uid": String(100),
        "dedup_key": String(400),
    }
    preparer = engine.dialect.identifier_preparer
    table_name = preparer.quote("security_events")

    with engine.begin() as connection:
        for name, sql_type in additions.items():
            if name in existing:
                continue
            column_name = preparer.quote(name)
            compiled_type = sql_type.compile(dialect=engine.dialect)
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {compiled_type}"))

        # Translate the two earlier status spellings into the agreed Security Team values.
        connection.execute(
            text(f"UPDATE {table_name} SET status = 'new' WHERE status = 'open'")
        )
        connection.execute(
            text(f"UPDATE {table_name} SET status = 'investigating' WHERE status = 'acknowledged'")
        )
        # false_positive is a classification (disposition), not a workflow status: keep it in disposition, close the alert.
        connection.execute(
            text(
                f"UPDATE {table_name} SET disposition = COALESCE(disposition, 'false_positive'), status = 'resolved' "
                "WHERE status = 'false_positive'"
            )
        )
        # One row per idempotency key. NULL keys are allowed many times (older rows and events without a key).
        # Same index name the model uses, so a fresh database and an upgraded one end up identical.
        connection.execute(
            text(f"CREATE UNIQUE INDEX IF NOT EXISTS ix_security_events_dedup_key ON {table_name} (dedup_key)")
        )
        if "device_ip" in existing or "device_ip" in additions:
            connection.execute(
                text(
                    f"UPDATE {table_name} SET sensor_agent_ip = device_ip "
                    "WHERE sensor_agent_ip IS NULL AND device_ip IS NOT NULL"
                )
            )


_TELEMETRY_NEW = ("boot_id", "schema_version", "system_status")


def upgrade_telemetry_table(engine: Engine) -> None:
    """Move an older telemetry table to the contract layout.

    The unique key changed from (drone_id, sequence) to (drone_id, boot_id, sequence). SQLite cannot
    change a constraint in place, so the table is rebuilt: old rows are copied, boot_id becomes "0"
    and schema_version "1.0". Nothing is lost. Runs once; it does nothing on a current database.
    """
    inspector = inspect(engine)
    if not inspector.has_table("telemetry"):
        return
    existing = {column["name"] for column in inspector.get_columns("telemetry")}
    if all(name in existing for name in _TELEMETRY_NEW):
        return

    if engine.dialect.name != "sqlite":
        # other databases: columns can be added, but the old unique key must be replaced with Alembic
        with engine.begin() as connection:
            for name, ddl in (("boot_id", "VARCHAR(64) NOT NULL DEFAULT '0'"),
                              ("schema_version", "VARCHAR(20) NOT NULL DEFAULT '1.0'"),
                              ("system_status", "VARCHAR(50)")):
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE telemetry ADD COLUMN {name} {ddl}"))
        return

    table = TelemetryRecord.__table__
    copy_columns = [c.name for c in table.columns if c.name in existing]
    column_list = ", ".join(copy_columns)
    with engine.begin() as connection:
        for index in inspector.get_indexes("telemetry"):
            if index.get("name"):
                connection.execute(text(f'DROP INDEX IF EXISTS "{index["name"]}"'))
        connection.execute(text("ALTER TABLE telemetry RENAME TO telemetry_old"))
        table.create(connection)
        connection.execute(text(f"INSERT INTO telemetry ({column_list}) SELECT {column_list} FROM telemetry_old"))
        connection.execute(text("DROP TABLE telemetry_old"))

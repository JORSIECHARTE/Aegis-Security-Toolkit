import sqlite3

from config import DATABASE_PATH
from utils.logger import get_logger


logger = get_logger(__name__)


DATABASE_VERSION = 1


def connect():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def table_exists(connection, table_name):
    cursor = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table_name,),
    )

    return cursor.fetchone() is not None


def get_table_columns(connection, table_name):
    cursor = connection.execute(
        f"PRAGMA table_info({table_name})"
    )

    return {
        row[1]
        for row in cursor.fetchall()
    }


def create_english_schema(connection):
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL,
            ip TEXT NOT NULL,
            start_port INTEGER NOT NULL,
            end_port INTEGER NOT NULL,
            ports_scanned INTEGER NOT NULL,
            open_ports INTEGER NOT NULL,
            duration_seconds REAL NOT NULL
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            service TEXT NOT NULL,
            response_time_ms REAL NOT NULL,
            banner TEXT,
            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
                ON DELETE CASCADE
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
        ON scan_results(scan_id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_scan_results_port
        ON scan_results(port)
        """
    )


def database_uses_legacy_schema(connection):
    if not table_exists(connection, "scans"):
        return False

    scan_columns = get_table_columns(
        connection,
        "scans",
    )

    return "fecha" in scan_columns


def database_uses_english_schema(connection):
    if not table_exists(connection, "scans"):
        return False

    scan_columns = get_table_columns(
        connection,
        "scans",
    )

    required_columns = {
        "id",
        "scan_date",
        "ip",
        "start_port",
        "end_port",
        "ports_scanned",
        "open_ports",
        "duration_seconds",
    }

    return required_columns.issubset(
        scan_columns
    )


def migrate_legacy_database():
    logger.info(
        "Starting legacy database migration."
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    try:
        connection.execute(
            "PRAGMA foreign_keys = OFF"
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        legacy_scans_exist = table_exists(
            connection,
            "scans",
        )

        legacy_results_exist = table_exists(
            connection,
            "scan_results",
        )

        if legacy_results_exist:
            connection.execute(
                """
                ALTER TABLE scan_results
                RENAME TO scan_results_legacy
                """
            )

        if legacy_scans_exist:
            connection.execute(
                """
                ALTER TABLE scans
                RENAME TO scans_legacy
                """
            )

        create_english_schema(connection)

        if legacy_scans_exist:
            connection.execute(
                """
                INSERT INTO scans (
                    id,
                    scan_date,
                    ip,
                    start_port,
                    end_port,
                    ports_scanned,
                    open_ports,
                    duration_seconds
                )
                SELECT
                    id,
                    fecha,
                    ip,
                    puerto_inicio,
                    puerto_fin,
                    puertos_analizados,
                    puertos_abiertos,
                    duracion_segundos
                FROM scans_legacy
                ORDER BY id
                """
            )

        if legacy_results_exist:
            connection.execute(
                """
                INSERT INTO scan_results (
                    id,
                    scan_id,
                    port,
                    status,
                    service,
                    response_time_ms,
                    banner
                )
                SELECT
                    id,
                    scan_id,
                    puerto,
                    estado,
                    servicio,
                    tiempo_ms,
                    banner
                FROM scan_results_legacy
                ORDER BY id
                """
            )

        if legacy_results_exist:
            connection.execute(
                """
                DROP TABLE scan_results_legacy
                """
            )

        if legacy_scans_exist:
            connection.execute(
                """
                DROP TABLE scans_legacy
                """
            )

        connection.execute(
            f"PRAGMA user_version = {DATABASE_VERSION}"
        )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()

        logger.exception(
            "Legacy database migration failed."
        )

        raise

    finally:
        connection.close()

    with connect() as verification_connection:
        foreign_key_errors = (
            verification_connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
        )

        if foreign_key_errors:
            logger.error(
                (
                    "Database migration completed "
                    "with foreign-key inconsistencies."
                )
            )

            raise RuntimeError(
                "The database migration completed, "
                "but foreign-key validation detected "
                "inconsistencies."
            )

    logger.info(
        "Legacy database migration completed successfully."
    )


def initialize_database():
    logger.info(
        "Initializing database."
    )

    with connect() as connection:
        legacy_schema = (
            database_uses_legacy_schema(
                connection
            )
        )

        english_schema = (
            database_uses_english_schema(
                connection
            )
        )

    if legacy_schema:
        logger.info(
            "Legacy database schema detected."
        )

        migrate_legacy_database()
        return

    if english_schema:
        with connect() as connection:
            create_english_schema(
                connection
            )

            connection.execute(
                f"PRAGMA user_version = "
                f"{DATABASE_VERSION}"
            )

        logger.info(
            "Database initialized with existing English schema."
        )

        return

    logger.info(
        "No compatible database schema detected. "
        "Creating database schema."
    )

    with connect() as connection:
        create_english_schema(
            connection
        )

        connection.execute(
            f"PRAGMA user_version = "
            f"{DATABASE_VERSION}"
        )

    logger.info(
        "Database schema created successfully."
    )


def save_scan(scan_result):
    logger.info(
        (
            "Saving scan result. "
            "Target=%s, open ports=%s."
        ),
        scan_result["ip"],
        scan_result["open_ports"],
    )

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO scans (
                scan_date,
                ip,
                start_port,
                end_port,
                ports_scanned,
                open_ports,
                duration_seconds
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result["scan_date"],
                scan_result["ip"],
                scan_result["start_port"],
                scan_result["end_port"],
                scan_result["ports_scanned"],
                scan_result["open_ports"],
                scan_result["duration_seconds"],
            ),
        )

        scan_id = cursor.lastrowid

        for result in scan_result["results"]:
            cursor.execute(
                """
                INSERT INTO scan_results (
                    scan_id,
                    port,
                    status,
                    service,
                    response_time_ms,
                    banner
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    result["port"],
                    result["status"],
                    result["service"],
                    result["response_time_ms"],
                    result.get(
                        "banner",
                        "",
                    ),
                ),
            )

    logger.info(
        (
            "Scan saved successfully. "
            "ID=%s, results=%s."
        ),
        scan_id,
        len(scan_result["results"]),
    )

    return scan_id


def get_scans():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                scan_date,
                ip,
                start_port,
                end_port,
                ports_scanned,
                open_ports,
                duration_seconds
            FROM scans
            ORDER BY id DESC
            """
        )

        return cursor.fetchall()


def get_scan_results(scan_id):
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                port,
                status,
                service,
                response_time_ms,
                banner
            FROM scan_results
            WHERE scan_id = ?
            ORDER BY port ASC
            """,
            (scan_id,),
        )

        return cursor.fetchall()


def get_dashboard_metrics():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*),
                COALESCE(SUM(open_ports), 0),
                COALESCE(AVG(duration_seconds), 0)
            FROM scans
            """
        )

        (
            total_scans,
            total_open_ports,
            average_duration,
        ) = cursor.fetchone()

        cursor.execute(
            """
            SELECT ip
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        )

        latest_scan = cursor.fetchone()

    latest_target = (
        latest_scan[0]
        if latest_scan
        else "No data"
    )

    return {
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "average_duration": round(
            average_duration,
            2,
        ),
        "latest_target": latest_target,
    }


def get_detected_services():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                service,
                COUNT(*) AS detection_count
            FROM scan_results
            GROUP BY service
            ORDER BY detection_count DESC
            """
        )

        return cursor.fetchall()


def get_recent_scans(limit=5):
    safe_limit = max(
        1,
        int(limit),
    )

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                scan_date,
                ip,
                start_port,
                end_port,
                open_ports,
                duration_seconds
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

        return cursor.fetchall()


def get_most_detected_ports(limit=10):
    safe_limit = max(
        1,
        int(limit),
    )

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                port,
                service,
                COUNT(*) AS detection_count
            FROM scan_results
            GROUP BY port, service
            ORDER BY detection_count DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

        return cursor.fetchall()


def get_scan_history():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                scan_date,
                ip,
                open_ports,
                duration_seconds
            FROM scans
            ORDER BY id ASC
            """
        )

        return cursor.fetchall()


def get_open_ports_by_scan():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                scan_date,
                ip,
                open_ports
            FROM scans
            ORDER BY id ASC
            """
        )

        return cursor.fetchall()
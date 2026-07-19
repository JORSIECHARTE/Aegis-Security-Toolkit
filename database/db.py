import sqlite3


DB_PATH = "aegis.db"


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with connect() as connection:
        cursor = connection.cursor()

        # Se mantiene el esquema para no romper las bases existentes.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TEXT NOT NULL,
                ip TEXT NOT NULL,
                puerto_inicio INTEGER NOT NULL,
                puerto_fin INTEGER NOT NULL,
                puertos_analizados INTEGER NOT NULL,
                puertos_abiertos INTEGER NOT NULL,
                duracion_segundos REAL NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                puerto INTEGER NOT NULL,
                estado TEXT NOT NULL,
                servicio TEXT NOT NULL,
                tiempo_ms REAL NOT NULL,
                banner TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
            """
        )


def save_scan(scan_result):
    scan_date = scan_result["scan_date"]
    ip_address = scan_result["ip"]
    start_port = scan_result["start_port"]
    end_port = scan_result["end_port"]
    ports_scanned = scan_result["ports_scanned"]
    open_ports = scan_result["open_ports"]
    duration_seconds = scan_result["duration_seconds"]
    results = scan_result["results"]

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO scans (
                fecha,
                ip,
                puerto_inicio,
                puerto_fin,
                puertos_analizados,
                puertos_abiertos,
                duracion_segundos
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_date,
                ip_address,
                start_port,
                end_port,
                ports_scanned,
                open_ports,
                duration_seconds,
            ),
        )

        scan_id = cursor.lastrowid

        for result in results:
            cursor.execute(
                """
                INSERT INTO scan_results (
                    scan_id,
                    puerto,
                    estado,
                    servicio,
                    tiempo_ms,
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
                    result.get("banner", ""),
                ),
            )

    return scan_id


def get_scans():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                fecha,
                ip,
                puerto_inicio,
                puerto_fin,
                puertos_analizados,
                puertos_abiertos,
                duracion_segundos
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
                puerto,
                estado,
                servicio,
                tiempo_ms,
                banner
            FROM scan_results
            WHERE scan_id = ?
            ORDER BY puerto ASC
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
                COALESCE(SUM(puertos_abiertos), 0),
                COALESCE(AVG(duracion_segundos), 0)
            FROM scans
            """
        )

        total_scans, total_open_ports, average_duration = cursor.fetchone()

        cursor.execute(
            """
            SELECT ip
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        )

        latest_scan = cursor.fetchone()

    latest_target = latest_scan[0] if latest_scan else "No data"

    return {
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "average_duration": round(average_duration, 2),
        "latest_target": latest_target,
    }


def get_detected_services():
    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                servicio,
                COUNT(*) AS detection_count
            FROM scan_results
            GROUP BY servicio
            ORDER BY detection_count DESC
            """
        )

        return cursor.fetchall()


def get_recent_scans(limit=5):
    safe_limit = max(1, int(limit))

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                fecha,
                ip,
                puerto_inicio,
                puerto_fin,
                puertos_abiertos,
                duracion_segundos
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

        return cursor.fetchall()


def get_most_detected_ports(limit=10):
    safe_limit = max(1, int(limit))

    with connect() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                puerto,
                servicio,
                COUNT(*) AS detection_count
            FROM scan_results
            GROUP BY puerto, servicio
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
                fecha,
                ip,
                puertos_abiertos,
                duracion_segundos
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
                fecha,
                ip,
                puertos_abiertos
            FROM scans
            ORDER BY id ASC
            """
        )

        return cursor.fetchall()
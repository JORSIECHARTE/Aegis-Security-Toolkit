import sqlite3


DB_PATH = "aegis.db"


def conectar():
    return sqlite3.connect(DB_PATH)


def inicializar_db():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
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
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            puerto INTEGER NOT NULL,
            estado TEXT NOT NULL,
            servicio TEXT NOT NULL,
            tiempo_ms REAL NOT NULL,
            banner TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


def guardar_scan(resultado_scan):
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
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
    """, (
        resultado_scan["fecha"],
        resultado_scan["ip"],
        resultado_scan["puerto_inicio"],
        resultado_scan["puerto_fin"],
        resultado_scan["puertos_analizados"],
        resultado_scan["puertos_abiertos"],
        resultado_scan["duracion_segundos"]
    ))

    scan_id = cursor.lastrowid

    for item in resultado_scan["resultados"]:
        cursor.execute("""
            INSERT INTO scan_results (
                scan_id,
                puerto,
                estado,
                servicio,
                tiempo_ms,
                banner
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            item["puerto"],
            item["estado"],
            item["servicio"],
            item["tiempo_ms"],
            item["banner"]
        ))

    conn.commit()
    conn.close()

    return scan_id


def obtener_scans():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
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
    """)

    filas = cursor.fetchall()
    conn.close()

    return filas


def obtener_resultados_scan(scan_id):
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            puerto,
            estado,
            servicio,
            tiempo_ms,
            banner
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY puerto ASC
    """, (scan_id,))

    filas = cursor.fetchall()
    conn.close()

    return filas


def obtener_metricas_dashboard():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(puertos_abiertos), 0) FROM scans")
    total_puertos_abiertos = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(AVG(duracion_segundos), 0) FROM scans")
    promedio_duracion = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)
    ultimo = cursor.fetchone()
    ultimo_objetivo = ultimo[0] if ultimo else "Sin datos"

    conn.close()

    return {
        "total_scans": total_scans,
        "total_puertos_abiertos": total_puertos_abiertos,
        "promedio_duracion": round(promedio_duracion, 2),
        "ultimo_objetivo": ultimo_objetivo
    }
    
def obtener_servicios_detectados():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT servicio, COUNT(*) as cantidad
        FROM scan_results
        GROUP BY servicio
        ORDER BY cantidad DESC
    """)

    filas = cursor.fetchall()
    conn.close()

    return filas

def obtener_ultimos_scans(limite=5):
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
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
    """, (limite,))

    filas = cursor.fetchall()
    conn.close()

    return filas


def obtener_puertos_mas_detectados(limite=10):
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT puerto, servicio, COUNT(*) as cantidad
        FROM scan_results
        GROUP BY puerto, servicio
        ORDER BY cantidad DESC
        LIMIT ?
    """, (limite,))

    filas = cursor.fetchall()
    conn.close()

    return filas

def get_scan_history():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            fecha,
            ip,
            puertos_abiertos,
            duracion_segundos
        FROM scans
        ORDER BY id ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows


def get_open_ports_by_scan():
    conn = conectar()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            scans.id,
            scans.fecha,
            scans.ip,
            scans.puertos_abiertos
        FROM scans
        ORDER BY scans.id ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows
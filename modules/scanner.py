import socket
import time
import csv
import io
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Dev",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8501: "Streamlit"
}


def obtener_servicio(puerto):
    if puerto in COMMON_SERVICES:
        return COMMON_SERVICES[puerto]

    try:
        return socket.getservbyport(puerto, "tcp").upper()
    except Exception:
        return "Desconocido"


def obtener_banner(ip, puerto, timeout=1):
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)

            if puerto in [80, 8080, 8000, 8501]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif puerto in [443, 8443]:
                return "TLS/HTTPS detectado. Banner no leído sin handshake TLS."
            else:
                s.sendall(b"\r\n")

            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
                return banner if banner else "Sin banner visible"
            except socket.timeout:
                return "Sin respuesta de banner"

    except Exception:
        return "No disponible"


def escanear_puerto(ip, puerto, timeout=0.3, banner=False):
    inicio = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            resultado = s.connect_ex((ip, puerto))
            tiempo_respuesta = round((time.perf_counter() - inicio) * 1000, 4)

            if resultado == 0:
                return {
                    "puerto": puerto,
                    "estado": "Abierto",
                    "servicio": obtener_servicio(puerto),
                    "tiempo_ms": tiempo_respuesta,
                    "banner": obtener_banner(ip, puerto) if banner else "No solicitado"
                }

    except Exception:
        pass

    return None


def escanear_rango(ip, puerto_inicio, puerto_fin, timeout=0.3, banner=False, workers=100):
    resultados = []
    inicio_scan = time.perf_counter()
    total_puertos = puerto_fin - puerto_inicio + 1

    workers = min(workers, total_puertos)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        tareas = {
            executor.submit(escanear_puerto, ip, puerto, timeout, banner): puerto
            for puerto in range(puerto_inicio, puerto_fin + 1)
        }

        for tarea in as_completed(tareas):
            resultado = tarea.result()
            if resultado:
                resultados.append(resultado)

    resultados.sort(key=lambda x: x["puerto"])

    duracion = round(time.perf_counter() - inicio_scan, 2)

    return {
        "ip": ip,
        "puerto_inicio": puerto_inicio,
        "puerto_fin": puerto_fin,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duracion_segundos": duracion,
        "puertos_analizados": total_puertos,
        "puertos_abiertos": len(resultados),
        "resultados": resultados
    }


def generar_reporte_txt(resultado_scan):
    reporte = f"""
AEGIS SECURITY TOOLKIT - REPORTE DE ESCANEO

Objetivo: {resultado_scan['ip']}
Fecha: {resultado_scan['fecha']}
Rango: {resultado_scan['puerto_inicio']} - {resultado_scan['puerto_fin']}
Puertos analizados: {resultado_scan['puertos_analizados']}
Duración: {resultado_scan['duracion_segundos']} segundos
Puertos abiertos: {resultado_scan['puertos_abiertos']}

RESULTADOS:
"""

    for item in resultado_scan["resultados"]:
        reporte += (
            f"\nPuerto: {item['puerto']}"
            f"\nEstado: {item['estado']}"
            f"\nServicio: {item['servicio']}"
            f"\nTiempo: {item['tiempo_ms']} ms"
            f"\nBanner: {item['banner']}"
            f"\n-----------------------------\n"
        )

    return reporte


def generar_reporte_csv(resultado_scan):
    salida = io.StringIO()

    campos = ["puerto", "estado", "servicio", "tiempo_ms", "banner"]
    writer = csv.DictWriter(salida, fieldnames=campos)

    writer.writeheader()
    writer.writerows(resultado_scan["resultados"])

    return salida.getvalue()
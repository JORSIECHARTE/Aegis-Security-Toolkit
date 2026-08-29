import csv
import io
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import (
    BANNER_RECEIVE_SIZE,
    DEFAULT_BANNER_TIMEOUT,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_SCAN_WORKERS,
)
from services.service_risk import get_service_risk


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
    8501: "Streamlit",
}


def get_service_name(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def get_banner(
    ip,
    port,
    timeout=DEFAULT_BANNER_TIMEOUT,
):
    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ) as connection:
            connection.settimeout(timeout)

            if port in {80, 8000, 8080, 8501}:
                connection.sendall(
                    b"HEAD / HTTP/1.0\r\n\r\n"
                )

            elif port in {443, 8443}:
                return (
                    "TLS/HTTPS detected. "
                    "Banner not read without a TLS handshake."
                )

            else:
                connection.sendall(b"\r\n")

            try:
                banner = (
                    connection.recv(BANNER_RECEIVE_SIZE)
                    .decode(errors="ignore")
                    .strip()
                )

                return (
                    banner
                    if banner
                    else "No visible banner"
                )

            except socket.timeout:
                return "No banner response"

    except (
        ConnectionError,
        OSError,
        socket.timeout,
    ):
        return "Not available"


def scan_port(
    ip,
    port,
    timeout=DEFAULT_SCAN_TIMEOUT,
    banner=False,
):
    start_time = time.perf_counter()

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as connection:
            connection.settimeout(timeout)

            connection_result = connection.connect_ex(
                (ip, port)
            )

            response_time_ms = round(
                (
                    time.perf_counter()
                    - start_time
                )
                * 1000,
                4,
            )

            if connection_result != 0:
                return None

            service_name = get_service_name(port)
            risk_info = get_service_risk(
                service_name
            )

            return {
                "port": port,
                "status": "Open",
                "service": service_name,
                "risk": risk_info["risk"],
                "risk_score": risk_info["score"],
                "recommendation": (
                    risk_info["recommendation"]
                ),
                "response_time_ms": response_time_ms,
                "banner": (
                    get_banner(
                        ip,
                        port,
                        timeout,
                    )
                    if banner
                    else "Disabled"
                ),
            }

    except (
        OSError,
        socket.timeout,
    ):
        return None


def scan_port_range(
    ip,
    start_port,
    end_port,
    timeout=DEFAULT_SCAN_TIMEOUT,
    banner=False,
    workers=DEFAULT_SCAN_WORKERS,
):
    if start_port > end_port:
        raise ValueError(
            "Start port cannot be greater than end port."
        )

    total_ports = end_port - start_port + 1

    worker_count = max(
        1,
        min(
            int(workers),
            total_ports,
        ),
    )

    results = []
    scan_start_time = time.perf_counter()

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:
        tasks = [
            executor.submit(
                scan_port,
                ip,
                port,
                timeout,
                banner,
            )
            for port in range(
                start_port,
                end_port + 1,
            )
        ]

        for task in as_completed(tasks):
            result = task.result()

            if result is not None:
                results.append(result)

    results.sort(
        key=lambda result: result["port"]
    )

    duration_seconds = round(
        time.perf_counter()
        - scan_start_time,
        2,
    )

    scan_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    return {
        "ip": ip,
        "start_port": start_port,
        "end_port": end_port,
        "scan_date": scan_date,
        "duration_seconds": duration_seconds,
        "ports_scanned": total_ports,
        "open_ports": len(results),
        "results": results,
    }


def generate_txt_report(scan_result):
    lines = [
        "AEGIS SECURITY TOOLKIT - SCAN REPORT",
        "",
        f"Target: {scan_result['ip']}",
        f"Date: {scan_result['scan_date']}",
        (
            f"Range: {scan_result['start_port']} - "
            f"{scan_result['end_port']}"
        ),
        f"Ports scanned: {scan_result['ports_scanned']}",
        (
            f"Duration: "
            f"{scan_result['duration_seconds']} seconds"
        ),
        f"Open ports: {scan_result['open_ports']}",
        "",
        "RESULTS:",
    ]

    for result in scan_result["results"]:
        risk = result.get(
            "risk",
            "Informational",
        )

        risk_score = result.get(
            "risk_score",
            0,
        )

        recommendation = result.get(
            "recommendation",
            "",
        )

        lines.extend(
            [
                "",
                f"Port: {result['port']}",
                f"Status: {result['status']}",
                f"Service: {result['service']}",
                f"Risk: {risk}",
                f"Risk Score: {risk_score}",
                (
                    f"Recommendation: "
                    f"{recommendation}"
                ),
                (
                    f"Time: "
                    f"{result['response_time_ms']} ms"
                ),
                f"Banner: {result['banner']}",
                "-----------------------------",
            ]
        )

    return "\n".join(lines)


def generate_csv_report(scan_result):
    output = io.StringIO(newline="")

    fields = [
        "port",
        "status",
        "service",
        "risk",
        "risk_score",
        "recommendation",
        "response_time_ms",
        "banner",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="ignore",
        quoting=csv.QUOTE_ALL,
        quotechar='"',
        escapechar="\\",
        lineterminator="\n",
    )

    writer.writeheader()

    for result in scan_result["results"]:
        clean_result = {
            field: result.get(field, "")
            for field in fields
        }

        for field, value in clean_result.items():
            if value is None:
                clean_result[field] = ""

            elif isinstance(value, str):
                clean_result[field] = (
                    value
                    .replace("\r\n", " ")
                    .replace("\r", " ")
                    .replace("\n", " ")
                    .replace("\x00", "")
                )

        writer.writerow(clean_result)

    return output.getvalue()
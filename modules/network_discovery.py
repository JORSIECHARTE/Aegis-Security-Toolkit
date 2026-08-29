import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import (
    COMMON_DISCOVERY_PORTS,
    DEFAULT_DISCOVERY_END_HOST,
    DEFAULT_DISCOVERY_START_HOST,
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_DISCOVERY_WORKERS,
)
from services.host_fingerprint import resolve_hostname


def check_port(
    ip,
    port,
    timeout=DEFAULT_DISCOVERY_TIMEOUT,
):
    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as connection:
            connection.settimeout(timeout)

            result = connection.connect_ex(
                (ip, port)
            )

            if result == 0:
                return port

    except Exception:
        pass

    return None


def check_host(
    ip,
    timeout=DEFAULT_DISCOVERY_TIMEOUT,
):
    for port in COMMON_DISCOVERY_PORTS:
        detected_port = check_port(
            ip=ip,
            port=port,
            timeout=timeout,
        )

        if detected_port is not None:
            return {
                "ip": ip,
                "hostname": resolve_hostname(ip),
                "status": "Active",
                "detected_port": detected_port,
            }

    return None


def discover_hosts(
    base_ip,
    start=DEFAULT_DISCOVERY_START_HOST,
    end=DEFAULT_DISCOVERY_END_HOST,
    workers=DEFAULT_DISCOVERY_WORKERS,
    timeout=DEFAULT_DISCOVERY_TIMEOUT,
):
    discovery_start_time = time.perf_counter()

    hosts = []

    ip_addresses = [
        f"{base_ip}.{host_number}"
        for host_number in range(
            start,
            end + 1,
        )
    ]

    total_hosts = len(ip_addresses)

    worker_count = min(
        max(
            1,
            int(workers),
        ),
        total_hosts,
    )

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:
        tasks = {
            executor.submit(
                check_host,
                ip_address,
                timeout,
            ): ip_address
            for ip_address in ip_addresses
        }

        for task in as_completed(tasks):
            host_result = task.result()

            if host_result:
                hosts.append(host_result)

    hosts.sort(
        key=lambda item: tuple(
            int(part)
            for part in item["ip"].split(".")
        )
    )

    duration_seconds = round(
        time.perf_counter()
        - discovery_start_time,
        2,
    )

    return {
        "hosts": hosts,
        "count": len(hosts),
        "duration": duration_seconds,
        "ports_checked": COMMON_DISCOVERY_PORTS,
        "addresses_checked": total_hosts,
    }
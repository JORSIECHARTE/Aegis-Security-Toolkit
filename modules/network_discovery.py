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
from utils.logger import get_logger


logger = get_logger(__name__)


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
                logger.debug(
                    "Open discovery port detected: %s:%s.",
                    ip,
                    port,
                )
                return port

    except Exception as error:
        logger.debug(
            "Discovery port check failed for %s:%s: %s",
            ip,
            port,
            error,
        )

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
            hostname = resolve_hostname(ip)

            logger.debug(
                "Active host detected: %s (%s), port=%s.",
                ip,
                hostname,
                detected_port,
            )

            return {
                "ip": ip,
                "hostname": hostname,
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

    logger.info(
        (
            "Starting network discovery on %s.%s-%s. "
            "Hosts=%s, workers=%s, timeout=%ss."
        ),
        base_ip,
        start,
        end,
        total_hosts,
        worker_count,
        timeout,
    )

    hosts = []

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

    logger.info(
        (
            "Network discovery completed on %s.%s-%s. "
            "Active hosts=%s, duration=%ss."
        ),
        base_ip,
        start,
        end,
        len(hosts),
        duration_seconds,
    )

    return {
        "hosts": hosts,
        "count": len(hosts),
        "duration": duration_seconds,
        "ports_checked": COMMON_DISCOVERY_PORTS,
        "addresses_checked": total_hosts,
    }
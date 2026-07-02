import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from services.host_fingerprint import resolve_hostname


COMMON_DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 8501]


def check_port(ip, port, timeout=0.4):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                return port

    except Exception:
        pass

    return None


def check_host(ip, timeout=0.4):
    for port in COMMON_DISCOVERY_PORTS:
        detected_port = check_port(ip, port, timeout)

        if detected_port:
            return {
                "ip": ip,
                "hostname": resolve_hostname(ip),
                "status": "Active",
                "detected_port": detected_port
            }

    return None


def discover_hosts(base_ip, start=1, end=254, workers=100, timeout=0.4):
    start_time = time.time()

    hosts = []
    ips = [f"{base_ip}.{i}" for i in range(start, end + 1)]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(check_host, ip, timeout): ip
            for ip in ips
        }

        for future in as_completed(futures):
            result = future.result()

            if result:
                hosts.append(result)

    hosts.sort(key=lambda item: list(map(int, item["ip"].split("."))))

    duration = round(time.time() - start_time, 2)

    return {
        "hosts": hosts,
        "count": len(hosts),
        "duration": duration,
        "ports_checked": COMMON_DISCOVERY_PORTS
    }
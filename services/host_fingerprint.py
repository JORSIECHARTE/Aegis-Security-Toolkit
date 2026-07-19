import socket


def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname

    except (
        socket.herror,
        socket.gaierror,
        TimeoutError,
        OSError,
    ):
        return "Unknown"
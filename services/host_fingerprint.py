import socket


def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname

    except Exception:
        return "Unknown"
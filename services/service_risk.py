SERVICE_RISK_DB = {
    "FTP": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use SFTP or restrict access.",
    },
    "HTTP": {
        "risk": "Medium",
        "score": 4,
        "recommendation": "Prefer HTTPS when possible.",
    },
    "HTTPS": {
        "risk": "Low",
        "score": 1,
        "recommendation": "Keep the TLS configuration updated.",
    },
    "SMB": {
        "risk": "High",
        "score": 8,
        "recommendation": "Restrict file-sharing access.",
    },
    "RDP": {
        "risk": "High",
        "score": 9,
        "recommendation": "Limit remote-access exposure.",
    },
    "MYSQL": {
        "risk": "High",
        "score": 8,
        "recommendation": "Do not expose databases unnecessarily.",
    },
    "SSH": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use key-based authentication.",
    },
    "SMTP": {
        "risk": "Medium",
        "score": 4,
        "recommendation": "Restrict mail-service exposure.",
    },
    "SMTP SUBMISSION": {
        "risk": "Medium",
        "score": 4,
        "recommendation": (
            "Require authentication and encrypted transport "
            "for mail submission."
        ),
    },
    "POP3": {
        "risk": "High",
        "score": 7,
        "recommendation": "Prefer encrypted mail protocols.",
    },
    "POP3S": {
        "risk": "Low",
        "score": 2,
        "recommendation": (
            "Keep the encrypted mail-service configuration updated."
        ),
    },
    "IMAP": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use IMAPS whenever possible.",
    },
    "IMAPS": {
        "risk": "Low",
        "score": 2,
        "recommendation": (
            "Keep the encrypted mail-service configuration updated."
        ),
    },
    "NETBIOS": {
        "risk": "High",
        "score": 7,
        "recommendation": "Disable NetBIOS if it is not required.",
    },
    "RPC": {
        "risk": "Medium",
        "score": 6,
        "recommendation": "Limit RPC access to trusted hosts.",
    },
    "NNTP": {
        "risk": "Low",
        "score": 2,
        "recommendation": "Disable NNTP if it is not required.",
    },
    "ICSLAP": {
        "risk": "Low",
        "score": 1,
        "recommendation": (
            "Review this service and disable it if it is not required."
        ),
    },
    "TELNET": {
        "risk": "High",
        "score": 9,
        "recommendation": "Replace Telnet with SSH.",
    },
    "DNS": {
        "risk": "Low",
        "score": 2,
        "recommendation": (
            "Restrict recursion and keep the DNS service updated."
        ),
    },
    "POSTGRESQL": {
        "risk": "High",
        "score": 8,
        "recommendation": (
            "Restrict database access to authorized systems."
        ),
    },
    "VNC": {
        "risk": "High",
        "score": 8,
        "recommendation": (
            "Restrict VNC access and use encrypted transport."
        ),
    },
    "REDIS": {
        "risk": "High",
        "score": 9,
        "recommendation": (
            "Do not expose Redis to untrusted networks."
        ),
    },
    "HTTP DEV": {
        "risk": "Medium",
        "score": 5,
        "recommendation": (
            "Do not expose development web services publicly."
        ),
    },
    "HTTP ALT": {
        "risk": "Medium",
        "score": 4,
        "recommendation": (
            "Review the alternate HTTP service and prefer HTTPS."
        ),
    },
    "HTTPS ALT": {
        "risk": "Low",
        "score": 2,
        "recommendation": (
            "Review the TLS configuration on the alternate HTTPS port."
        ),
    },
    "STREAMLIT": {
        "risk": "Medium",
        "score": 5,
        "recommendation": (
            "Restrict access and avoid exposing development "
            "applications directly to the internet."
        ),
    },
}


DEFAULT_SERVICE_RISK = {
    "risk": "Informational",
    "score": 0,
    "recommendation": "Review this service if it is not recognized.",
}


def normalize_service_name(service_name):
    return " ".join(
        str(service_name)
        .strip()
        .upper()
        .replace("_", " ")
        .replace("-", " ")
        .split()
    )


def get_service_risk(service_name):
    normalized_service = normalize_service_name(service_name)
    return SERVICE_RISK_DB.get(
        normalized_service,
        DEFAULT_SERVICE_RISK,
    ).copy()
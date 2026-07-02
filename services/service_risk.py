SERVICE_RISK_DB = {
    "FTP": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use SFTP or restrict access."
    },

    "HTTP": {
        "risk": "Medium",
        "score": 4,
        "recommendation": "Prefer HTTPS when possible."
    },

    "HTTPS": {
        "risk": "Low",
        "score": 1,
        "recommendation": "Keep TLS configuration updated."
    },

    "SMB": {
        "risk": "High",
        "score": 8,
        "recommendation": "Restrict file sharing access."
    },

    "RDP": {
        "risk": "High",
        "score": 9,
        "recommendation": "Limit remote access exposure."
    },

    "MySQL": {
        "risk": "High",
        "score": 8,
        "recommendation": "Do not expose databases unnecessarily."
    },

    "SSH": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use key authentication."
    },

    "SMTP": {
        "risk": "Medium",
        "score": 4,
        "recommendation": "Restrict mail service exposure."
    },

    "POP3": {
        "risk": "High",
        "score": 7,
        "recommendation": "Prefer encrypted mail protocols."
    },

    "POP3S": {
        "risk": "Low",
        "score": 2,
        "recommendation": "Keep encrypted mail service configuration updated."
    },

    "IMAP": {
        "risk": "Medium",
        "score": 5,
        "recommendation": "Use IMAPS whenever possible."
    },

    "IMAPS": {
        "risk": "Low",
        "score": 2,
        "recommendation": "Keep encrypted mail service configuration updated."
    },

    "NetBIOS": {
        "risk": "High",
        "score": 7,
        "recommendation": "Disable NetBIOS if not required."
    },

    "RPC": {
        "risk": "Medium",
        "score": 6,
        "recommendation": "Limit RPC access to trusted hosts."
    },

    "NNTP": {
        "risk": "Low",
        "score": 2,
        "recommendation": "Disable NNTP if not required."
    },

    "ICSLAP": {
        "risk": "Low",
        "score": 1,
        "recommendation": "Review this service and disable it if not required."
    }
}


def get_service_risk(service_name):
    return SERVICE_RISK_DB.get(
        service_name,
        {
            "risk": "Informational",
            "score": 0,
            "recommendation": "Review this service if it is not recognized."
        }
    )
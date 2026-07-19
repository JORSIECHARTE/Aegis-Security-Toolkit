import re
from collections import Counter

from services.security_rules import (
    calculate_risk_score,
    classify_risk,
    detect_brute_force,
    detect_successful_login_after_failures,
)


IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

FAILED_LOGIN_PATTERNS = [
    "failed password",
    "authentication failure",
    "login failed",
    "failed login",
    "invalid user",
]

SUCCESSFUL_LOGIN_PATTERNS = [
    "accepted password",
    "login successful",
    "session opened",
]

SUSPICIOUS_EVENT_PATTERNS = [
    "root",
    "admin",
    "administrator",
    "brute force",
    "unauthorized",
    "denied",
]


def extract_first_ip(line):
    match = re.search(IP_PATTERN, line)

    if match:
        return match.group(0)

    return None


def contains_any_pattern(text, patterns):
    return any(pattern in text for pattern in patterns)


def convert_events_to_compatibility_format(events):
    return [
        {
            "linea": event["line"],
            "ip": event["ip"],
            "contenido": event["content"],
        }
        for event in events
    ]


def convert_alerts_to_compatibility_format(alerts):
    return [
        {
            "tipo": alert["type"],
            "ip": alert["ip"],
            "cantidad": alert["count"],
            "severidad": alert["severity"],
            "descripcion": alert["description"],
        }
        for alert in alerts
    ]


def analyze_logs(content):
    lines = content.splitlines()

    failed_logins = []
    successful_logins = []
    detected_ips = []
    suspicious_events = []

    for line_number, line in enumerate(lines, start=1):
        lowercase_line = line.lower()

        detected_ips.extend(
            re.findall(IP_PATTERN, line)
        )

        event = {
            "line": line_number,
            "ip": extract_first_ip(line),
            "content": line,
        }

        if contains_any_pattern(
            lowercase_line,
            FAILED_LOGIN_PATTERNS,
        ):
            failed_logins.append(event.copy())

        if contains_any_pattern(
            lowercase_line,
            SUCCESSFUL_LOGIN_PATTERNS,
        ):
            successful_logins.append(event.copy())

        if contains_any_pattern(
            lowercase_line,
            SUSPICIOUS_EVENT_PATTERNS,
        ):
            suspicious_events.append(event.copy())

    ip_counter = Counter(detected_ips)

    frequent_ips = [
        {
            "ip": ip_address,
            "count": count,
        }
        for ip_address, count in ip_counter.most_common()
    ]

    brute_force_alerts = detect_brute_force(
        failed_logins,
        threshold=5,
    )

    post_failure_login_alerts = (
        detect_successful_login_after_failures(
            failed_logins,
            successful_logins,
        )
    )

    alerts = brute_force_alerts + post_failure_login_alerts

    results_for_risk_calculation = {
        "failed_logins": failed_logins,
        "suspicious_events": suspicious_events,
        "alerts": alerts,
    }

    risk_score = calculate_risk_score(
        results_for_risk_calculation
    )
    risk_level = classify_risk(risk_score)

    summary = {
        "failed_attempts": len(failed_logins),
        "successful_logins": len(successful_logins),
        "suspicious_events": len(suspicious_events),
        "unique_ips": len(ip_counter),
        "alerts": len(alerts),
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    compatibility_failed_logins = (
        convert_events_to_compatibility_format(
            failed_logins
        )
    )
    compatibility_successful_logins = (
        convert_events_to_compatibility_format(
            successful_logins
        )
    )
    compatibility_suspicious_events = (
        convert_events_to_compatibility_format(
            suspicious_events
        )
    )
    compatibility_alerts = (
        convert_alerts_to_compatibility_format(
            alerts
        )
    )

    compatibility_frequent_ips = [
        {
            "ip": item["ip"],
            "cantidad": item["count"],
        }
        for item in frequent_ips
    ]

    compatibility_summary = {
        "intentos_fallidos": summary["failed_attempts"],
        "logins_exitosos": summary["successful_logins"],
        "eventos_sospechosos": summary["suspicious_events"],
        "ips_unicas": summary["unique_ips"],
        "alertas": summary["alerts"],
        "risk_score": summary["risk_score"],
        "nivel_riesgo": summary["risk_level"],
    }

    return {
        "total_lines": len(lines),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "detected_ips": detected_ips,
        "frequent_ips": frequent_ips,
        "suspicious_events": suspicious_events,
        "alerts": alerts,
        "summary": summary,

        # Temporary compatibility keys
        "total_lineas": len(lines),
        "ips_detectadas": detected_ips,
        "ips_frecuentes": compatibility_frequent_ips,
        "eventos_sospechosos": compatibility_suspicious_events,
        "alertas": compatibility_alerts,
        "resumen": compatibility_summary,
    }


# Temporary compatibility aliases
extraer_primera_ip = extract_first_ip
analizar_logs = analyze_logs
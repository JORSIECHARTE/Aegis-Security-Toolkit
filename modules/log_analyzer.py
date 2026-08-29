import re
from collections import Counter

from config import BRUTE_FORCE_THRESHOLD
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
    return any(
        pattern in text
        for pattern in patterns
    )


def analyze_logs(content):
    lines = content.splitlines()

    failed_logins = []
    successful_logins = []
    detected_ips = []
    suspicious_events = []

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        lowercase_line = line.lower()

        detected_ips.extend(
            re.findall(
                IP_PATTERN,
                line,
            )
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
            failed_logins.append(
                event.copy()
            )

        if contains_any_pattern(
            lowercase_line,
            SUCCESSFUL_LOGIN_PATTERNS,
        ):
            successful_logins.append(
                event.copy()
            )

        if contains_any_pattern(
            lowercase_line,
            SUSPICIOUS_EVENT_PATTERNS,
        ):
            suspicious_events.append(
                event.copy()
            )

    ip_counter = Counter(detected_ips)

    frequent_ips = [
        {
            "ip": ip_address,
            "count": count,
        }
        for (
            ip_address,
            count,
        ) in ip_counter.most_common()
    ]

    brute_force_alerts = detect_brute_force(
        failed_logins,
        threshold=BRUTE_FORCE_THRESHOLD,
    )

    post_failure_login_alerts = (
        detect_successful_login_after_failures(
            failed_logins,
            successful_logins,
        )
    )

    alerts = (
        brute_force_alerts
        + post_failure_login_alerts
    )

    results_for_risk_calculation = {
        "failed_logins": failed_logins,
        "suspicious_events": suspicious_events,
        "alerts": alerts,
    }

    risk_score = calculate_risk_score(
        results_for_risk_calculation
    )

    risk_level = classify_risk(
        risk_score
    )

    summary = {
        "failed_attempts": len(
            failed_logins
        ),
        "successful_logins": len(
            successful_logins
        ),
        "suspicious_events": len(
            suspicious_events
        ),
        "unique_ips": len(ip_counter),
        "alerts": len(alerts),
        "risk_score": risk_score,
        "risk_level": risk_level,
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
    }
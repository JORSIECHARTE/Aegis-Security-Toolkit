from collections import Counter

from config import (
    ALERT_RISK_WEIGHT,
    BRUTE_FORCE_THRESHOLD,
    CRITICAL_RISK_THRESHOLD,
    FAILED_LOGIN_RISK_WEIGHT,
    HIGH_RISK_THRESHOLD,
    MAX_RISK_SCORE,
    MEDIUM_RISK_THRESHOLD,
    SUCCESS_AFTER_FAILURES_THRESHOLD,
    SUSPICIOUS_EVENT_RISK_WEIGHT,
)


def detect_brute_force(
    failed_logins,
    threshold=BRUTE_FORCE_THRESHOLD,
):
    attempts_by_ip = Counter()

    for event in failed_logins:
        ip_address = event.get("ip")

        if ip_address:
            attempts_by_ip[ip_address] += 1

    alerts = []

    for (
        ip_address,
        attempt_count,
    ) in attempts_by_ip.items():
        if attempt_count >= threshold:
            alerts.append(
                {
                    "type": "Possible brute-force attack",
                    "ip": ip_address,
                    "count": attempt_count,
                    "severity": "High",
                    "description": (
                        f"{attempt_count} failed login attempts were "
                        f"detected from the same IP address."
                    ),
                }
            )

    return alerts


def detect_successful_login_after_failures(
    failed_logins,
    successful_logins,
    minimum_failures=SUCCESS_AFTER_FAILURES_THRESHOLD,
):
    failures_by_ip = Counter()

    for event in failed_logins:
        ip_address = event.get("ip")

        if ip_address:
            failures_by_ip[ip_address] += 1

    alerts = []

    for event in successful_logins:
        ip_address = event.get("ip")

        failure_count = failures_by_ip.get(
            ip_address,
            0,
        )

        if (
            ip_address
            and failure_count >= minimum_failures
        ):
            alerts.append(
                {
                    "type": (
                        "Successful login after "
                        "multiple failures"
                    ),
                    "ip": ip_address,
                    "count": failure_count,
                    "severity": "Medium",
                    "description": (
                        f"The IP address {ip_address} generated "
                        f"{failure_count} failed attempts before a "
                        f"successful login."
                    ),
                }
            )

    return alerts


def calculate_risk_score(results):
    failed_logins = results.get(
        "failed_logins",
        [],
    )

    suspicious_events = results.get(
        "suspicious_events",
        [],
    )

    alerts = results.get(
        "alerts",
        [],
    )

    score = 0

    score += (
        len(failed_logins)
        * FAILED_LOGIN_RISK_WEIGHT
    )

    score += (
        len(suspicious_events)
        * SUSPICIOUS_EVENT_RISK_WEIGHT
    )

    score += (
        len(alerts)
        * ALERT_RISK_WEIGHT
    )

    return min(
        score,
        MAX_RISK_SCORE,
    )


def classify_risk(score):
    if score >= CRITICAL_RISK_THRESHOLD:
        return "Critical"

    if score >= HIGH_RISK_THRESHOLD:
        return "High"

    if score >= MEDIUM_RISK_THRESHOLD:
        return "Medium"

    return "Low"
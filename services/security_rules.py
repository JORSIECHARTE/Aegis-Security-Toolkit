from collections import Counter


def detect_brute_force(failed_logins, threshold=5):
    attempts_by_ip = Counter()

    for event in failed_logins:
        ip_address = event.get("ip")

        if ip_address:
            attempts_by_ip[ip_address] += 1

    alerts = []

    for ip_address, attempt_count in attempts_by_ip.items():
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
    minimum_failures=3,
):
    failures_by_ip = Counter()

    for event in failed_logins:
        ip_address = event.get("ip")

        if ip_address:
            failures_by_ip[ip_address] += 1

    alerts = []

    for event in successful_logins:
        ip_address = event.get("ip")
        failure_count = failures_by_ip.get(ip_address, 0)

        if ip_address and failure_count >= minimum_failures:
            alerts.append(
                {
                    "type": "Successful login after multiple failures",
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
    failed_logins = results.get("failed_logins", [])
    suspicious_events = results.get("suspicious_events", [])
    alerts = results.get("alerts", [])

    score = 0
    score += len(failed_logins) * 3
    score += len(suspicious_events) * 4
    score += len(alerts) * 15

    return min(score, 100)


def classify_risk(score):
    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"
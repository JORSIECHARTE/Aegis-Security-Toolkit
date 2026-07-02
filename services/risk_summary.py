def calculate_overall_risk(scan_results):
    total_score = 0
    high_risk_services = []
    recommendations = []

    for item in scan_results:
        score = item.get("risk_score", 0)
        risk = item.get("risk", "Unknown")
        service = item.get("servicio", "Unknown")
        port = item.get("puerto", "Unknown")
        recommendation = item.get("recommendation", "")

        total_score += score

        if risk == "High":
            high_risk_services.append({
                "port": port,
                "service": service,
                "risk": risk,
                "score": score
            })

        if (
            recommendation
            and recommendation != "No recommendation available."
            and recommendation not in recommendations
        ):
            recommendations.append(recommendation)

    if total_score >= 80:
        assessment = "Critical"
    elif total_score >= 50:
        assessment = "High"
    elif total_score >= 20:
        assessment = "Medium"
    else:
        assessment = "Low"

    return {
        "overall_score": total_score,
        "assessment": assessment,
        "high_risk_services": high_risk_services,
        "recommendations": recommendations
    }


def generate_executive_summary(scan_result):
    risk_summary = calculate_overall_risk(
        scan_result["resultados"]
    )

    open_ports = scan_result["puertos_abiertos"]
    target = scan_result["ip"]

    summary = (
        f"The scan against {target} detected {open_ports} open ports. "
        f"The overall risk assessment is "
        f"{risk_summary['assessment']} "
        f"with a total score of "
        f"{risk_summary['overall_score']}."
    )

    if risk_summary["high_risk_services"]:
        services = ", ".join(
            f"{item['service']} on port {item['port']}"
            for item in risk_summary["high_risk_services"]
        )

        summary += (
            f" High-risk services detected: "
            f"{services}."
        )

    if risk_summary["recommendations"]:
        summary += (
            " Review the recommendations before "
            "exposing this host to untrusted networks."
        )

    return summary
from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary
)


def get_risk_class(risk):
    risk = str(risk).lower()

    if risk == "high":
        return "risk-high"
    if risk == "medium":
        return "risk-medium"
    if risk == "low":
        return "risk-low"

    return "risk-unknown"


def generar_html_scan(scan_result):
    risk_summary = calculate_overall_risk(scan_result["resultados"])
    executive_summary = generate_executive_summary(scan_result)

    high_risk_rows = ""

    for item in risk_summary["high_risk_services"]:
        high_risk_rows += f"""
        <tr>
            <td>{item["port"]}</td>
            <td>{item["service"]}</td>
            <td class="risk-high">{item["risk"]}</td>
            <td>{item["score"]}</td>
        </tr>
        """

    recommendation_items = ""

    for recommendation in risk_summary["recommendations"]:
        recommendation_items += f"<li>{recommendation}</li>"

    port_rows = ""

    for item in scan_result["resultados"]:
        risk_class = get_risk_class(item.get("risk", "Unknown"))

        port_rows += f"""
        <tr>
            <td>{item["puerto"]}</td>
            <td>{item["servicio"]}</td>
            <td class="{risk_class}">{item.get("risk", "Unknown")}</td>
            <td>{item.get("risk_score", 0)}</td>
            <td>{item.get("recommendation", "")}</td>
            <td>{item["tiempo_ms"]}</td>
            <td>{item["banner"]}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Aegis Security Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            margin: 0;
            padding: 40px;
            color: #111827;
        }}

        .container {{
            background: white;
            padding: 32px;
            border-radius: 12px;
            max-width: 1200px;
            margin: auto;
        }}

        h1 {{
            margin-bottom: 4px;
            color: #111827;
        }}

        h2 {{
            margin-top: 32px;
            color: #1f2937;
        }}

        .subtitle {{
            color: #6b7280;
            margin-bottom: 28px;
        }}

        .metrics {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 24px 0;
        }}

        .card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            padding: 16px;
            border-radius: 10px;
        }}

        .card-title {{
            font-size: 13px;
            color: #6b7280;
        }}

        .card-value {{
            font-size: 26px;
            font-weight: bold;
            margin-top: 8px;
        }}

        .summary {{
            background: #eef2ff;
            border-left: 5px solid #4f46e5;
            padding: 16px;
            margin: 24px 0;
            border-radius: 8px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }}

        th {{
            background: #1f2937;
            color: white;
            text-align: left;
            padding: 10px;
        }}

        td {{
            border: 1px solid #e5e7eb;
            padding: 10px;
            vertical-align: top;
        }}

        tr:nth-child(even) {{
            background: #f9fafb;
        }}

        .risk-high {{
            color: #b91c1c;
            font-weight: bold;
        }}

        .risk-medium {{
            color: #b45309;
            font-weight: bold;
        }}

        .risk-low {{
            color: #047857;
            font-weight: bold;
        }}

        .risk-unknown {{
            color: #6b7280;
            font-weight: bold;
        }}

        ul {{
            line-height: 1.8;
        }}

        .footer {{
            margin-top: 40px;
            color: #6b7280;
            font-size: 12px;
            border-top: 1px solid #e5e7eb;
            padding-top: 16px;
        }}
    </style>
</head>

<body>
    <div class="container">
        <h1>Aegis Security Toolkit</h1>
        <div class="subtitle">Advanced Security Scan Report</div>

        <div class="metrics">
            <div class="card">
                <div class="card-title">Target</div>
                <div class="card-value">{scan_result["ip"]}</div>
            </div>

            <div class="card">
                <div class="card-title">Open Ports</div>
                <div class="card-value">{scan_result["puertos_abiertos"]}</div>
            </div>

            <div class="card">
                <div class="card-title">Risk Score</div>
                <div class="card-value">{risk_summary["overall_score"]}</div>
            </div>

            <div class="card">
                <div class="card-title">Assessment</div>
                <div class="card-value">{risk_summary["assessment"]}</div>
            </div>
        </div>

        <p><strong>Date:</strong> {scan_result["fecha"]}</p>
        <p><strong>Port Range:</strong> {scan_result["puerto_inicio"]} - {scan_result["puerto_fin"]}</p>
        <p><strong>Duration:</strong> {scan_result["duracion_segundos"]} seconds</p>

        <h2>Executive Summary</h2>
        <div class="summary">
            {executive_summary}
        </div>

        <h2>High Risk Services</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Risk</th>
                <th>Score</th>
            </tr>
            {high_risk_rows}
        </table>

        <h2>Priority Actions</h2>
        <ul>
            {recommendation_items}
        </ul>

        <h2>Open Ports Detail</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Recommendation</th>
                <th>Time (ms)</th>
                <th>Banner</th>
            </tr>
            {port_rows}
        </table>

        <div class="footer">
            Report generated by Aegis Security Toolkit.
        </div>
    </div>
</body>
</html>
"""

    return html
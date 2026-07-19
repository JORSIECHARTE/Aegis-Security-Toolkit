from html import escape

from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary,
)


def get_risk_class(risk):
    normalized_risk = str(risk).strip().lower()

    if normalized_risk == "critical":
        return "risk-critical"
    if normalized_risk == "high":
        return "risk-high"
    if normalized_risk == "medium":
        return "risk-medium"
    if normalized_risk == "low":
        return "risk-low"
    if normalized_risk == "informational":
        return "risk-informational"

    return "risk-unknown"


def format_html_value(value):
    if value is None:
        return ""

    return escape(str(value))


def generate_html_scan_report(scan_result):
    results = scan_result["results"]

    risk_summary = calculate_overall_risk(results)
    executive_summary = generate_executive_summary(scan_result)

    high_risk_rows = ""

    for item in risk_summary.get("high_risk_services", []):
        risk = item.get("risk", "Unknown")
        risk_class = get_risk_class(risk)

        high_risk_rows += f"""
        <tr>
            <td>{format_html_value(item.get("port", ""))}</td>
            <td>{format_html_value(item.get("service", ""))}</td>
            <td class="{risk_class}">
                {format_html_value(risk)}
            </td>
            <td>{format_html_value(item.get("score", 0))}</td>
        </tr>
        """

    if not high_risk_rows:
        high_risk_rows = """
        <tr>
            <td colspan="4" class="empty-state">
                No high-risk services were detected.
            </td>
        </tr>
        """

    recommendation_items = ""

    for recommendation in risk_summary.get("recommendations", []):
        recommendation_items += (
            f"<li>{format_html_value(recommendation)}</li>"
        )

    if not recommendation_items:
        recommendation_items = (
            "<li>No priority recommendations were generated.</li>"
        )

    port_rows = ""

    for item in results:
        risk = item.get("risk", "Unknown")
        risk_class = get_risk_class(risk)

        port_rows += f"""
        <tr>
            <td>{format_html_value(item["port"])}</td>
            <td>{format_html_value(item["service"])}</td>
            <td class="{risk_class}">
                {format_html_value(risk)}
            </td>
            <td>{format_html_value(item.get("risk_score", 0))}</td>
            <td>{format_html_value(item.get("recommendation", ""))}</td>
            <td>
                {format_html_value(
                    item["response_time_ms"]
                )}
            </td>
            <td class="banner-cell">
                {format_html_value(item.get("banner", ""))}
            </td>
        </tr>
        """

    if not port_rows:
        port_rows = """
        <tr>
            <td colspan="7" class="empty-state">
                No open ports were detected.
            </td>
        </tr>
        """

    target = scan_result["ip"]
    open_ports = scan_result["open_ports"]
    scan_date = scan_result["scan_date"]
    start_port = scan_result["start_port"]
    end_port = scan_result["end_port"]
    duration_seconds = scan_result["duration_seconds"]
    ports_scanned = scan_result["ports_scanned"]

    html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Aegis Security Report</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

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
            box-shadow: 0 8px 24px rgba(17, 24, 39, 0.08);
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
            overflow-wrap: anywhere;
        }}

        .summary {{
            background: #eef2ff;
            border-left: 5px solid #4f46e5;
            padding: 16px;
            margin: 24px 0;
            border-radius: 8px;
            white-space: pre-wrap;
        }}

        .table-wrapper {{
            width: 100%;
            overflow-x: auto;
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

        .risk-critical {{
            color: #7f1d1d;
            font-weight: bold;
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

        .risk-informational {{
            color: #0369a1;
            font-weight: bold;
        }}

        .risk-unknown {{
            color: #6b7280;
            font-weight: bold;
        }}

        .banner-cell {{
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            max-width: 320px;
        }}

        .empty-state {{
            color: #6b7280;
            text-align: center;
            padding: 20px;
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

        @media (max-width: 900px) {{
            body {{
                padding: 16px;
            }}

            .container {{
                padding: 20px;
            }}

            .metrics {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 520px) {{
            .metrics {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>

<body>
    <div class="container">
        <h1>Aegis Security Toolkit</h1>
        <div class="subtitle">
            Advanced Security Scan Report
        </div>

        <div class="metrics">
            <div class="card">
                <div class="card-title">Target</div>
                <div class="card-value">
                    {format_html_value(target)}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Open Ports</div>
                <div class="card-value">
                    {format_html_value(open_ports)}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Risk Score</div>
                <div class="card-value">
                    {format_html_value(
                        risk_summary.get("overall_score", 0)
                    )}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Assessment</div>
                <div class="card-value">
                    {format_html_value(
                        risk_summary.get("assessment", "Unknown")
                    )}
                </div>
            </div>
        </div>

        <p>
            <strong>Date:</strong>
            {format_html_value(scan_date)}
        </p>

        <p>
            <strong>Port Range:</strong>
            {format_html_value(start_port)}
            -
            {format_html_value(end_port)}
        </p>

        <p>
            <strong>Ports Scanned:</strong>
            {format_html_value(ports_scanned)}
        </p>

        <p>
            <strong>Duration:</strong>
            {format_html_value(duration_seconds)} seconds
        </p>

        <h2>Executive Summary</h2>

        <div class="summary">
            {format_html_value(executive_summary)}
        </div>

        <h2>High-Risk Services</h2>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Score</th>
                    </tr>
                </thead>

                <tbody>
                    {high_risk_rows}
                </tbody>
            </table>
        </div>

        <h2>Priority Actions</h2>

        <ul>
            {recommendation_items}
        </ul>

        <h2>Open Ports Detail</h2>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Score</th>
                        <th>Recommendation</th>
                        <th>Time (ms)</th>
                        <th>Banner</th>
                    </tr>
                </thead>

                <tbody>
                    {port_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Report generated by Aegis Security Toolkit.
        </div>
    </div>
</body>
</html>
"""

    return html_report
from datetime import datetime


def generar_html_scan(resultado_scan):

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">

        <title>Aegis Security Report</title>

        <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f4f4;
        }}

        .container {{
            background: white;
            padding: 30px;
            border-radius: 10px;
        }}

        h1 {{
            color: #1f2937;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
        }}

        th {{
            background: #1f2937;
            color: white;
        }}

        .metric {{
            margin-bottom: 10px;
        }}

        </style>

    </head>

    <body>

    <div class="container">

    <h1>Aegis Security Toolkit</h1>

    <h2>Reporte de Escaneo</h2>

    <div class="metric">
        <strong>Objetivo:</strong> {resultado_scan["ip"]}
    </div>

    <div class="metric">
        <strong>Fecha:</strong> {resultado_scan["fecha"]}
    </div>

    <div class="metric">
        <strong>Rango:</strong>
        {resultado_scan["puerto_inicio"]}
        -
        {resultado_scan["puerto_fin"]}
    </div>

    <div class="metric">
        <strong>Puertos abiertos:</strong>
        {resultado_scan["puertos_abiertos"]}
    </div>

    <div class="metric">
        <strong>Duración:</strong>
        {resultado_scan["duracion_segundos"]} segundos
    </div>

    <table>

        <tr>
            <th>Puerto</th>
            <th>Servicio</th>
            <th>Tiempo (ms)</th>
            <th>Banner</th>
        </tr>
    """

    for item in resultado_scan["resultados"]:

        html += f"""
        <tr>
            <td>{item['puerto']}</td>
            <td>{item['servicio']}</td>
            <td>{item['tiempo_ms']}</td>
            <td>{item['banner']}</td>
        </tr>
        """

    html += """
    </table>

    </div>

    </body>
    </html>
    """

    return html
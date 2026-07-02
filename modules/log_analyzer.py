import re
from collections import Counter

from services.security_rules import (
    detectar_fuerza_bruta,
    detectar_login_exitoso_despues_de_fallos,
    calcular_risk_score,
    clasificar_riesgo
)


def extraer_primera_ip(linea):
    patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    coincidencia = re.search(patron_ip, linea)

    if coincidencia:
        return coincidencia.group(0)

    return None


def analizar_logs(contenido):
    lineas = contenido.splitlines()

    resultados = {
        "total_lineas": len(lineas),
        "failed_logins": [],
        "successful_logins": [],
        "ips_detectadas": [],
        "eventos_sospechosos": [],
        "alertas": []
    }

    patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for numero, linea in enumerate(lineas, start=1):
        linea_lower = linea.lower()

        ips = re.findall(patron_ip, linea)
        resultados["ips_detectadas"].extend(ips)

        ip_principal = extraer_primera_ip(linea)

        if any(texto in linea_lower for texto in [
            "failed password",
            "authentication failure",
            "login failed",
            "failed login",
            "invalid user"
        ]):
            resultados["failed_logins"].append({
                "linea": numero,
                "ip": ip_principal,
                "contenido": linea
            })

        if any(texto in linea_lower for texto in [
            "accepted password",
            "login successful",
            "session opened"
        ]):
            resultados["successful_logins"].append({
                "linea": numero,
                "ip": ip_principal,
                "contenido": linea
            })

        if any(texto in linea_lower for texto in [
            "root",
            "admin",
            "administrator",
            "brute force",
            "unauthorized",
            "denied"
        ]):
            resultados["eventos_sospechosos"].append({
                "linea": numero,
                "ip": ip_principal,
                "contenido": linea
            })

    contador_ips = Counter(resultados["ips_detectadas"])

    resultados["ips_frecuentes"] = [
        {"ip": ip, "cantidad": cantidad}
        for ip, cantidad in contador_ips.most_common()
    ]

    alertas_fuerza_bruta = detectar_fuerza_bruta(
        resultados["failed_logins"],
        umbral=5
    )

    alertas_login_post_fallo = detectar_login_exitoso_despues_de_fallos(
        resultados["failed_logins"],
        resultados["successful_logins"]
    )

    resultados["alertas"] = alertas_fuerza_bruta + alertas_login_post_fallo

    risk_score = calcular_risk_score(resultados)
    nivel_riesgo = clasificar_riesgo(risk_score)

    resultados["resumen"] = {
        "intentos_fallidos": len(resultados["failed_logins"]),
        "logins_exitosos": len(resultados["successful_logins"]),
        "eventos_sospechosos": len(resultados["eventos_sospechosos"]),
        "ips_unicas": len(contador_ips),
        "alertas": len(resultados["alertas"]),
        "risk_score": risk_score,
        "nivel_riesgo": nivel_riesgo
    }

    return resultados
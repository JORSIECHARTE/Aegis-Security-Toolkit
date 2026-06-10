import re
from collections import Counter


def analizar_logs(contenido):
    lineas = contenido.splitlines()

    resultados = {
        "total_lineas": len(lineas),
        "failed_logins": [],
        "successful_logins": [],
        "ips_detectadas": [],
        "eventos_sospechosos": []
    }

    patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for numero, linea in enumerate(lineas, start=1):
        linea_lower = linea.lower()

        ips = re.findall(patron_ip, linea)
        resultados["ips_detectadas"].extend(ips)

        if any(texto in linea_lower for texto in [
            "failed password",
            "authentication failure",
            "login failed",
            "failed login",
            "invalid user"
        ]):
            resultados["failed_logins"].append({
                "linea": numero,
                "contenido": linea
            })

        if any(texto in linea_lower for texto in [
            "accepted password",
            "login successful",
            "session opened"
        ]):
            resultados["successful_logins"].append({
                "linea": numero,
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
                "contenido": linea
            })

    contador_ips = Counter(resultados["ips_detectadas"])

    resultados["ips_frecuentes"] = [
        {"ip": ip, "cantidad": cantidad}
        for ip, cantidad in contador_ips.most_common()
    ]

    resultados["resumen"] = {
        "intentos_fallidos": len(resultados["failed_logins"]),
        "logins_exitosos": len(resultados["successful_logins"]),
        "eventos_sospechosos": len(resultados["eventos_sospechosos"]),
        "ips_unicas": len(contador_ips)
    }

    return resultados
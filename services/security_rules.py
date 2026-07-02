from collections import Counter


def detectar_fuerza_bruta(failed_logins, umbral=5):
    contador_ips = Counter()

    for evento in failed_logins:
        ip = evento.get("ip")
        if ip:
            contador_ips[ip] += 1

    alertas = []

    for ip, cantidad in contador_ips.items():
        if cantidad >= umbral:
            alertas.append({
                "tipo": "Posible fuerza bruta",
                "ip": ip,
                "cantidad": cantidad,
                "severidad": "Alta",
                "descripcion": f"Se detectaron {cantidad} intentos fallidos desde la misma IP."
            })

    return alertas


def detectar_login_exitoso_despues_de_fallos(failed_logins, successful_logins):
    fallos_por_ip = Counter()

    for evento in failed_logins:
        ip = evento.get("ip")
        if ip:
            fallos_por_ip[ip] += 1

    alertas = []

    for evento in successful_logins:
        ip = evento.get("ip")

        if ip and fallos_por_ip[ip] >= 3:
            alertas.append({
                "tipo": "Login exitoso después de múltiples fallos",
                "ip": ip,
                "cantidad": fallos_por_ip[ip],
                "severidad": "Media",
                "descripcion": f"La IP {ip} tuvo {fallos_por_ip[ip]} fallos y luego un login exitoso."
            })

    return alertas


def calcular_risk_score(resultados):
    score = 0

    score += len(resultados.get("failed_logins", [])) * 3
    score += len(resultados.get("eventos_sospechosos", [])) * 4
    score += len(resultados.get("alertas", [])) * 15

    if score > 100:
        score = 100

    return score


def clasificar_riesgo(score):
    if score >= 80:
        return "Crítico"
    if score >= 60:
        return "Alto"
    if score >= 30:
        return "Medio"
    return "Bajo"
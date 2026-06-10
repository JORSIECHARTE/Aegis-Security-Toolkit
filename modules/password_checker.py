import re
import math


COMMON_WORDS = [
    "password", "contraseña", "admin", "administrator", "root",
    "qwerty", "usuario", "login", "welcome", "bienvenido",
    "argentina", "buenosaires", "joaquin", "juaquin",
    "registro", "libre", "aegis", "security", "toolkit"
]

COMMON_PATTERNS = [
    "123", "1234", "12345", "123456",
    "000", "111", "222", "abc", "abcd",
    "qwerty", "asdf", "zxcv",
    "2023", "2024", "2025", "2026"
]

LEET_REPLACEMENTS = {
    "@": "a",
    "4": "a",
    "0": "o",
    "1": "i",
    "3": "e",
    "$": "s",
    "5": "s",
    "7": "t"
}


def normalizar_leet(password):
    resultado = password.lower()

    for simbolo, letra in LEET_REPLACEMENTS.items():
        resultado = resultado.replace(simbolo, letra)

    return resultado


def contiene_secuencia(password):
    password_lower = password.lower()

    secuencias = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    for secuencia in secuencias:
        for i in range(len(secuencia) - 3):
            fragmento = secuencia[i:i + 4]
            if fragmento in password_lower or fragmento[::-1] in password_lower:
                return True, fragmento

    return False, None


def estimar_tiempo_fuerza_bruta(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"\d", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0:
        return "No se puede estimar"

    combinaciones = charset ** len(password)

    intentos_por_segundo = 1_000_000_000
    segundos = combinaciones / intentos_por_segundo

    if segundos < 1:
        return "Instantáneo"
    elif segundos < 60:
        return "Menos de 1 minuto"
    elif segundos < 3600:
        return "Minutos"
    elif segundos < 86400:
        return "Horas"
    elif segundos < 31_536_000:
        return "Días o meses"
    elif segundos < 31_536_000 * 100:
        return "Años"
    else:
        return "Siglos o más"


def calcular_entropia(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"\d", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0:
        return 0

    return round(len(password) * math.log2(charset), 2)


def analizar_password(password):
    puntuacion = 0
    observaciones = []
    recomendaciones = []

    password_lower = password.lower()
    password_normalizada = normalizar_leet(password)

    if len(password) >= 18:
        puntuacion += 3
    elif len(password) >= 14:
        puntuacion += 2
    elif len(password) >= 12:
        puntuacion += 1
    else:
        puntuacion -= 2
        observaciones.append("La contraseña es corta.")
        recomendaciones.append("Usá al menos 14 caracteres. Idealmente 16 o más.")

    if re.search(r"[A-Z]", password):
        puntuacion += 1
    else:
        observaciones.append("No contiene mayúsculas.")

    if re.search(r"[a-z]", password):
        puntuacion += 1
    else:
        observaciones.append("No contiene minúsculas.")

    if re.search(r"\d", password):
        puntuacion += 1
    else:
        observaciones.append("No contiene números.")

    if re.search(r"[^A-Za-z0-9]", password):
        puntuacion += 1
    else:
        observaciones.append("No contiene símbolos.")

    for word in COMMON_WORDS:
        if word in password_lower or word in password_normalizada:
            puntuacion -= 3
            observaciones.append(f"Contiene una palabra común o fácil de asociar: {word}.")
            recomendaciones.append("Evitá palabras comunes, nombres propios o datos personales.")

    for pattern in COMMON_PATTERNS:
        if pattern in password_lower:
            puntuacion -= 2
            observaciones.append(f"Contiene un patrón predecible: {pattern}.")
            recomendaciones.append("Evitá secuencias como 1234, abcd, qwerty o años.")

    tiene_secuencia, secuencia = contiene_secuencia(password)

    if tiene_secuencia:
        puntuacion -= 2
        observaciones.append(f"Contiene una secuencia de teclado o numérica: {secuencia}.")
        recomendaciones.append("Evitá secuencias consecutivas de teclado o números.")

    if re.search(r"(19|20)\d{2}", password):
        puntuacion -= 2
        observaciones.append("Contiene un año.")
        recomendaciones.append("Evitá usar años, fechas de nacimiento o fechas importantes.")

    if re.search(r"(.)\1{2,}", password):
        puntuacion -= 1
        observaciones.append("Contiene caracteres repetidos varias veces seguidas.")

    if re.search(r"[A-Za-z]+\d+[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]?$", password):
        puntuacion -= 3
        observaciones.append("Tiene una estructura común: palabra + números + símbolo.")
        recomendaciones.append("Evitá formatos previsibles como Nombre2026! o Password123.")

    entropia = calcular_entropia(password)
    tiempo_estimado = estimar_tiempo_fuerza_bruta(password)

    if puntuacion <= 2:
        nivel = "Débil"
    elif puntuacion <= 6:
        nivel = "Media"
    else:
        nivel = "Fuerte"

    if not recomendaciones and nivel == "Fuerte":
        recomendaciones.append("La contraseña cumple buenas prácticas básicas.")

    return {
        "nivel": nivel,
        "puntuacion": puntuacion,
        "observaciones": observaciones,
        "recomendaciones": list(set(recomendaciones)),
        "entropia": entropia,
        "tiempo_estimado": tiempo_estimado
    }
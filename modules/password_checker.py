import math
import re


COMMON_WORDS = [
    "password",
    "contraseña",
    "admin",
    "administrator",
    "root",
    "qwerty",
    "usuario",
    "login",
    "welcome",
    "bienvenido",
    "argentina",
    "buenosaires",
    "joaquin",
    "juaquin",
    "registro",
    "libre",
    "aegis",
    "security",
    "toolkit",
]

COMMON_PATTERNS = [
    "123",
    "1234",
    "12345",
    "123456",
    "000",
    "111",
    "222",
    "abc",
    "abcd",
    "qwerty",
    "asdf",
    "zxcv",
    "2023",
    "2024",
    "2025",
    "2026",
]

LEET_REPLACEMENTS = {
    "@": "a",
    "4": "a",
    "0": "o",
    "1": "i",
    "3": "e",
    "$": "s",
    "5": "s",
    "7": "t",
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def normalize_leet(password):
    normalized_password = password.lower()

    for symbol, letter in LEET_REPLACEMENTS.items():
        normalized_password = normalized_password.replace(symbol, letter)

    return normalized_password


def contains_sequence(password):
    lowercase_password = password.lower()

    for sequence in SEQUENCES:
        for index in range(len(sequence) - 3):
            fragment = sequence[index:index + 4]

            if (
                fragment in lowercase_password
                or fragment[::-1] in lowercase_password
            ):
                return True, fragment

    return False, None


def calculate_character_set_size(password):
    character_set_size = 0

    if re.search(r"[a-z]", password):
        character_set_size += 26

    if re.search(r"[A-Z]", password):
        character_set_size += 26

    if re.search(r"\d", password):
        character_set_size += 10

    if re.search(r"[^A-Za-z0-9]", password):
        character_set_size += 32

    return character_set_size


def estimate_brute_force_time(password):
    character_set_size = calculate_character_set_size(password)

    if character_set_size == 0:
        return "Unable to estimate"

    combinations = character_set_size ** len(password)

    guesses_per_second = 1_000_000_000
    estimated_seconds = combinations / guesses_per_second

    if estimated_seconds < 1:
        return "Instantly"

    if estimated_seconds < 60:
        return "Less than 1 minute"

    if estimated_seconds < 3_600:
        return "Minutes"

    if estimated_seconds < 86_400:
        return "Hours"

    if estimated_seconds < 31_536_000:
        return "Days or months"

    if estimated_seconds < 31_536_000 * 100:
        return "Years"

    return "Centuries or longer"


def calculate_entropy(password):
    character_set_size = calculate_character_set_size(password)

    if character_set_size == 0:
        return 0

    return round(
        len(password) * math.log2(character_set_size),
        2,
    )


def remove_duplicates(items):
    return list(dict.fromkeys(items))


def analyze_password(password):
    score = 0
    observations = []
    recommendations = []

    lowercase_password = password.lower()
    normalized_password = normalize_leet(password)

    if len(password) >= 18:
        score += 3
    elif len(password) >= 14:
        score += 2
    elif len(password) >= 12:
        score += 1
    else:
        score -= 2
        observations.append("The password is too short.")
        recommendations.append(
            "Use at least 14 characters. Ideally, use 16 or more."
        )

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        observations.append("It does not contain uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        observations.append("It does not contain lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        observations.append("It does not contain numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        observations.append("It does not contain symbols.")

    detected_common_words = set()

    for word in COMMON_WORDS:
        if (
            word in lowercase_password
            or word in normalized_password
        ):
            detected_common_words.add(word)

    for word in sorted(detected_common_words):
        score -= 3
        observations.append(
            f"It contains a common or easily associated word: {word}."
        )
        recommendations.append(
            "Avoid common words, personal names, or personal information."
        )

    for pattern in COMMON_PATTERNS:
        if pattern in lowercase_password:
            score -= 2
            observations.append(
                f"It contains a predictable pattern: {pattern}."
            )
            recommendations.append(
                "Avoid sequences such as 1234, abcd, qwerty, or years."
            )

    has_sequence, detected_sequence = contains_sequence(password)

    if has_sequence:
        score -= 2
        observations.append(
            "It contains a keyboard or numeric sequence: "
            f"{detected_sequence}."
        )
        recommendations.append(
            "Avoid consecutive keyboard or numeric sequences."
        )

    if re.search(r"(19|20)\d{2}", password):
        score -= 2
        observations.append("It contains a year.")
        recommendations.append(
            "Avoid years, birth dates, or other important dates."
        )

    if re.search(r"(.)\1{2,}", password):
        score -= 1
        observations.append(
            "It contains the same character repeated several times."
        )

    common_structure_pattern = (
        r"[A-Za-z]+\d+"
        r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]?$"
    )

    if re.search(common_structure_pattern, password):
        score -= 3
        observations.append(
            "It follows a common structure: word + numbers + symbol."
        )
        recommendations.append(
            "Avoid predictable formats such as Name2026! or Password123."
        )

    entropy = calculate_entropy(password)
    estimated_time = estimate_brute_force_time(password)

    if score <= 2:
        level = "Weak"
    elif score <= 6:
        level = "Moderate"
    else:
        level = "Strong"

    if not recommendations and level == "Strong":
        recommendations.append(
            "The password meets basic security recommendations."
        )

    recommendations = remove_duplicates(recommendations)

    return {
        "level": level,
        "score": score,
        "observations": observations,
        "recommendations": recommendations,
        "entropy": entropy,
        "estimated_time": estimated_time,

        # Temporary compatibility keys
        "nivel": level,
        "puntuacion": score,
        "observaciones": observations,
        "recomendaciones": recommendations,
        "entropia": entropy,
        "tiempo_estimado": estimated_time,
    }


# Temporary compatibility aliases
normalizar_leet = normalize_leet
contiene_secuencia = contains_sequence
estimar_tiempo_fuerza_bruta = estimate_brute_force_time
calcular_entropia = calculate_entropy
analizar_password = analyze_password
import streamlit as st

from modules.password_checker import analizar_password as analyze_password


LEVEL_TRANSLATIONS = {
    "Fuerte": "Strong",
    "Media": "Moderate",
    "Débil": "Weak",
    "Strong": "Strong",
    "Moderate": "Moderate",
    "Weak": "Weak",
}


def show_password_checker():
    st.header("Password Analyzer")

    st.info(
        "The analysis is performed locally. "
        "The entered password is not stored or logged."
    )

    password = st.text_input(
        "Enter a password",
        type="password",
    )

    if not st.button("Analyze"):
        return

    if not password:
        st.warning("Enter a password before running the analysis.")
        return

    result = analyze_password(password)

    level = result.get(
        "level",
        result.get("nivel", "Unknown"),
    )
    score = result.get(
        "score",
        result.get("puntuacion", 0),
    )
    entropy = result.get(
        "entropy",
        result.get("entropia", 0),
    )
    estimated_time = result.get(
        "estimated_time",
        result.get("tiempo_estimado", "Unknown"),
    )
    observations = result.get(
        "observations",
        result.get("observaciones", []),
    )
    recommendations = result.get(
        "recommendations",
        result.get("recomendaciones", []),
    )

    displayed_level = LEVEL_TRANSLATIONS.get(
        level,
        level,
    )

    st.subheader(f"Result: {displayed_level}")

    score_column, entropy_column, brute_force_column = st.columns(3)

    score_column.metric(
        "Score",
        score,
    )
    entropy_column.metric(
        "Estimated entropy",
        f"{entropy} bits",
    )
    brute_force_column.metric(
        "Brute-force estimate",
        estimated_time,
    )

    if displayed_level == "Strong":
        st.success(
            "The password meets basic security recommendations."
        )
    elif displayed_level == "Moderate":
        st.warning(
            "The password provides moderate protection but could be improved."
        )
    else:
        st.error(
            "The password is weak and should be replaced."
        )

    if observations:
        st.subheader("Observations")

        for observation in observations:
            st.write(f"- {observation}")

    if recommendations:
        st.subheader("Recommendations")

        for recommendation in recommendations:
            st.write(f"- {recommendation}")


# Temporary compatibility alias
mostrar_password_checker = show_password_checker
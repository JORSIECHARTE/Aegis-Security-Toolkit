import streamlit as st

from modules.password_checker import analyze_password


def show_password_checker():
    st.header("Password Analyzer")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    st.info(
        "The analysis is performed locally. "
        "The entered password is not stored or logged."
    )

    if interface_mode == "Standard":
        st.caption(
            "Aegis evaluates common weaknesses, predictable "
            "patterns, password length, character variety, and "
            "estimated resistance to brute-force attacks."
        )

        with st.expander("How does password analysis work?"):
            st.write(
                "Aegis examines several characteristics of the "
                "password without sending it to an external service. "
                "The analysis looks for common words, predictable "
                "sequences, repeated characters, years, common "
                "structures, length, and character variety."
            )

            st.write(
                "The result is an estimate intended to help identify "
                "weak password construction. It does not guarantee "
                "that a password cannot be compromised."
            )

    else:
        st.caption(
            "Advanced Mode displays the complete technical analysis, "
            "including score, estimated entropy, brute-force estimate, "
            "observations, and recommendations."
        )

    password = st.text_input(
        "Enter a password",
        type="password",
        help=(
            "The password is analyzed locally and is not "
            "stored in the Aegis database."
        ),
    )

    if not st.button(
        "Analyze Password",
        type="primary",
    ):
        return

    if not password:
        st.warning(
            "Enter a password before running the analysis."
        )
        return

    with st.spinner("Analyzing password..."):
        result = analyze_password(password)

    level = result.get(
        "level",
        "Unknown",
    )

    score = result.get(
        "score",
        0,
    )

    entropy = result.get(
        "entropy",
        0,
    )

    estimated_time = result.get(
        "estimated_time",
        "Unknown",
    )

    observations = result.get(
        "observations",
        [],
    )

    recommendations = result.get(
        "recommendations",
        [],
    )

    # ---------------------------------------------------------
    # Result
    # ---------------------------------------------------------

    st.subheader(
        f"Password Strength: {level}"
    )

    if level == "Strong":
        st.success(
            "The password meets the current Aegis "
            "security recommendations."
        )

    elif level == "Moderate":
        st.warning(
            "The password provides moderate protection "
            "but could be improved."
        )

    else:
        st.error(
            "The password contains weaknesses and "
            "should be improved."
        )

    # ---------------------------------------------------------
    # Standard mode
    # ---------------------------------------------------------

    if interface_mode == "Standard":
        (
            strength_column,
            brute_force_column,
        ) = st.columns(2)

        strength_column.metric(
            "Strength",
            level,
        )

        brute_force_column.metric(
            "Estimated Brute-Force Resistance",
            estimated_time,
        )

        st.caption(
            "The brute-force estimate is theoretical and depends "
            "on assumptions about the attacker's guessing rate. "
            "Real attack times can differ significantly."
        )

        if observations:
            st.subheader("What Aegis Detected")

            for observation in observations:
                st.write(
                    f"- {observation}"
                )

        if recommendations:
            st.subheader("How to Improve It")

            for recommendation in recommendations:
                st.write(
                    f"- {recommendation}"
                )

        with st.expander("View Technical Details"):
            st.metric(
                "Internal Score",
                score,
            )

            st.metric(
                "Estimated Entropy",
                f"{entropy} bits",
            )

            st.write(
                "Entropy is a mathematical estimate based on "
                "password length and the character sets used. "
                "Predictable human patterns can make a password "
                "weaker than its theoretical entropy suggests."
            )

        return

    # ---------------------------------------------------------
    # Advanced mode
    # ---------------------------------------------------------

    (
        score_column,
        entropy_column,
        brute_force_column,
    ) = st.columns(3)

    score_column.metric(
        "Score",
        score,
    )

    entropy_column.metric(
        "Estimated Entropy",
        f"{entropy} bits",
    )

    brute_force_column.metric(
        "Brute-Force Estimate",
        estimated_time,
    )

    st.caption(
        "Entropy and brute-force resistance are estimates. "
        "Predictable structures, dictionary attacks, credential "
        "reuse, leaked passwords, and attacker knowledge can "
        "substantially reduce real-world resistance."
    )

    if observations:
        st.subheader("Observations")

        for observation in observations:
            st.write(
                f"- {observation}"
            )

    else:
        st.success(
            "No significant weaknesses were detected by "
            "the current analysis rules."
        )

    if recommendations:
        st.subheader("Recommendations")

        for recommendation in recommendations:
            st.write(
                f"- {recommendation}"
            )
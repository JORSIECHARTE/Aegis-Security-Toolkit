import streamlit as st

from modules.log_analyzer import analizar_logs as analyze_logs


RISK_LEVEL_TRANSLATIONS = {
    "Crítico": "Critical",
    "Alto": "High",
    "Medio": "Medium",
    "Bajo": "Low",
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


def show_log_analyzer():
    st.header("Log Analyzer")

    st.info(
        "Upload a .log or .txt file to detect basic and advanced "
        "security events."
    )

    uploaded_file = st.file_uploader(
        "Select a log file",
        type=["log", "txt"],
    )

    if uploaded_file is None:
        return

    file_content = uploaded_file.read().decode(
        "utf-8",
        errors="ignore",
    )

    result = analyze_logs(file_content)

    summary = result.get(
        "summary",
        result.get("resumen", {}),
    )

    total_lines = result.get(
        "total_lines",
        result.get("total_lineas", 0),
    )
    failed_attempts = summary.get(
        "failed_attempts",
        summary.get("intentos_fallidos", 0),
    )
    alert_count = summary.get(
        "alerts",
        summary.get("alertas", 0),
    )
    risk_score = summary.get(
        "risk_score",
        0,
    )
    risk_level = summary.get(
        "risk_level",
        summary.get("nivel_riesgo", "Low"),
    )

    alerts = result.get(
        "alerts",
        result.get("alertas", []),
    )
    frequent_ips = result.get(
        "frequent_ips",
        result.get("ips_frecuentes", []),
    )
    suspicious_events = result.get(
        "suspicious_events",
        result.get("eventos_sospechosos", []),
    )
    failed_logins = result.get(
        "failed_logins",
        [],
    )
    successful_logins = result.get(
        "successful_logins",
        [],
    )

    displayed_risk_level = RISK_LEVEL_TRANSLATIONS.get(
        risk_level,
        risk_level,
    )

    st.subheader("Security Summary")

    (
        lines_column,
        failed_column,
        alerts_column,
        risk_column,
    ) = st.columns(4)

    lines_column.metric(
        "Lines analyzed",
        total_lines,
    )
    failed_column.metric(
        "Failed attempts",
        failed_attempts,
    )
    alerts_column.metric(
        "Alerts",
        alert_count,
    )
    risk_column.metric(
        "Risk score",
        f"{risk_score}/100",
    )

    if displayed_risk_level == "Critical":
        st.error(f"Risk level: {displayed_risk_level}")
    elif displayed_risk_level == "High":
        st.warning(f"Risk level: {displayed_risk_level}")
    elif displayed_risk_level == "Medium":
        st.info(f"Risk level: {displayed_risk_level}")
    else:
        st.success(f"Risk level: {displayed_risk_level}")

    st.divider()

    st.subheader("Detected Alerts")

    if alerts:
        st.dataframe(
            alerts,
            width="stretch",
            hide_index=True,
        )
    else:
        st.success("No advanced alerts were detected.")

    st.divider()

    ip_column, events_column = st.columns(2)

    with ip_column:
        st.subheader("Detected IP Addresses")

        if frequent_ips:
            st.dataframe(
                frequent_ips,
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No IP addresses were detected.")

    with events_column:
        st.subheader("Suspicious Events")

        if suspicious_events:
            st.dataframe(
                suspicious_events,
                width="stretch",
                hide_index=True,
            )
        else:
            st.success("No suspicious events were detected.")

    st.divider()

    st.subheader("Failed Login Attempts")

    if failed_logins:
        st.dataframe(
            failed_logins,
            width="stretch",
            hide_index=True,
        )
    else:
        st.success("No failed login attempts were detected.")

    st.subheader("Successful Logins")

    if successful_logins:
        st.dataframe(
            successful_logins,
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No successful logins were detected.")


# Temporary compatibility alias
mostrar_log_analyzer = show_log_analyzer
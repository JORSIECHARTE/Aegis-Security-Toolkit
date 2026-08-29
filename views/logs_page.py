import streamlit as st

from modules.log_analyzer import analyze_logs


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
        {},
    )

    total_lines = result.get(
        "total_lines",
        0,
    )

    failed_attempts = summary.get(
        "failed_attempts",
        0,
    )

    alert_count = summary.get(
        "alerts",
        0,
    )

    risk_score = summary.get(
        "risk_score",
        0,
    )

    risk_level = summary.get(
        "risk_level",
        "Low",
    )

    alerts = result.get(
        "alerts",
        [],
    )

    frequent_ips = result.get(
        "frequent_ips",
        [],
    )

    suspicious_events = result.get(
        "suspicious_events",
        [],
    )

    failed_logins = result.get(
        "failed_logins",
        [],
    )

    successful_logins = result.get(
        "successful_logins",
        [],
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

    if risk_level == "Critical":
        st.error(
            f"Risk level: {risk_level}"
        )

    elif risk_level == "High":
        st.warning(
            f"Risk level: {risk_level}"
        )

    elif risk_level == "Medium":
        st.info(
            f"Risk level: {risk_level}"
        )

    else:
        st.success(
            f"Risk level: {risk_level}"
        )

    st.divider()

    st.subheader("Detected Alerts")

    if alerts:
        st.dataframe(
            alerts,
            width="stretch",
            hide_index=True,
        )

    else:
        st.success(
            "No advanced alerts were detected."
        )

    st.divider()

    ip_column, events_column = st.columns(2)

    with ip_column:
        st.subheader(
            "Detected IP Addresses"
        )

        if frequent_ips:
            st.dataframe(
                frequent_ips,
                width="stretch",
                hide_index=True,
            )

        else:
            st.info(
                "No IP addresses were detected."
            )

    with events_column:
        st.subheader(
            "Suspicious Events"
        )

        if suspicious_events:
            st.dataframe(
                suspicious_events,
                width="stretch",
                hide_index=True,
            )

        else:
            st.success(
                "No suspicious events were detected."
            )

    st.divider()

    st.subheader("Failed Login Attempts")

    if failed_logins:
        st.dataframe(
            failed_logins,
            width="stretch",
            hide_index=True,
        )

    else:
        st.success(
            "No failed login attempts were detected."
        )

    st.subheader("Successful Logins")

    if successful_logins:
        st.dataframe(
            successful_logins,
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No successful logins were detected."
        )
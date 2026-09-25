import streamlit as st

from modules.log_analyzer import analyze_logs


def show_log_analyzer():
    st.header("Log Analyzer")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    st.info(
        "Upload a .log or .txt file to identify security events, "
        "authentication activity, suspicious patterns, and alerts."
    )

    if interface_mode == "Standard":
        st.caption(
            "Aegis analyzes the log automatically and highlights "
            "the most relevant security information."
        )

        with st.expander("What does the Log Analyzer look for?"):
            st.write(
                "Aegis searches for authentication failures, "
                "successful logins, suspicious events, recurring "
                "IP addresses, and patterns that may indicate "
                "security-relevant activity."
            )

    else:
        st.caption(
            "Advanced Mode displays the complete set of events "
            "and technical information extracted from the log."
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

    if not file_content.strip():
        st.warning(
            "The uploaded file is empty or contains no readable text."
        )
        return

    with st.spinner("Analyzing log..."):
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

    # ---------------------------------------------------------
    # Security summary
    # ---------------------------------------------------------

    st.subheader("Security Summary")

    (
        lines_column,
        failed_column,
        alerts_column,
        risk_column,
    ) = st.columns(4)

    lines_column.metric(
        "Lines Analyzed",
        total_lines,
    )

    failed_column.metric(
        "Failed Attempts",
        failed_attempts,
    )

    alerts_column.metric(
        "Alerts",
        alert_count,
    )

    risk_column.metric(
        "Risk Score",
        f"{risk_score}/100",
    )

    if interface_mode == "Standard":
        st.caption(
            "The risk score summarizes the security-relevant "
            "activity detected in this log. A high score indicates "
            "that the events should receive closer investigation."
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

    # ---------------------------------------------------------
    # Alerts
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Detected Alerts")

    if interface_mode == "Standard":
        st.caption(
            "Alerts represent patterns that Aegis considers "
            "important enough to require further review."
        )

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

    # ---------------------------------------------------------
    # Standard mode
    # ---------------------------------------------------------

    if interface_mode == "Standard":
        st.divider()

        st.subheader("Activity Overview")

        (
            suspicious_column,
            failed_login_column,
            successful_login_column,
        ) = st.columns(3)

        suspicious_column.metric(
            "Suspicious Events",
            len(suspicious_events),
        )

        failed_login_column.metric(
            "Failed Logins",
            len(failed_logins),
        )

        successful_login_column.metric(
            "Successful Logins",
            len(successful_logins),
        )

        if suspicious_events:
            st.subheader("Suspicious Events")

            st.dataframe(
                suspicious_events,
                width="stretch",
                hide_index=True,
            )

        if failed_logins:
            st.subheader("Failed Login Attempts")

            st.dataframe(
                failed_logins,
                width="stretch",
                hide_index=True,
            )

        with st.expander("View Additional Technical Details"):
            st.subheader("Detected IP Addresses")

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

        return

    # ---------------------------------------------------------
    # Advanced mode
    # ---------------------------------------------------------

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

import streamlit as st

from config import (
    CSV_REPORT_FILENAME,
    DEFAULT_END_PORT,
    DEFAULT_SCAN_TARGET,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_START_PORT,
    HTML_REPORT_FILENAME,
    MAX_PORT,
    MAX_SCAN_WORKERS,
    MIN_PORT,
    MIN_SCAN_WORKERS,
    SCAN_TIMEOUT_OPTIONS,
    SCAN_WORKERS_STEP,
    TXT_REPORT_FILENAME,
)
from database.db import (
    get_active_targets,
    save_scan,
)
from modules.report_generator import (
    generate_html_scan_report,
)
from modules.scanner import (
    generate_csv_report,
    generate_txt_report,
    scan_port_range,
)
from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary,
)
from services.vulnerability_rules import (
    analyze_service_vulnerabilities,
)


SCAN_PROFILES = {
    "Quick Scan": {
        "start_port": 1,
        "end_port": 1024,
        "timeout": 0.3,
        "workers": 100,
        "description": (
            "Scans ports 1-1024, covering many commonly "
            "used network services."
        ),
    },
    "Common Services": {
        "start_port": 1,
        "end_port": 5000,
        "timeout": 0.3,
        "workers": 100,
        "description": (
            "Scans a broader range that includes many "
            "common application and service ports."
        ),
    },
    "Extended Scan": {
        "start_port": 1,
        "end_port": 10000,
        "timeout": 0.5,
        "workers": 100,
        "description": (
            "Performs a wider scan for services running "
            "outside the most common port range."
        ),
    },
}


def show_port_scanner():
    st.header("Port Scanner")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    st.warning(
        "Use this module only on systems you own, localhost, "
        "authorized networks, or personal lab environments."
    )

    if interface_mode == "Standard":
        st.caption(
            "Standard Mode uses predefined scan profiles so "
            "you can run an assessment without configuring "
            "low-level scanner parameters."
        )
    else:
        st.caption(
            "Advanced Mode provides direct control over the "
            "scanner configuration."
        )

    # ---------------------------------------------------------
    # Target selection
    # ---------------------------------------------------------

    st.subheader("Scan Target")

    active_targets = get_active_targets()

    target_sources = [
        "Managed Target",
        "Custom Target",
    ]

    if active_targets:
        default_source_index = 0
    else:
        default_source_index = 1

    target_source = st.radio(
        "Target Source",
        target_sources,
        index=default_source_index,
        horizontal=True,
        help=(
            "Select an active target managed by Aegis or "
            "enter a custom IP address or hostname."
        ),
    )

    selected_target_id = None

    if target_source == "Managed Target":
        if not active_targets:
            st.info(
                "No active managed targets are available. "
                "Create or activate a target in "
                "Targets > Manage Targets."
            )
            return

        target_lookup = {
            target[0]: target
            for target in active_targets
        }

        selected_target_id = st.selectbox(
            "Select Managed Target",
            options=list(target_lookup.keys()),
            format_func=lambda target_id: (
                f"{target_lookup[target_id][1]} | "
                f"{target_lookup[target_id][2]}"
            ),
        )

        selected_target = target_lookup[
            selected_target_id
        ]

        target_name = selected_target[1]
        target = selected_target[2].strip()
        target_description = selected_target[3]

        st.text_input(
            "Target IP or hostname",
            value=target,
            disabled=True,
        )

        if target_description:
            st.caption(
                f"Description: {target_description}"
            )

        if interface_mode == "Advanced":
            with st.expander("Managed Target Details"):
                st.write(
                    f"**Target ID:** {selected_target_id}"
                )
                st.write(
                    f"**Name:** {target_name}"
                )
                st.write(
                    f"**Host:** {target}"
                )
                st.write(
                    "**Status:** Active"
                )
                st.write(
                    f"**Created:** {selected_target[5]}"
                )

    else:
        target = st.text_input(
            "Target IP or hostname",
            value=DEFAULT_SCAN_TARGET,
            help=(
                "Enter the IP address or hostname of "
                "a system you are authorized to assess."
            ),
        ).strip()

        if interface_mode == "Standard":
            st.caption(
                "Custom targets can be scanned without "
                "adding them to the managed target list."
            )

    # ---------------------------------------------------------
    # Scan configuration
    # ---------------------------------------------------------

    st.subheader("Scan Configuration")

    if interface_mode == "Standard":
        profile_name = st.selectbox(
            "Scan Profile",
            list(SCAN_PROFILES.keys()),
        )

        profile = SCAN_PROFILES[profile_name]

        st.info(profile["description"])

        start_port = profile["start_port"]
        end_port = profile["end_port"]
        timeout = profile["timeout"]
        workers = profile["workers"]

        (
            range_column,
            timeout_column,
            workers_column,
        ) = st.columns(3)

        range_column.metric(
            "Port Range",
            f"{start_port}-{end_port}",
        )

        timeout_column.metric(
            "Timeout",
            f"{timeout} s",
        )

        workers_column.metric(
            "Concurrent Threads",
            workers,
        )

    else:
        (
            start_column,
            end_column,
            timeout_column,
        ) = st.columns(3)

        with start_column:
            start_port = st.number_input(
                "Start port",
                min_value=MIN_PORT,
                max_value=MAX_PORT,
                value=DEFAULT_START_PORT,
            )

        with end_column:
            end_port = st.number_input(
                "End port",
                min_value=MIN_PORT,
                max_value=MAX_PORT,
                value=DEFAULT_END_PORT,
            )

        with timeout_column:
            timeout = st.selectbox(
                "Timeout per port",
                SCAN_TIMEOUT_OPTIONS,
                index=SCAN_TIMEOUT_OPTIONS.index(
                    DEFAULT_SCAN_TIMEOUT
                ),
            )

        workers = st.slider(
            "Concurrent threads",
            min_value=MIN_SCAN_WORKERS,
            max_value=MAX_SCAN_WORKERS,
            value=DEFAULT_SCAN_WORKERS,
            step=SCAN_WORKERS_STEP,
        )

    banner_enabled = st.checkbox(
        "Enable banner grabbing",
        help=(
            "Attempts to retrieve information exposed by "
            "services running on open ports."
        ),
    )

    if interface_mode == "Standard":
        with st.expander("What is banner grabbing?"):
            st.write(
                "Banner grabbing attempts to collect information "
                "returned by a network service. This information "
                "can help identify the software or service running "
                "on an open port."
            )

    # ---------------------------------------------------------
    # Scan execution
    # ---------------------------------------------------------

    if not st.button(
        "Start Scan",
        type="primary",
    ):
        return

    if not target.strip():
        st.error(
            "Enter a target IP address or hostname."
        )
        return

    if start_port > end_port:
        st.error(
            "Start port cannot be greater than end port."
        )
        return

    with st.spinner(
        f"Scanning {target}..."
    ):
        scan_result = scan_port_range(
            ip=target,
            start_port=int(start_port),
            end_port=int(end_port),
            timeout=float(timeout),
            banner=banner_enabled,
            workers=int(workers),
        )

    scan_id = save_scan(scan_result)

    st.success(
        f"Scan saved to history with ID {scan_id}."
    )

    # ---------------------------------------------------------
    # Scan summary
    # ---------------------------------------------------------

    st.subheader("Scan Summary")

    (
        target_column,
        scanned_column,
        open_column,
        duration_column,
    ) = st.columns(4)

    target_column.metric(
        "Target",
        scan_result["ip"],
    )

    scanned_column.metric(
        "Ports Scanned",
        scan_result["ports_scanned"],
    )

    open_column.metric(
        "Open Ports",
        scan_result["open_ports"],
    )

    duration_column.metric(
        "Duration",
        f"{scan_result['duration_seconds']} s",
    )

    if selected_target_id is not None:
        st.caption(
            f"Managed Target: {target_name} "
            f"(ID: {selected_target_id})"
        )

    risk_summary = calculate_overall_risk(
        scan_result["results"]
    )

    executive_summary = generate_executive_summary(
        scan_result
    )

    vulnerability_findings = (
        analyze_service_vulnerabilities(
            scan_result["results"]
        )
    )

    # ---------------------------------------------------------
    # Risk dashboard
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Risk Dashboard")

    (
        score_column,
        assessment_column,
    ) = st.columns(2)

    score_column.metric(
        "Overall Risk Score",
        risk_summary["overall_score"],
    )

    assessment_column.metric(
        "Assessment",
        risk_summary["assessment"],
    )

    assessment = risk_summary["assessment"]

    if interface_mode == "Standard":
        st.caption(
            "The risk score summarizes the exposure identified "
            "during this scan. It should be treated as an "
            "assessment aid rather than proof that a system is "
            "vulnerable."
        )

    if assessment in ["Critical", "High"]:
        st.error(executive_summary)

    elif assessment == "Medium":
        st.warning(executive_summary)

    else:
        st.success(executive_summary)

    if risk_summary["high_risk_services"]:
        st.subheader("High-Risk Services")

        if interface_mode == "Standard":
            st.caption(
                "These services may require additional review "
                "because of their exposure or security relevance."
            )

        st.dataframe(
            risk_summary["high_risk_services"],
            width="stretch",
        )

    # ---------------------------------------------------------
    # Vulnerability findings
    # ---------------------------------------------------------

    st.subheader("Vulnerability Findings")

    if interface_mode == "Standard":
        st.caption(
            "Findings are generated from the evidence collected "
            "by Aegis and its current detection rules. A finding "
            "should be validated before being treated as a "
            "confirmed vulnerability."
        )

    if vulnerability_findings:
        st.dataframe(
            vulnerability_findings,
            width="stretch",
        )

    else:
        st.success(
            "No vulnerability findings were detected "
            "based on the current rules."
        )

    if risk_summary["recommendations"]:
        st.subheader("Recommendations")

        for recommendation in risk_summary[
            "recommendations"
        ]:
            st.write(
                f"- {recommendation}"
            )

    # ---------------------------------------------------------
    # Scan details
    # ---------------------------------------------------------

    st.divider()

    st.write(
        f"Date: {scan_result['scan_date']}"
    )

    st.write(
        f"Port range: "
        f"{scan_result['start_port']} - "
        f"{scan_result['end_port']}"
    )

    if not scan_result["results"]:
        st.info(
            "No open ports were detected in the "
            "selected range."
        )
        return

    st.subheader("Open Ports")

    if interface_mode == "Standard":
        st.caption(
            "An open port indicates that a network service is "
            "accepting connections. An open port alone does not "
            "mean that the service is vulnerable."
        )

    st.dataframe(
        scan_result["results"],
        width="stretch",
    )

    # ---------------------------------------------------------
    # Reports
    # ---------------------------------------------------------

    txt_report = generate_txt_report(
        scan_result
    )

    csv_report = generate_csv_report(
        scan_result
    )

    html_report = generate_html_scan_report(
        scan_result
    )

    (
        txt_column,
        csv_column,
        html_column,
    ) = st.columns(3)

    with txt_column:
        st.download_button(
            label="Download TXT Report",
            data=txt_report,
            file_name=TXT_REPORT_FILENAME,
            mime="text/plain",
        )

    with csv_column:
        st.download_button(
            label="Download CSV Report",
            data=csv_report,
            file_name=CSV_REPORT_FILENAME,
            mime="text/csv",
        )

    with html_column:
        st.download_button(
            label="Download HTML Report",
            data=html_report,
            file_name=HTML_REPORT_FILENAME,
            mime="text/html",
        )

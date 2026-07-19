import streamlit as st

from modules.network_discovery import discover_hosts
from modules.report_generator import generate_html_scan_report
from modules.scanner import scan_port_range
from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary,
)
from services.vulnerability_rules import analyze_service_vulnerabilities


def show_network_discovery():
    st.header("Network Discovery")

    st.info(
        "Discover active hosts inside your local network. "
        "Use this module only on networks you own or are authorized to assess."
    )

    base_ip = st.text_input(
        "Base network",
        value="192.168.1",
    )

    workers = st.slider(
        "Concurrent threads",
        min_value=10,
        max_value=200,
        value=100,
    )

    timeout = st.selectbox(
        "Timeout per check",
        options=[0.2, 0.4, 0.6, 1.0],
        index=1,
    )

    if st.button("Discover Hosts"):
        with st.spinner("Searching for active hosts..."):
            discovery_result = discover_hosts(
                base_ip=base_ip,
                workers=int(workers),
                timeout=float(timeout),
            )

        st.session_state["network_discovery_result"] = discovery_result

    if "network_discovery_result" not in st.session_state:
        return

    discovery_result = st.session_state["network_discovery_result"]

    hosts_column, duration_column = st.columns(2)

    hosts_column.metric(
        "Hosts Detected",
        discovery_result["count"],
    )

    duration_column.metric(
        "Duration",
        f"{discovery_result['duration']} s",
    )

    st.write(
        f"Ports checked: {discovery_result['ports_checked']}"
    )

    if not discovery_result["hosts"]:
        st.warning("No active hosts were detected.")
        return

    st.dataframe(
        discovery_result["hosts"],
        width="stretch",
    )

    st.divider()
    st.subheader("Quick Scan Selected Host")

    host_options = [
        (
            f"{host['ip']} | "
            f"{host['hostname']} | "
            f"Port {host['detected_port']}"
        )
        for host in discovery_result["hosts"]
    ]

    selected_host_label = st.selectbox(
        "Select host",
        options=host_options,
    )

    selected_ip = selected_host_label.split(" | ")[0]

    start_column, end_column, banner_column = st.columns(3)

    with start_column:
        start_port = st.number_input(
            "Start port",
            min_value=1,
            max_value=65535,
            value=1,
        )

    with end_column:
        end_port = st.number_input(
            "End port",
            min_value=1,
            max_value=65535,
            value=1024,
        )

    with banner_column:
        banner_enabled = st.checkbox(
            "Enable banner grabbing"
        )

    if st.button("Run Quick Scan"):
        if start_port > end_port:
            st.error(
                "Start port cannot be greater than end port."
            )
            return

        with st.spinner(f"Scanning {selected_ip}..."):
            quick_scan_result = scan_port_range(
                ip=selected_ip,
                start_port=int(start_port),
                end_port=int(end_port),
                timeout=float(timeout),
                banner=banner_enabled,
                workers=int(workers),
            )

        st.session_state["network_quick_scan_result"] = (
            quick_scan_result
        )

    if "network_quick_scan_result" not in st.session_state:
        return

    scan_result = st.session_state["network_quick_scan_result"]

    st.subheader("Quick Scan Result")

    target_column, open_ports_column, duration_column = st.columns(3)

    target_column.metric(
        "Target",
        scan_result["ip"],
    )

    open_ports_column.metric(
        "Open Ports",
        scan_result["open_ports"],
    )

    duration_column.metric(
        "Duration",
        f"{scan_result['duration_seconds']} s",
    )

    risk_summary = calculate_overall_risk(
        scan_result["results"]
    )

    executive_summary = generate_executive_summary(
        scan_result
    )

    vulnerability_findings = analyze_service_vulnerabilities(
        scan_result["results"]
    )

    st.divider()
    st.subheader("Risk Dashboard")

    score_column, assessment_column = st.columns(2)

    score_column.metric(
        "Overall Risk Score",
        risk_summary["overall_score"],
    )

    assessment_column.metric(
        "Assessment",
        risk_summary["assessment"],
    )

    assessment = risk_summary["assessment"]

    if assessment in {"Critical", "High"}:
        st.error(executive_summary)

    elif assessment == "Medium":
        st.warning(executive_summary)

    else:
        st.success(executive_summary)

    if risk_summary["high_risk_services"]:
        st.subheader("High-Risk Services")

        st.dataframe(
            risk_summary["high_risk_services"],
            width="stretch",
        )

    if risk_summary["recommendations"]:
        st.subheader("Recommendations")

        for recommendation in risk_summary["recommendations"]:
            st.write(f"- {recommendation}")

    st.divider()
    st.subheader("Vulnerability Findings")

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

    st.divider()

    if not scan_result["results"]:
        st.info(
            "No open ports were detected in the selected range."
        )
        return

    st.subheader("Open Ports")

    st.dataframe(
        scan_result["results"],
        width="stretch",
    )

    html_report = generate_html_scan_report(scan_result)

    st.download_button(
        label="Download Advanced HTML Report",
        data=html_report,
        file_name="aegis_advanced_report.html",
        mime="text/html",
    )
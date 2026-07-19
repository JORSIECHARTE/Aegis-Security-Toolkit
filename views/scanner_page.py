import streamlit as st

from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary
)
from services.vulnerability_rules import analyze_service_vulnerabilities

from modules.scanner import (
    scan_port_range,
    generate_txt_report,
    generate_csv_report
)
from modules.report_generator import generate_html_scan_report
from database.db import save_scan


def show_port_scanner():
    st.header("Port Scanner")

    st.warning(
        "Use this module only on systems you own, localhost, "
        "authorized networks, or personal lab environments."
    )

    target = st.text_input(
        "Target IP or hostname",
        value="127.0.0.1"
    )

    start_column, end_column, timeout_column = st.columns(3)

    with start_column:
        start_port = st.number_input(
            "Start port",
            min_value=1,
            max_value=65535,
            value=1
        )

    with end_column:
        end_port = st.number_input(
            "End port",
            min_value=1,
            max_value=65535,
            value=1024
        )

    with timeout_column:
        timeout = st.selectbox(
            "Timeout per port",
            [0.3, 0.5, 1.0, 2.0],
            index=0
        )

    workers = st.slider(
        "Concurrent threads",
        min_value=10,
        max_value=200,
        value=100,
        step=10
    )

    banner_enabled = st.checkbox("Enable banner grabbing")

    if not st.button("Start Scan"):
        return

    if start_port > end_port:
        st.error("Start port cannot be greater than end port.")
        return

    with st.spinner("Scanning ports..."):
        scan_result = scan_port_range(
            ip=target,
            start_port=int(start_port),
            end_port=int(end_port),
            timeout=float(timeout),
            banner=banner_enabled,
            workers=int(workers)
        )

    scan_id = save_scan(scan_result)

    st.success(
        f"Scan saved to history with ID {scan_id}."
    )

    st.subheader("Scan Summary")

    target_column, scanned_column, open_column, duration_column = st.columns(4)

    target_column.metric(
        "Target",
        scan_result["ip"]
    )

    scanned_column.metric(
        "Ports Scanned",
        scan_result["ports_scanned"]
    )

    open_column.metric(
        "Open Ports",
        scan_result["open_ports"]
    )

    duration_column.metric(
        "Duration",
        f"{scan_result['duration_seconds']} s"
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
        risk_summary["overall_score"]
    )

    assessment_column.metric(
        "Assessment",
        risk_summary["assessment"]
    )

    assessment = risk_summary["assessment"]

    if assessment in ["Critical", "High"]:
        st.error(executive_summary)
    elif assessment == "Medium":
        st.warning(executive_summary)
    else:
        st.success(executive_summary)

    if risk_summary["high_risk_services"]:
        st.subheader("High-Risk Services")

        st.dataframe(
            risk_summary["high_risk_services"],
            width="stretch"
        )

    st.subheader("Vulnerability Findings")

    if vulnerability_findings:
        st.dataframe(
            vulnerability_findings,
            width="stretch"
        )
    else:
        st.success(
            "No vulnerability findings were detected "
            "based on the current rules."
        )

    if risk_summary["recommendations"]:
        st.subheader("Recommendations")

        for recommendation in risk_summary["recommendations"]:
            st.write(f"- {recommendation}")

    st.divider()

    st.write(f"Date: {scan_result['scan_date']}")
    st.write(
        f"Port range: "
        f"{scan_result['start_port']} - {scan_result['end_port']}"
    )

    if not scan_result["results"]:
        st.info(
            "No open ports were detected in the selected range."
        )
        return

    st.subheader("Open Ports")

    st.dataframe(
        scan_result["results"],
        width="stretch"
    )

    txt_report = generate_txt_report(scan_result)
    csv_report = generate_csv_report(scan_result)

    # This generator still uses its previous Spanish function name.
    # It will be renamed when report_generator.py is refactored.
    html_report = generate_html_scan_report(scan_result)

    txt_column, csv_column, html_column = st.columns(3)

    with txt_column:
        st.download_button(
            label="Download TXT Report",
            data=txt_report,
            file_name="aegis_scan_report.txt",
            mime="text/plain"
        )

    with csv_column:
        st.download_button(
            label="Download CSV Report",
            data=csv_report,
            file_name="aegis_scan_report.csv",
            mime="text/csv"
        )

    with html_column:
        st.download_button(
            label="Download HTML Report",
            data=html_report,
            file_name="aegis_advanced_report.html",
            mime="text/html"
        )



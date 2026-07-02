import streamlit as st

from modules.network_discovery import discover_hosts
from modules.scanner import escanear_rango
from modules.report_generator import generar_html_scan

from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary
)

from services.vulnerability_rules import analyze_service_vulnerabilities


def mostrar_network_discovery():
    st.header("Network Discovery")

    st.info("Discover active hosts inside your local network.")

    base_ip = st.text_input(
        "Base network",
        value="192.168.1"
    )

    workers = st.slider(
        "Concurrent threads",
        10,
        200,
        100
    )

    timeout = st.selectbox(
        "Timeout per check",
        [0.2, 0.4, 0.6, 1.0],
        index=1
    )

    if st.button("Discover hosts"):
        with st.spinner("Searching active hosts..."):
            result = discover_hosts(
                base_ip=base_ip,
                workers=workers,
                timeout=float(timeout)
            )

        st.session_state["network_discovery_result"] = result

    if "network_discovery_result" not in st.session_state:
        return

    result = st.session_state["network_discovery_result"]

    col1, col2 = st.columns(2)

    col1.metric("Hosts detected", result["count"])
    col2.metric("Duration", f"{result['duration']} s")

    st.write(f"Ports checked: {result['ports_checked']}")

    if not result["hosts"]:
        st.warning("No active hosts detected.")
        return

    st.dataframe(result["hosts"], width="stretch")

    st.divider()

    st.subheader("Quick Scan Selected Host")

    host_options = [
        f"{host['ip']} | {host['hostname']} | Port {host['detected_port']}"
        for host in result["hosts"]
    ]

    selected_host_label = st.selectbox(
        "Select host",
        host_options
    )

    selected_ip = selected_host_label.split(" | ")[0]

    col_start, col_end, col_banner = st.columns(3)

    with col_start:
        port_start = st.number_input(
            "Start port",
            min_value=1,
            max_value=65535,
            value=1
        )

    with col_end:
        port_end = st.number_input(
            "End port",
            min_value=1,
            max_value=65535,
            value=1024
        )

    with col_banner:
        enable_banner = st.checkbox("Enable banner grabbing")

    if st.button("Run Quick Scan"):
        if port_start > port_end:
            st.error("Start port cannot be greater than end port.")
            return

        with st.spinner(f"Scanning {selected_ip}..."):
            scan_result = escanear_rango(
                ip=selected_ip,
                puerto_inicio=int(port_start),
                puerto_fin=int(port_end),
                timeout=float(timeout),
                banner=enable_banner,
                workers=int(workers)
            )

        st.subheader("Quick Scan Result")

        col_a, col_b, col_c = st.columns(3)

        col_a.metric("Target", scan_result["ip"])
        col_b.metric("Open ports", scan_result["puertos_abiertos"])
        col_c.metric("Duration", f"{scan_result['duracion_segundos']} s")

        risk_summary = calculate_overall_risk(scan_result["resultados"])
        executive_summary = generate_executive_summary(scan_result)
        vulnerability_findings = analyze_service_vulnerabilities(
            scan_result["resultados"]
        )

        st.divider()
        st.subheader("Risk Dashboard")

        risk_col1, risk_col2 = st.columns(2)

        risk_col1.metric(
            "Overall Risk Score",
            risk_summary["overall_score"]
        )

        risk_col2.metric(
            "Assessment",
            risk_summary["assessment"]
        )

        if risk_summary["assessment"] in ["Critical", "High"]:
            st.error(executive_summary)
        elif risk_summary["assessment"] == "Medium":
            st.warning(executive_summary)
        else:
            st.success(executive_summary)

        if risk_summary["high_risk_services"]:
            st.subheader("High Risk Services")
            st.dataframe(
                risk_summary["high_risk_services"],
                width="stretch"
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
                width="stretch"
            )
        else:
            st.success("No vulnerability findings detected based on the current rules.")

        st.divider()

        if scan_result["resultados"]:
            st.subheader("Open Ports")
            st.dataframe(scan_result["resultados"], width="stretch")

            html_report = generar_html_scan(scan_result)

            st.download_button(
                label="Download Advanced HTML Report",
                data=html_report,
                file_name="aegis_advanced_report.html",
                mime="text/html"
            )

        else:
            st.info("No open ports detected in the selected range.")
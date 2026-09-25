import streamlit as st

from config import (
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_DISCOVERY_WORKERS,
    DEFAULT_END_PORT,
    DEFAULT_NETWORK_BASE,
    DEFAULT_START_PORT,
    DISCOVERY_TIMEOUT_OPTIONS,
    DISCOVERY_WORKERS_STEP,
    HTML_REPORT_FILENAME,
    MAX_DISCOVERY_WORKERS,
    MAX_PORT,
    MIN_DISCOVERY_WORKERS,
    MIN_PORT,
)
from modules.network_discovery import discover_hosts
from modules.report_generator import generate_html_scan_report
from modules.scanner import scan_port_range
from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary,
)
from services.vulnerability_rules import (
    analyze_service_vulnerabilities,
)


def show_network_discovery():
    st.header("Network Discovery")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    st.info(
        "Discover active hosts inside your local network. "
        "Use this module only on networks you own or are authorized "
        "to assess."
    )

    if interface_mode == "Standard":
        st.caption(
            "Aegis uses recommended discovery settings automatically. "
            "Enter the base network and start the discovery."
        )

    else:
        st.caption(
            "Advanced Mode provides direct control over discovery "
            "timeout and concurrency."
        )

    base_ip = st.text_input(
        "Base network",
        value=DEFAULT_NETWORK_BASE,
        help=(
            "Enter the first three octets of an IPv4 network, "
            "for example 192.168.1."
        ),
    )

    if interface_mode == "Standard":
        workers = DEFAULT_DISCOVERY_WORKERS
        timeout = DEFAULT_DISCOVERY_TIMEOUT

        (
            range_column,
            timeout_column,
            workers_column,
        ) = st.columns(3)

        range_column.metric(
            "Discovery Range",
            f"{base_ip}.1 - {base_ip}.254",
        )

        timeout_column.metric(
            "Timeout",
            f"{timeout} s",
        )

        workers_column.metric(
            "Concurrent Threads",
            workers,
        )

        with st.expander("How does host discovery work?"):
            st.write(
                "Aegis checks selected network services across the "
                "target network. A host that responds on one of these "
                "services is considered active."
            )

    else:
        workers = st.slider(
            "Concurrent threads",
            min_value=MIN_DISCOVERY_WORKERS,
            max_value=MAX_DISCOVERY_WORKERS,
            value=DEFAULT_DISCOVERY_WORKERS,
            step=DISCOVERY_WORKERS_STEP,
        )

        timeout = st.selectbox(
            "Timeout per check",
            options=DISCOVERY_TIMEOUT_OPTIONS,
            index=DISCOVERY_TIMEOUT_OPTIONS.index(
                DEFAULT_DISCOVERY_TIMEOUT
            ),
        )

    if st.button(
        "Discover Hosts",
        type="primary",
    ):
        if not base_ip.strip():
            st.error(
                "Enter a base network."
            )
            return

        with st.spinner(
            "Searching for active hosts..."
        ):
            discovery_result = discover_hosts(
                base_ip=base_ip,
                workers=int(workers),
                timeout=float(timeout),
            )

        st.session_state[
            "network_discovery_result"
        ] = discovery_result

        st.session_state.pop(
            "network_quick_scan_result",
            None,
        )

    if (
        "network_discovery_result"
        not in st.session_state
    ):
        return

    discovery_result = st.session_state[
        "network_discovery_result"
    ]

    st.subheader("Discovery Summary")

    (
        hosts_column,
        duration_column,
    ) = st.columns(2)

    hosts_column.metric(
        "Hosts Detected",
        discovery_result["count"],
    )

    duration_column.metric(
        "Duration",
        f"{discovery_result['duration']} s",
    )

    st.write(
        f"Ports checked: "
        f"{discovery_result['ports_checked']}"
    )

    if interface_mode == "Standard":
        st.caption(
            "A detected host responded on at least one of the "
            "network services checked by Aegis. Hosts that do not "
            "respond may still be online."
        )

    if not discovery_result["hosts"]:
        st.warning(
            "No active hosts were detected."
        )
        return

    st.subheader("Discovered Hosts")

    st.dataframe(
        discovery_result["hosts"],
        width="stretch",
    )

    st.divider()

    st.subheader(
        "Scan Selected Host"
    )

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

    selected_ip = selected_host_label.split(
        " | "
    )[0]

    if interface_mode == "Standard":
        scan_profile = st.selectbox(
            "Scan Profile",
            [
                "Quick Scan",
                "Common Services",
                "Extended Scan",
            ],
            key="network_scan_profile",
        )

        if scan_profile == "Quick Scan":
            start_port = 1
            end_port = 1024

        elif scan_profile == "Common Services":
            start_port = 1
            end_port = 5000

        else:
            start_port = 1
            end_port = 10000

        (
            target_column,
            range_column,
        ) = st.columns(2)

        target_column.metric(
            "Selected Target",
            selected_ip,
        )

        range_column.metric(
            "Port Range",
            f"{start_port}-{end_port}",
        )

    else:
        (
            start_column,
            end_column,
        ) = st.columns(2)

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

    banner_enabled = st.checkbox(
        "Enable banner grabbing",
        key="network_banner_grabbing",
        help=(
            "Attempts to retrieve information exposed by services "
            "running on open ports."
        ),
    )

    if interface_mode == "Standard":
        with st.expander("What is banner grabbing?"):
            st.write(
                "Banner grabbing attempts to collect information "
                "returned by a network service. This can help identify "
                "the software or service running on an open port."
            )

    if st.button(
        "Run Host Scan",
        type="primary",
    ):
        if start_port > end_port:
            st.error(
                "Start port cannot be greater than "
                "end port."
            )
            return

        with st.spinner(
            f"Scanning {selected_ip}..."
        ):
            quick_scan_result = scan_port_range(
                ip=selected_ip,
                start_port=int(start_port),
                end_port=int(end_port),
                timeout=float(timeout),
                banner=banner_enabled,
                workers=int(workers),
            )

        st.session_state[
            "network_quick_scan_result"
        ] = quick_scan_result

    if (
        "network_quick_scan_result"
        not in st.session_state
    ):
        return

    scan_result = st.session_state[
        "network_quick_scan_result"
    ]

    st.subheader("Host Scan Result")

    (
        target_column,
        open_ports_column,
        duration_column,
    ) = st.columns(3)

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

    executive_summary = (
        generate_executive_summary(
            scan_result
        )
    )

    vulnerability_findings = (
        analyze_service_vulnerabilities(
            scan_result["results"]
        )
    )

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

    if interface_mode == "Standard":
        st.caption(
            "The risk score summarizes the exposure identified "
            "during the scan. It does not by itself confirm that "
            "the target is vulnerable."
        )

    assessment = risk_summary["assessment"]

    if assessment in {
        "Critical",
        "High",
    }:
        st.error(executive_summary)

    elif assessment == "Medium":
        st.warning(executive_summary)

    else:
        st.success(executive_summary)

    if risk_summary["high_risk_services"]:
        st.subheader(
            "High-Risk Services"
        )

        st.dataframe(
            risk_summary[
                "high_risk_services"
            ],
            width="stretch",
        )

    if risk_summary["recommendations"]:
        st.subheader("Recommendations")

        for recommendation in risk_summary[
            "recommendations"
        ]:
            st.write(
                f"- {recommendation}"
            )

    st.divider()

    st.subheader(
        "Vulnerability Findings"
    )

    if interface_mode == "Standard":
        st.caption(
            "Findings are based on the evidence collected by "
            "Aegis and its current detection rules. They should "
            "be validated before being treated as confirmed "
            "vulnerabilities."
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

    st.divider()

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

    html_report = generate_html_scan_report(
        scan_result
    )

    st.download_button(
        label="Download Advanced HTML Report",
        data=html_report,
        file_name=HTML_REPORT_FILENAME,
        mime="text/html",
    )
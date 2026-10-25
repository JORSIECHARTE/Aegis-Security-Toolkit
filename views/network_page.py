
import ipaddress

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
from database.db import get_active_targets
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


SCAN_PROFILES = {
    "Quick Scan": (1, 1024),
    "Common Services": (1, 5000),
    "Extended Scan": (1, 10000),
}


def validate_network_base(value):
    parts = value.strip().split(".")

    if len(parts) != 3:
        return None

    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return None

    if any(
        not part.isdecimal()
        or str(octet) != part
        or not 0 <= octet <= 255
        for part, octet in zip(parts, octets)
    ):
        return None

    return ".".join(str(octet) for octet in octets)


def get_target_network(host):
    try:
        address = ipaddress.IPv4Address(host.strip())
    except ipaddress.AddressValueError:
        return None

    network = ipaddress.IPv4Network(
        f"{address}/24",
        strict=False,
    )

    return ".".join(
        str(network.network_address).split(".")[:3]
    )


def show_network_discovery():
    st.header("Network Discovery")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    st.info(
        "Discover active hosts inside authorized networks. "
        "Only assess systems and network ranges for which "
        "you have permission."
    )

    if interface_mode == "Standard":
        st.caption(
            "Standard Mode uses recommended discovery "
            "settings and simplified scan profiles."
        )
    else:
        st.caption(
            "Advanced Mode provides direct control over "
            "discovery and scanning parameters."
        )

    # ---------------------------------------------------------
    # Network source
    # ---------------------------------------------------------

    st.subheader("Discovery Target")

    active_targets = get_active_targets()

    source_options = [
        "Custom Network",
        "Managed Target",
    ]

    network_source = st.radio(
        "Network Source",
        source_options,
        horizontal=True,
        help=(
            "Enter a network manually or derive a /24 "
            "network from a managed IPv4 target."
        ),
    )

    selected_target_id = None
    selected_target_name = None
    base_ip = None

    if network_source == "Custom Network":
        entered_base = st.text_input(
            "Base network",
            value=DEFAULT_NETWORK_BASE,
            help=(
                "Enter the first three IPv4 octets, "
                "for example 192.168.1."
            ),
        )

        base_ip = validate_network_base(
            entered_base
        )

        if entered_base.strip() and base_ip is None:
            st.error(
                "Invalid base network. Use a format "
                "such as 192.168.1."
            )

    else:
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

        selected_target_name = selected_target[1]
        selected_host = selected_target[2]

        st.text_input(
            "Managed Target Address",
            value=selected_host,
            disabled=True,
        )

        base_ip = get_target_network(
            selected_host
        )

        if base_ip is None:
            st.warning(
                "Network Discovery requires an IPv4 "
                "address to derive a network. "
                "This managed target cannot be used "
                "for network discovery."
            )
            return

        st.caption(
            f"Derived network: {base_ip}.0/24"
        )

        if interface_mode == "Advanced":
            with st.expander("Managed Target Details"):
                st.write(
                    f"**Target ID:** {selected_target_id}"
                )
                st.write(
                    f"**Name:** {selected_target_name}"
                )
                st.write(
                    f"**Host:** {selected_host}"
                )
                st.write(
                    "**Status:** Active"
                )

    # ---------------------------------------------------------
    # Discovery configuration
    # ---------------------------------------------------------

    st.subheader("Discovery Configuration")

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
            (
                f"{base_ip}.1 - {base_ip}.254"
                if base_ip
                else "Invalid network"
            ),
        )

        timeout_column.metric(
            "Timeout",
            f"{timeout} s",
        )

        workers_column.metric(
            "Concurrent Threads",
            workers,
        )

        with st.expander(
            "How does host discovery work?"
        ):
            st.write(
                "Aegis checks selected network services "
                "across the target network. A host that "
                "responds on one of these services is "
                "considered active. Hosts that do not "
                "respond may still be online."
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

        st.write(
            "Discovery range:",
            (
                f"{base_ip}.1 - {base_ip}.254"
                if base_ip
                else "Invalid network"
            ),
        )

    # ---------------------------------------------------------
    # Scope confirmation
    # ---------------------------------------------------------

    st.warning(
        "Discovery checks addresses across the entire "
        "displayed /24 range, not only the selected host. "
        "Confirm that the complete range is authorized."
    )

    scope_confirmed = st.checkbox(
        "I am authorized to assess this network range.",
        key="network_scope_confirmation",
    )

    # ---------------------------------------------------------
    # Discovery execution
    # ---------------------------------------------------------

    discovery_context = (
        network_source,
        selected_target_id,
        base_ip,
        int(workers),
        float(timeout),
    )

    if (
        st.session_state.get(
            "network_discovery_context"
        ) != discovery_context
    ):
        st.session_state.pop(
            "network_discovery_result",
            None,
        )
        st.session_state.pop(
            "network_quick_scan_result",
            None,
        )
        st.session_state.pop(
            "network_scanned_host",
            None,
        )

    if st.button(
        "Discover Hosts",
        type="primary",
    ):
        if base_ip is None:
            st.error(
                "Enter or select a valid IPv4 network."
            )
            return

        if not scope_confirmed:
            st.error(
                "Confirm authorization for the "
                "complete network range before scanning."
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

        st.session_state[
            "network_discovery_context"
        ] = discovery_context

        st.session_state.pop(
            "network_quick_scan_result",
            None,
        )
        st.session_state.pop(
            "network_scanned_host",
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

    # ---------------------------------------------------------
    # Discovery summary
    # ---------------------------------------------------------

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
            "A detected host responded on at least one "
            "network service checked by Aegis. "
            "Undetected hosts may still be online."
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

    # ---------------------------------------------------------
    # Host selection
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Scan Selected Host")

    host_lookup = {
        host["ip"]: host
        for host in discovery_result["hosts"]
    }

    selected_ip = st.selectbox(
        "Select host",
        options=list(host_lookup.keys()),
        format_func=lambda ip: (
            f"{ip} | "
            f"{host_lookup[ip]['hostname']} | "
            f"Port {host_lookup[ip]['detected_port']}"
        ),
    )

    if interface_mode == "Standard":
        scan_profile = st.selectbox(
            "Scan Profile",
            list(SCAN_PROFILES.keys()),
            key="network_scan_profile",
        )

        (
            start_port,
            end_port,
        ) = SCAN_PROFILES[scan_profile]

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
            "Attempts to retrieve information exposed "
            "by services running on open ports."
        ),
    )

    if interface_mode == "Standard":
        with st.expander(
            "What is banner grabbing?"
        ):
            st.write(
                "Banner grabbing attempts to collect "
                "information returned by a network service. "
                "This can help identify the software or "
                "service running on an open port."
            )

    # ---------------------------------------------------------
    # Host scan execution
    # ---------------------------------------------------------

    if st.button(
        "Run Host Scan",
        type="primary",
    ):
        if start_port > end_port:
            st.error(
                "Start port cannot be greater "
                "than end port."
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

        st.session_state[
            "network_scanned_host"
        ] = selected_ip

    if (
        "network_quick_scan_result"
        not in st.session_state
    ):
        return

    if (
        st.session_state.get(
            "network_scanned_host"
        ) != selected_ip
    ):
        st.info(
            "Run a scan for the newly selected host "
            "to display its results."
        )
        return

    scan_result = st.session_state[
        "network_quick_scan_result"
    ]

    # ---------------------------------------------------------
    # Host scan summary
    # ---------------------------------------------------------

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

    if interface_mode == "Standard":
        st.caption(
            "The risk score summarizes the exposure "
            "identified during the scan. It does not "
            "by itself confirm a vulnerability."
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

    # ---------------------------------------------------------
    # Vulnerability findings
    # ---------------------------------------------------------

    st.divider()

    st.subheader(
        "Vulnerability Findings"
    )

    if interface_mode == "Standard":
        st.caption(
            "Findings are based on the evidence "
            "collected by Aegis and its current "
            "detection rules. They should be validated "
            "before being treated as confirmed "
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

    # ---------------------------------------------------------
    # Open ports and report
    # ---------------------------------------------------------

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
            "An open port indicates that a network "
            "service is accepting connections. "
            "An open port alone does not mean that "
            "the service is vulnerable."
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

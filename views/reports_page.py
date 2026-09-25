import streamlit as st

from database.db import (
    get_scan_results,
    get_scans,
)


def show_reports():
    st.header("Reports")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    if interface_mode == "Standard":
        st.caption(
            "Review saved scan results and inspect the "
            "security information collected for each target."
        )

    else:
        st.caption(
            "Inspect stored scan records and detailed "
            "technical results."
        )

    scans = get_scans()

    if not scans:
        st.info(
            "No scans have been saved yet. Run a port scan "
            "to generate assessment data."
        )
        return

    # ---------------------------------------------------------
    # Available scans
    # ---------------------------------------------------------

    st.subheader("Available Scans")

    if interface_mode == "Standard":
        formatted_scans = [
            {
                "date": scan_date,
                "target": ip_address,
                "ports_scanned": ports_scanned,
                "open_ports": open_ports,
            }
            for (
                scan_id,
                scan_date,
                ip_address,
                start_port,
                end_port,
                ports_scanned,
                open_ports,
                duration_seconds,
            ) in scans
        ]

    else:
        formatted_scans = [
            {
                "id": scan_id,
                "date": scan_date,
                "target": ip_address,
                "start_port": start_port,
                "end_port": end_port,
                "ports_scanned": ports_scanned,
                "open_ports": open_ports,
                "duration_seconds": duration_seconds,
            }
            for (
                scan_id,
                scan_date,
                ip_address,
                start_port,
                end_port,
                ports_scanned,
                open_ports,
                duration_seconds,
            ) in scans
        ]

    st.dataframe(
        formatted_scans,
        width="stretch",
        hide_index=True,
    )

    # ---------------------------------------------------------
    # Scan selection
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Scan Report")

    scan_options = {
        f"{ip_address} | {scan_date} | Scan {scan_id}": scan_id
        for (
            scan_id,
            scan_date,
            ip_address,
            _,
            _,
            _,
            _,
            _,
        ) in scans
    }

    selected_scan = st.selectbox(
        "Select a scan",
        list(scan_options.keys()),
    )

    scan_id = scan_options[selected_scan]

    selected_scan_data = next(
        scan
        for scan in scans
        if scan[0] == scan_id
    )

    (
        _,
        scan_date,
        ip_address,
        start_port,
        end_port,
        ports_scanned,
        open_ports,
        duration_seconds,
    ) = selected_scan_data

    # ---------------------------------------------------------
    # Scan summary
    # ---------------------------------------------------------

    (
        target_column,
        ports_column,
        open_ports_column,
        duration_column,
    ) = st.columns(4)

    target_column.metric(
        "Target",
        ip_address,
    )

    ports_column.metric(
        "Ports Scanned",
        ports_scanned,
    )

    open_ports_column.metric(
        "Open Ports",
        open_ports,
    )

    duration_column.metric(
        "Duration",
        f"{duration_seconds} s",
    )

    if interface_mode == "Advanced":
        st.caption(
            f"Scan ID: {scan_id} | "
            f"Date: {scan_date} | "
            f"Port range: {start_port}-{end_port}"
        )

    # ---------------------------------------------------------
    # Scan results
    # ---------------------------------------------------------

    scan_results = get_scan_results(
        scan_id
    )

    st.divider()

    st.subheader("Detected Services")

    if not scan_results:
        st.info(
            "This scan does not have any recorded open ports."
        )
        return

    if interface_mode == "Standard":
        formatted_results = [
            {
                "port": port,
                "status": status,
                "service": service,
            }
            for (
                port,
                status,
                service,
                response_time_ms,
                banner,
            ) in scan_results
        ]

    else:
        formatted_results = [
            {
                "port": port,
                "status": status,
                "service": service,
                "response_time_ms": response_time_ms,
                "banner": banner,
            }
            for (
                port,
                status,
                service,
                response_time_ms,
                banner,
            ) in scan_results
        ]

    st.dataframe(
        formatted_results,
        width="stretch",
        hide_index=True,
    )

    if interface_mode == "Standard":
        st.caption(
            "Open ports identify network services that were "
            "reachable during the scan. An open port alone does "
            "not indicate that the service is vulnerable."
        )

        with st.expander(
            "Technical scan information"
        ):
            st.write(
                f"**Scan ID:** {scan_id}"
            )

            st.write(
                f"**Date:** {scan_date}"
            )

            st.write(
                f"**Port Range:** "
                f"{start_port} - {end_port}"
            )

            st.write(
                f"**Duration:** "
                f"{duration_seconds} seconds"
            )

            technical_results = [
                {
                    "port": port,
                    "response_time_ms": response_time_ms,
                    "banner": banner,
                }
                for (
                    port,
                    status,
                    service,
                    response_time_ms,
                    banner,
                ) in scan_results
            ]

            st.dataframe(
                technical_results,
                width="stretch",
                hide_index=True,
            )
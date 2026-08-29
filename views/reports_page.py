import streamlit as st

from database.db import (
    get_scan_results,
    get_scans,
)


def show_reports():
    st.header("Scan History")

    scans = get_scans()

    if not scans:
        st.info("No scans have been saved yet.")
        return

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

    scan_options = {
        f"ID {scan_id} | {ip_address} | {scan_date}": scan_id
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
        "Select a scan to view its details",
        list(scan_options.keys()),
    )

    scan_id = scan_options[selected_scan]

    scan_results = get_scan_results(scan_id)

    if not scan_results:
        st.info(
            "This scan does not have any recorded open ports."
        )
        return

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

    st.subheader(f"Scan Details — ID {scan_id}")

    st.dataframe(
        formatted_results,
        width="stretch",
        hide_index=True,
    )
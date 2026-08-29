import streamlit as st

from database.db import (
    get_open_ports_by_scan,
    get_scan_history,
)


def show_history_dashboard():
    st.header("Historical Dashboard")

    scan_history = get_scan_history()

    if not scan_history:
        st.info(
            "No historical scan data is available."
        )
        return

    formatted_scans = [
        {
            "scan_id": scan_id,
            "date": scan_date,
            "target": ip_address,
            "open_ports": open_ports,
            "duration_seconds": duration_seconds,
        }
        for (
            scan_id,
            scan_date,
            ip_address,
            open_ports,
            duration_seconds,
        ) in scan_history
    ]

    st.subheader("Scan History")

    st.dataframe(
        formatted_scans,
        width="stretch",
        hide_index=True,
    )

    st.divider()

    st.subheader("Open Ports Over Time")

    open_ports_history = (
        get_open_ports_by_scan()
    )

    chart_data = [
        {
            "scan_id": scan_id,
            "open_ports": open_ports,
        }
        for (
            scan_id,
            _,
            _,
            open_ports,
        ) in open_ports_history
    ]

    st.line_chart(
        chart_data,
        x="scan_id",
        y="open_ports",
    )

    st.divider()

    st.subheader("Summary")

    total_scans = len(
        formatted_scans
    )

    total_open_ports = sum(
        scan["open_ports"]
        for scan in formatted_scans
    )

    average_open_ports = round(
        total_open_ports / total_scans,
        2,
    )

    (
        total_scans_column,
        total_ports_column,
        average_column,
    ) = st.columns(3)

    total_scans_column.metric(
        "Total scans",
        total_scans,
    )

    total_ports_column.metric(
        "Total open ports detected",
        total_open_ports,
    )

    average_column.metric(
        "Average open ports per scan",
        average_open_ports,
    )
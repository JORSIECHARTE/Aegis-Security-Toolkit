import streamlit as st

from database.db import (
    get_scan_history,
    get_open_ports_by_scan
)


def show_history_dashboard():
    st.header("Historical Dashboard")

    scans = get_scan_history()

    if not scans:
        st.info("No historical scan data available.")
        return

    formatted_scans = []

    for scan in scans:
        formatted_scans.append({
            "scan_id": scan[0],
            "date": scan[1],
            "target": scan[2],
            "open_ports": scan[3],
            "duration_seconds": scan[4]
        })

    st.subheader("Scan History")
    st.dataframe(formatted_scans, width="stretch")

    st.divider()

    st.subheader("Open Ports Over Time")

    open_ports_data = get_open_ports_by_scan()

    chart_data = []

    for item in open_ports_data:
        chart_data.append({
            "scan_id": item[0],
            "open_ports": item[3]
        })

    st.line_chart(
        chart_data,
        x="scan_id",
        y="open_ports"
    )

    st.divider()

    st.subheader("Summary")

    total_scans = len(formatted_scans)
    total_open_ports = sum(item["open_ports"] for item in formatted_scans)
    avg_open_ports = round(total_open_ports / total_scans, 2)

    col1, col2, col3 = st.columns(3)

    col1.metric("Total scans", total_scans)
    col2.metric("Total open ports detected", total_open_ports)
    col3.metric("Average open ports", avg_open_ports)
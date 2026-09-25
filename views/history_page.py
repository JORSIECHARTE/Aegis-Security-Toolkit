import streamlit as st

from database.db import (
    get_open_ports_by_scan,
    get_scan_history,
)


def show_history_dashboard():
    st.header("Scan History")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    if interface_mode == "Standard":
        st.caption(
            "Review previous scans and observe how detected "
            "network exposure changes over time."
        )

    else:
        st.caption(
            "Review stored scan records and historical "
            "open-port activity."
        )

    scan_history = get_scan_history()

    if not scan_history:
        st.info(
            "No historical scan data is available."
        )
        return

    # ---------------------------------------------------------
    # Scan history
    # ---------------------------------------------------------

    if interface_mode == "Standard":
        formatted_scans = [
            {
                "date": scan_date,
                "target": ip_address,
                "open_ports": open_ports,
            }
            for (
                scan_id,
                scan_date,
                ip_address,
                open_ports,
                duration_seconds,
            ) in scan_history
        ]

    else:
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

    st.subheader("Previous Scans")

    st.dataframe(
        formatted_scans,
        width="stretch",
        hide_index=True,
    )

    if interface_mode == "Standard":
        st.caption(
            "Each entry represents a completed port scan "
            "stored in the Aegis database."
        )

    # ---------------------------------------------------------
    # Historical activity
    # ---------------------------------------------------------

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

    if interface_mode == "Standard":
        st.caption(
            "This chart shows the number of open ports detected "
            "during each stored scan. Changes can indicate that "
            "services were added, removed, enabled, or disabled."
        )

        with st.expander(
            "How should I interpret changes?"
        ):
            st.write(
                "An increase in open ports does not automatically "
                "mean that security became worse, and a decrease "
                "does not automatically mean that security improved."
            )

            st.write(
                "Changes should be investigated together with the "
                "target, detected services, configuration changes, "
                "and other available evidence."
            )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Historical Summary")

    total_scans = len(
        scan_history
    )

    total_open_ports = sum(
        scan[3]
        for scan in scan_history
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
        "Total Scans",
        total_scans,
    )

    total_ports_column.metric(
        "Open Port Detections",
        total_open_ports,
    )

    average_column.metric(
        "Average Open Ports per Scan",
        average_open_ports,
    )

    if interface_mode == "Standard":
        st.caption(
            "Open Port Detections is cumulative across scans. "
            "The same port detected during multiple scans is "
            "counted multiple times."
        )
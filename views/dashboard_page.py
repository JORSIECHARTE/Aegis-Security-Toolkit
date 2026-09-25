import streamlit as st

from database.db import (
    get_dashboard_metrics,
    get_detected_services,
    get_most_detected_ports,
    get_recent_scans,
)


def show_dashboard():
    st.header("Dashboard")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    if interface_mode == "Standard":
        st.caption(
            "Overview of the security activity and scan results "
            "stored by Aegis."
        )

    else:
        st.caption(
            "Operational overview of stored scans, detected "
            "services, ports, and recent assessment activity."
        )

    metrics = get_dashboard_metrics()

    # ---------------------------------------------------------
    # Main metrics
    # ---------------------------------------------------------

    (
        metric_column_1,
        metric_column_2,
        metric_column_3,
        metric_column_4,
    ) = st.columns(4)

    metric_column_1.metric(
        "Scans Completed",
        metrics["total_scans"],
    )

    metric_column_2.metric(
        "Open Ports Detected",
        metrics["total_open_ports"],
    )

    metric_column_3.metric(
        "Average Scan Duration",
        f"{metrics['average_duration']} s",
    )

    metric_column_4.metric(
        "Latest Target",
        metrics["latest_target"],
    )

    if interface_mode == "Standard":
        with st.expander("What do these metrics mean?"):
            st.write(
                "**Scans Completed:** number of port scans "
                "stored in the Aegis database."
            )

            st.write(
                "**Open Ports Detected:** total number of open "
                "ports identified across stored scans."
            )

            st.write(
                "**Average Scan Duration:** average execution "
                "time of stored scans."
            )

            st.write(
                "**Latest Target:** most recent target scanned "
                "and stored by Aegis."
            )

    # ---------------------------------------------------------
    # Detection overview
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Detection Overview")

    detected_services = get_detected_services()
    detected_ports = get_most_detected_ports()

    services_column, ports_column = st.columns(2)

    with services_column:
        st.markdown("#### Most Detected Services")

        if detected_services:
            formatted_services = [
                {
                    "service": service_name,
                    "detections": detection_count,
                }
                for (
                    service_name,
                    detection_count,
                ) in detected_services
            ]

            st.bar_chart(
                formatted_services,
                x="service",
                y="detections",
            )

            if interface_mode == "Advanced":
                st.dataframe(
                    formatted_services,
                    width="stretch",
                    hide_index=True,
                )

        else:
            st.info(
                "No services have been detected yet."
            )

    with ports_column:
        st.markdown("#### Most Detected Ports")

        if detected_ports:
            formatted_ports = [
                {
                    "port": port,
                    "service": service_name,
                    "detections": detection_count,
                }
                for (
                    port,
                    service_name,
                    detection_count,
                ) in detected_ports
            ]

            st.dataframe(
                formatted_ports,
                width="stretch",
                hide_index=True,
            )

        else:
            st.info(
                "No open ports have been detected yet."
            )

    if interface_mode == "Standard":
        st.caption(
            "Frequently detected services and ports help provide "
            "a quick view of the network exposure observed during "
            "previous scans. Their presence alone does not indicate "
            "a vulnerability."
        )

    # ---------------------------------------------------------
    # Recent scans
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Recent Scans")

    recent_scans = get_recent_scans()

    if recent_scans:
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
                    start_port,
                    end_port,
                    open_ports,
                    duration_seconds,
                ) in recent_scans
            ]

        else:
            formatted_scans = [
                {
                    "id": scan_id,
                    "date": scan_date,
                    "target": ip_address,
                    "port_range": (
                        f"{start_port} - {end_port}"
                    ),
                    "open_ports": open_ports,
                    "duration_seconds": duration_seconds,
                }
                for (
                    scan_id,
                    scan_date,
                    ip_address,
                    start_port,
                    end_port,
                    open_ports,
                    duration_seconds,
                ) in recent_scans
            ]

        st.dataframe(
            formatted_scans,
            width="stretch",
            hide_index=True,
        )

        if interface_mode == "Standard":
            with st.expander(
                "About scan history"
            ):
                st.write(
                    "Aegis stores completed port scans so that "
                    "previous activity can be reviewed later from "
                    "Scan History."
                )

    else:
        st.info(
            "No scans have been saved yet. Run a port scan "
            "to begin building assessment history."
        )
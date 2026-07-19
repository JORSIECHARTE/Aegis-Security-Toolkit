import streamlit as st

from database.db import (
    get_dashboard_metrics,
    get_detected_services,
    get_most_detected_ports,
    get_recent_scans,
)


def show_dashboard():
    st.header("Main Dashboard")

    metrics = get_dashboard_metrics()

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
        "Average Duration",
        f"{metrics['average_duration']} s",
    )

    metric_column_4.metric(
        "Latest Target",
        metrics["latest_target"],
    )

    st.divider()

    services_column, ports_column = st.columns(2)

    with services_column:
        st.subheader("Most Detected Services")

        detected_services = get_detected_services()

        if detected_services:
            formatted_services = [
                {
                    "service": service_name,
                    "detections": detection_count,
                }
                for service_name, detection_count in detected_services
            ]

            st.dataframe(
                formatted_services,
                width="stretch",
                hide_index=True,
            )

            st.bar_chart(
                formatted_services,
                x="service",
                y="detections",
            )

        else:
            st.info("No services have been detected yet.")

    with ports_column:
        st.subheader("Most Detected Ports")

        detected_ports = get_most_detected_ports()

        if detected_ports:
            formatted_ports = [
                {
                    "port": port,
                    "service": service_name,
                    "detections": detection_count,
                }
                for port, service_name, detection_count in detected_ports
            ]

            st.dataframe(
                formatted_ports,
                width="stretch",
                hide_index=True,
            )

        else:
            st.info("No open ports have been detected yet.")

    st.divider()

    st.subheader("Recent Scans")

    recent_scans = get_recent_scans()

    if recent_scans:
        formatted_scans = [
            {
                "id": scan_id,
                "date": scan_date,
                "target": ip_address,
                "port_range": f"{start_port} - {end_port}",
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

    else:
        st.info("No scans have been saved yet.")
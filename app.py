import streamlit as st

from config import (
    APP_DESCRIPTION,
    APP_NAME,
    DEFAULT_INTERFACE_MODE,
    INTERFACE_MODES,
    PAGE_LAYOUT,
    PAGE_TITLE,
)
from database.db import (
    get_setting,
    initialize_database,
)
from utils.logger import configure_logging
from views.dashboard_page import show_dashboard
from views.history_page import show_history_dashboard
from views.logs_page import show_log_analyzer
from views.network_page import show_network_discovery
from views.password_page import show_password_checker
from views.reports_page import show_reports
from views.scanner_page import show_port_scanner
from views.settings_page import show_settings
from views.targets_page import show_targets


logger = configure_logging()


st.set_page_config(
    page_title=PAGE_TITLE,
    layout=PAGE_LAYOUT,
)

initialize_database()

logger.info("Application started.")


# ---------------------------------------------------------
# Session state
# ---------------------------------------------------------

if "selected_page" not in st.session_state:
    st.session_state.selected_page = "Dashboard"

if "interface_mode" not in st.session_state:
    saved_interface_mode = get_setting(
        "interface_mode",
        DEFAULT_INTERFACE_MODE,
    )

    if saved_interface_mode not in INTERFACE_MODES:
        saved_interface_mode = DEFAULT_INTERFACE_MODE

    st.session_state.interface_mode = saved_interface_mode


def navigate_to(page: str) -> None:
    st.session_state.selected_page = page


# ---------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------

st.sidebar.title("Aegis")

st.sidebar.button(
    "Dashboard",
    use_container_width=True,
    on_click=navigate_to,
    args=("Dashboard",),
)

with st.sidebar.expander("Targets"):
    st.button(
        "Manage Targets",
        key="nav_manage_targets",
        use_container_width=True,
        on_click=navigate_to,
        args=("Targets",),
    )

with st.sidebar.expander("Discovery"):
    st.button(
        "Network Discovery",
        key="nav_network_discovery",
        use_container_width=True,
        on_click=navigate_to,
        args=("Network Discovery",),
    )

with st.sidebar.expander("Scanning"):
    st.button(
        "Port Scanner",
        key="nav_port_scanner",
        use_container_width=True,
        on_click=navigate_to,
        args=("Port Scanner",),
    )

with st.sidebar.expander("Security Analysis"):
    st.button(
        "Log Analyzer",
        key="nav_log_analyzer",
        use_container_width=True,
        on_click=navigate_to,
        args=("Log Analyzer",),
    )

    st.button(
        "Password Analyzer",
        key="nav_password_analyzer",
        use_container_width=True,
        on_click=navigate_to,
        args=("Password Analyzer",),
    )

with st.sidebar.expander("Results"):
    st.button(
        "Scan History",
        key="nav_scan_history",
        use_container_width=True,
        on_click=navigate_to,
        args=("Scan History",),
    )

    st.button(
        "Reports",
        key="nav_reports",
        use_container_width=True,
        on_click=navigate_to,
        args=("Reports",),
    )

with st.sidebar.expander("Settings"):
    st.button(
        "General",
        key="nav_settings_general",
        use_container_width=True,
        on_click=navigate_to,
        args=("Settings",),
    )


# ---------------------------------------------------------
# Application header
# ---------------------------------------------------------

st.title(APP_NAME)
st.markdown(APP_DESCRIPTION)


# ---------------------------------------------------------
# Page routing
# ---------------------------------------------------------

selected_page = st.session_state.selected_page

if selected_page == "Dashboard":
    show_dashboard()

elif selected_page == "Targets":
    show_targets()

elif selected_page == "Network Discovery":
    show_network_discovery()

elif selected_page == "Port Scanner":
    show_port_scanner()

elif selected_page == "Log Analyzer":
    show_log_analyzer()

elif selected_page == "Password Analyzer":
    show_password_checker()

elif selected_page == "Scan History":
    show_history_dashboard()

elif selected_page == "Reports":
    show_reports()

elif selected_page == "Settings":
    show_settings()
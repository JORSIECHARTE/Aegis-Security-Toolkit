import streamlit as st

from config import (
    APP_DESCRIPTION,
    APP_NAME,
    NAVIGATION_PAGES,
    PAGE_LAYOUT,
    PAGE_TITLE,
)
from database.db import initialize_database
from utils.logger import configure_logging
from views.dashboard_page import show_dashboard
from views.history_page import show_history_dashboard
from views.logs_page import show_log_analyzer
from views.network_page import show_network_discovery
from views.password_page import show_password_checker
from views.reports_page import show_reports
from views.scanner_page import show_port_scanner


logger = configure_logging()


st.set_page_config(
    page_title=PAGE_TITLE,
    layout=PAGE_LAYOUT,
)

initialize_database()

logger.info("Application started.")

st.title(APP_NAME)

st.markdown(APP_DESCRIPTION)

selected_page = st.sidebar.radio(
    "Select Module",
    NAVIGATION_PAGES,
)

if selected_page == "Home":
    show_dashboard()

elif selected_page == "Network Discovery":
    show_network_discovery()

elif selected_page == "Port Scanner":
    show_port_scanner()

elif selected_page == "Log Analyzer":
    show_log_analyzer()

elif selected_page == "Password Analyzer":
    show_password_checker()

elif selected_page == "Historical Dashboard":
    show_history_dashboard()

elif selected_page == "Reports":
    show_reports()
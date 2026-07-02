import streamlit as st

from database.db import inicializar_db

from views.dashboard_page import mostrar_dashboard
from views.network_page import mostrar_network_discovery
from views.scanner_page import mostrar_scanner
from views.logs_page import mostrar_log_analyzer
from views.password_page import mostrar_password_checker
from views.history_page import show_history_dashboard
from views.reports_page import mostrar_reportes


st.set_page_config(
    page_title="Aegis Security Toolkit",
    layout="wide"
)

inicializar_db()

st.title("Aegis Security Toolkit")

st.markdown("""
Welcome to Aegis.

An educational toolkit designed to learn defensive cybersecurity concepts.
""")

option = st.sidebar.radio(
    "Select Module",
    [
        "Home",
        "Network Discovery",
        "Port Scanner",
        "Log Analyzer",
        "Password Analyzer",
        "Historical Dashboard",
        "Reports"
    ]
)

if option == "Home":
    mostrar_dashboard()

elif option == "Network Discovery":
    mostrar_network_discovery()

elif option == "Port Scanner":
    mostrar_scanner()

elif option == "Log Analyzer":
    mostrar_log_analyzer()

elif option == "Password Analyzer":
    mostrar_password_checker()

elif option == "Historical Dashboard":
    show_history_dashboard()

elif option == "Reports":
    mostrar_reportes()
import streamlit as st

from database.db import inicializar_db

from views.dashboard_page import mostrar_dashboard
from views.scanner_page import mostrar_scanner
from views.password_page import mostrar_password_checker
from views.logs_page import mostrar_log_analyzer
from views.reports_page import mostrar_reportes


st.set_page_config(
    page_title="Aegis Security Toolkit",
    layout="wide"
)

inicializar_db()

st.title("Aegis Security Toolkit")

st.markdown("""
Bienvenido a Aegis.

Herramienta educativa orientada al aprendizaje de conceptos de ciberseguridad defensiva.
""")

opcion = st.sidebar.radio(
    "Seleccionar módulo",
    [
        "Inicio",
        "Escáner de Puertos",
        "Analizador de Contraseñas",
        "Analizador de Logs",
        "Reportes"
    ]
)

if opcion == "Inicio":
    mostrar_dashboard()

elif opcion == "Escáner de Puertos":
    mostrar_scanner()

elif opcion == "Analizador de Contraseñas":
    mostrar_password_checker()

elif opcion == "Analizador de Logs":
    mostrar_log_analyzer()

elif opcion == "Reportes":
    mostrar_reportes()
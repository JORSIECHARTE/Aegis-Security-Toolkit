import streamlit as st

from modules.log_analyzer import analizar_logs


def mostrar_log_analyzer():
    st.header("Analizador de Logs")

    st.info("Subí un archivo .log o .txt para detectar eventos básicos de seguridad.")

    archivo = st.file_uploader(
        "Seleccionar archivo de log",
        type=["log", "txt"]
    )

    if archivo is None:
        return

    contenido = archivo.read().decode("utf-8", errors="ignore")

    resultado = analizar_logs(contenido)

    st.subheader("Resumen")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Líneas analizadas", resultado["total_lineas"])
    col2.metric("Intentos fallidos", resultado["resumen"]["intentos_fallidos"])
    col3.metric("Logins exitosos", resultado["resumen"]["logins_exitosos"])
    col4.metric("IPs únicas", resultado["resumen"]["ips_unicas"])

    st.subheader("IPs detectadas")

    if resultado["ips_frecuentes"]:
        st.dataframe(resultado["ips_frecuentes"], width="stretch")
    else:
        st.info("No se detectaron IPs.")

    st.subheader("Intentos fallidos de login")

    if resultado["failed_logins"]:
        st.dataframe(resultado["failed_logins"], width="stretch")
    else:
        st.success("No se detectaron intentos fallidos.")

    st.subheader("Eventos sospechosos")

    if resultado["eventos_sospechosos"]:
        st.dataframe(resultado["eventos_sospechosos"], width="stretch")
    else:
        st.success("No se detectaron eventos sospechosos.")
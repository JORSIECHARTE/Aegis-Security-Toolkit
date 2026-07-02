import streamlit as st

from modules.log_analyzer import analizar_logs


def mostrar_log_analyzer():
    st.header("Analizador de Logs")

    st.info("Subí un archivo .log o .txt para detectar eventos básicos y avanzados de seguridad.")

    archivo = st.file_uploader(
        "Seleccionar archivo de log",
        type=["log", "txt"]
    )

    if archivo is None:
        return

    contenido = archivo.read().decode("utf-8", errors="ignore")

    resultado = analizar_logs(contenido)

    st.subheader("Resumen de Seguridad")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Líneas analizadas", resultado["total_lineas"])
    col2.metric("Intentos fallidos", resultado["resumen"]["intentos_fallidos"])
    col3.metric("Alertas", resultado["resumen"]["alertas"])
    col4.metric("Risk Score", f"{resultado['resumen']['risk_score']}/100")

    nivel = resultado["resumen"]["nivel_riesgo"]

    if nivel == "Crítico":
        st.error(f"Nivel de riesgo: {nivel}")
    elif nivel == "Alto":
        st.warning(f"Nivel de riesgo: {nivel}")
    elif nivel == "Medio":
        st.info(f"Nivel de riesgo: {nivel}")
    else:
        st.success(f"Nivel de riesgo: {nivel}")

    st.divider()

    st.subheader("Alertas Detectadas")

    if resultado["alertas"]:
        st.dataframe(resultado["alertas"], width="stretch")
    else:
        st.success("No se detectaron alertas avanzadas.")

    st.divider()

    col_ips, col_eventos = st.columns(2)

    with col_ips:
        st.subheader("IPs detectadas")

        if resultado["ips_frecuentes"]:
            st.dataframe(resultado["ips_frecuentes"], width="stretch")
        else:
            st.info("No se detectaron IPs.")

    with col_eventos:
        st.subheader("Eventos sospechosos")

        if resultado["eventos_sospechosos"]:
            st.dataframe(resultado["eventos_sospechosos"], width="stretch")
        else:
            st.success("No se detectaron eventos sospechosos.")

    st.divider()

    st.subheader("Intentos fallidos de login")

    if resultado["failed_logins"]:
        st.dataframe(resultado["failed_logins"], width="stretch")
    else:
        st.success("No se detectaron intentos fallidos.")

    st.subheader("Logins exitosos")

    if resultado["successful_logins"]:
        st.dataframe(resultado["successful_logins"], width="stretch")
    else:
        st.info("No se detectaron logins exitosos.")
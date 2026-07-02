import streamlit as st

from services.risk_summary import (
    calculate_overall_risk,
    generate_executive_summary
)

from services.vulnerability_rules import analyze_service_vulnerabilities

from modules.scanner import (
    escanear_rango,
    generar_reporte_txt,
    generar_reporte_csv
)

from database.db import guardar_scan
from modules.report_generator import generar_html_scan


def mostrar_scanner():
    st.header("Escáner de Puertos")

    st.warning(
        "Usar solo sobre equipos propios, localhost, red local autorizada o laboratorio personal."
    )

    ip = st.text_input("IP o hostname objetivo", value="127.0.0.1")

    col1, col2, col3 = st.columns(3)

    with col1:
        puerto_inicio = st.number_input(
            "Puerto inicial",
            min_value=1,
            max_value=65535,
            value=1
        )

    with col2:
        puerto_fin = st.number_input(
            "Puerto final",
            min_value=1,
            max_value=65535,
            value=1024
        )

    with col3:
        timeout = st.selectbox(
            "Timeout por puerto",
            [0.3, 0.5, 1.0, 2.0],
            index=0
        )

    workers = st.slider(
        "Cantidad de hilos simultáneos",
        min_value=10,
        max_value=200,
        value=100,
        step=10
    )

    banner = st.checkbox("Intentar obtener banner del servicio")

    if st.button("Iniciar escaneo"):

        if puerto_inicio > puerto_fin:
            st.error("El puerto inicial no puede ser mayor que el puerto final.")
            return

        with st.spinner("Escaneando puertos..."):
            resultado_scan = escanear_rango(
                ip=ip,
                puerto_inicio=int(puerto_inicio),
                puerto_fin=int(puerto_fin),
                timeout=float(timeout),
                banner=banner,
                workers=int(workers)
            )

        scan_id = guardar_scan(resultado_scan)
        st.success(f"Escaneo guardado en historial con ID {scan_id}.")

        st.subheader("Resumen del escaneo")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Objetivo", resultado_scan["ip"])
        col2.metric("Puertos analizados", resultado_scan["puertos_analizados"])
        col3.metric("Puertos abiertos", resultado_scan["puertos_abiertos"])
        col4.metric("Duración", f"{resultado_scan['duracion_segundos']} s")

        risk_summary = calculate_overall_risk(resultado_scan["resultados"])
        executive_summary = generate_executive_summary(resultado_scan)
        vulnerability_findings = analyze_service_vulnerabilities(
            resultado_scan["resultados"]
        )

        st.divider()
        st.subheader("Risk Dashboard")

        col_risk_1, col_risk_2 = st.columns(2)

        col_risk_1.metric("Overall Risk Score", risk_summary["overall_score"])
        col_risk_2.metric("Assessment", risk_summary["assessment"])

        if risk_summary["assessment"] in ["Critical", "High"]:
            st.error(executive_summary)
        elif risk_summary["assessment"] == "Medium":
            st.warning(executive_summary)
        else:
            st.success(executive_summary)

        if risk_summary["high_risk_services"]:
            st.subheader("High Risk Services")
            st.dataframe(risk_summary["high_risk_services"], width="stretch")

        st.subheader("Vulnerability Findings")

        if vulnerability_findings:
            st.dataframe(vulnerability_findings, width="stretch")
        else:
            st.success("No vulnerability findings detected based on the current rules.")

        if risk_summary["recommendations"]:
            st.subheader("Recommendations")
            for recommendation in risk_summary["recommendations"]:
                st.write(f"- {recommendation}")

        st.divider()

        st.write(f"Fecha: {resultado_scan['fecha']}")
        st.write(
            f"Rango analizado: {resultado_scan['puerto_inicio']} - {resultado_scan['puerto_fin']}"
        )

        if resultado_scan["resultados"]:
            st.subheader("Puertos abiertos detectados")

            st.dataframe(
                resultado_scan["resultados"],
                width="stretch"
            )

            reporte_txt = generar_reporte_txt(resultado_scan)
            reporte_csv = generar_reporte_csv(resultado_scan)
            reporte_html = generar_html_scan(resultado_scan)

            col_txt, col_csv, col_html = st.columns(3)

            with col_txt:
                st.download_button(
                    label="Descargar reporte TXT",
                    data=reporte_txt,
                    file_name="reporte_escaneo_aegis.txt",
                    mime="text/plain"
                )

            with col_csv:
                st.download_button(
                    label="Descargar reporte CSV",
                    data=reporte_csv,
                    file_name="reporte_escaneo_aegis.csv",
                    mime="text/csv"
                )

            with col_html:
                st.download_button(
                    label="Descargar reporte HTML",
                    data=reporte_html,
                    file_name="reporte_escaneo_aegis.html",
                    mime="text/html"
                )

        else:
            st.info("No se detectaron puertos abiertos en el rango indicado.")
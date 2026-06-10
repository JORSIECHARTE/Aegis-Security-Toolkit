import streamlit as st

from database.db import (
    obtener_metricas_dashboard,
    obtener_servicios_detectados,
    obtener_ultimos_scans,
    obtener_puertos_mas_detectados
)


def mostrar_dashboard():
    st.header("Panel Principal")

    metricas = obtener_metricas_dashboard()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Escaneos realizados", metricas["total_scans"])
    col2.metric("Puertos abiertos detectados", metricas["total_puertos_abiertos"])
    col3.metric("Promedio duración", f"{metricas['promedio_duracion']} s")
    col4.metric("Último objetivo", metricas["ultimo_objetivo"])

    st.divider()

    col_servicios, col_puertos = st.columns(2)

    with col_servicios:
        st.subheader("Servicios más detectados")

        servicios = obtener_servicios_detectados()

        if servicios:
            servicios_formateados = [
                {"servicio": servicio[0], "cantidad": servicio[1]}
                for servicio in servicios
            ]

            st.dataframe(servicios_formateados, width="stretch")
            st.bar_chart(servicios_formateados, x="servicio", y="cantidad")
        else:
            st.info("Todavía no hay servicios detectados.")

    with col_puertos:
        st.subheader("Puertos más detectados")

        puertos = obtener_puertos_mas_detectados()

        if puertos:
            puertos_formateados = [
                {
                    "puerto": puerto[0],
                    "servicio": puerto[1],
                    "cantidad": puerto[2]
                }
                for puerto in puertos
            ]

            st.dataframe(puertos_formateados, width="stretch")
        else:
            st.info("Todavía no hay puertos detectados.")

    st.divider()

    st.subheader("Últimos escaneos")

    ultimos = obtener_ultimos_scans()

    if ultimos:
        ultimos_formateados = [
            {
                "id": scan[0],
                "fecha": scan[1],
                "ip": scan[2],
                "rango": f"{scan[3]} - {scan[4]}",
                "puertos_abiertos": scan[5],
                "duracion_segundos": scan[6]
            }
            for scan in ultimos
        ]

        st.dataframe(ultimos_formateados, width="stretch")
    else:
        st.info("Todavía no hay escaneos guardados.")
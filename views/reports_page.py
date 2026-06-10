import streamlit as st

from database.db import (
    obtener_scans,
    obtener_resultados_scan
)


def mostrar_reportes():
    st.header("Historial de Escaneos")

    scans = obtener_scans()

    if not scans:
        st.info("Todavía no hay escaneos guardados.")
        return

    scans_formateados = []

    for scan in scans:
        scans_formateados.append({
            "id": scan[0],
            "fecha": scan[1],
            "ip": scan[2],
            "puerto_inicio": scan[3],
            "puerto_fin": scan[4],
            "puertos_analizados": scan[5],
            "puertos_abiertos": scan[6],
            "duracion_segundos": scan[7]
        })

    st.dataframe(scans_formateados, width="stretch")

    opciones = {
        f"ID {scan[0]} | {scan[2]} | {scan[1]}": scan[0]
        for scan in scans
    }

    seleccion = st.selectbox(
        "Seleccionar escaneo para ver detalle",
        list(opciones.keys())
    )

    scan_id = opciones[seleccion]

    resultados = obtener_resultados_scan(scan_id)

    if not resultados:
        st.info("Ese escaneo no tiene puertos abiertos registrados.")
        return

    detalle = []

    for r in resultados:
        detalle.append({
            "puerto": r[0],
            "estado": r[1],
            "servicio": r[2],
            "tiempo_ms": r[3],
            "banner": r[4]
        })

    st.subheader(f"Detalle del escaneo ID {scan_id}")
    st.dataframe(detalle, width="stretch")
import streamlit as st

from modules.password_checker import analizar_password


def mostrar_password_checker():
    st.header("Analizador de Contraseñas")

    st.info("El análisis se realiza localmente. La contraseña ingresada no se guarda ni se registra.")

    password = st.text_input(
        "Ingrese una contraseña",
        type="password"
    )

    if st.button("Analizar"):

        if not password:
            st.warning("Ingrese una contraseña.")
            return

        resultado = analizar_password(password)

        st.subheader(f"Resultado: {resultado['nivel']}")

        col1, col2, col3 = st.columns(3)

        col1.metric("Puntuación", resultado["puntuacion"])
        col2.metric("Entropía estimada", f"{resultado['entropia']} bits")
        col3.metric("Fuerza bruta", resultado["tiempo_estimado"])

        if resultado["nivel"] == "Fuerte":
            st.success("La contraseña cumple buenas prácticas básicas.")
        elif resultado["nivel"] == "Media":
            st.warning("La contraseña podría mejorarse.")
        else:
            st.error("La contraseña es débil.")

        if resultado["observaciones"]:
            st.subheader("Observaciones")
            for obs in resultado["observaciones"]:
                st.write(f"- {obs}")

        if resultado["recomendaciones"]:
            st.subheader("Recomendaciones")
            for rec in resultado["recomendaciones"]:
                st.write(f"- {rec}")
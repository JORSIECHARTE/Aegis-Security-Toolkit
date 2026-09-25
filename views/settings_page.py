import streamlit as st

from config import (
    DEFAULT_INTERFACE_MODE,
    INTERFACE_MODES,
)
from database.db import save_setting


def show_settings():
    st.header("Settings")

    st.subheader("General")

    st.write(
        "Configure how Aegis presents tools and "
        "technical information."
    )

    current_mode = st.session_state.get(
        "interface_mode",
        DEFAULT_INTERFACE_MODE,
    )

    interface_mode = st.radio(
        "Interface Mode",
        INTERFACE_MODES,
        index=INTERFACE_MODES.index(
            current_mode
        ),
        horizontal=True,
    )

    if interface_mode != current_mode:
        st.session_state.interface_mode = interface_mode

        save_setting(
            "interface_mode",
            interface_mode,
        )

    if interface_mode == "Standard":
        st.info(
            "Standard Mode uses recommended defaults and "
            "provides additional explanations while keeping "
            "the same underlying security analysis."
        )

    else:
        st.info(
            "Advanced Mode exposes additional technical "
            "controls and detailed analysis information."
        )
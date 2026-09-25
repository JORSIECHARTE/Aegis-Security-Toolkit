import sqlite3

import streamlit as st

from config import (
    DEFAULT_TARGET_STATUS,
    TARGET_STATUSES,
)
from database.db import (
    create_target,
    delete_target,
    get_targets,
    target_host_exists,
    update_target,
)


def show_targets():
    st.header("Targets")

    interface_mode = st.session_state.get(
        "interface_mode",
        "Standard",
    )

    if interface_mode == "Standard":
        st.caption(
            "Create and manage the systems that Aegis "
            "will assess."
        )
    else:
        st.caption(
            "Manage persistent assessment targets and "
            "their operational status."
        )

    # ---------------------------------------------------------
    # Create target
    # ---------------------------------------------------------

    st.subheader("Add Target")

    with st.form(
        "create_target_form",
        clear_on_submit=True,
    ):
        name = st.text_input(
            "Name",
            placeholder="Example: Web Server",
        )

        host = st.text_input(
            "Host or IP Address",
            placeholder="Example: 192.168.1.10",
        )

        description = st.text_area(
            "Description",
            placeholder=(
                "Optional notes about this target."
            ),
        )

        status = st.selectbox(
            "Status",
            TARGET_STATUSES,
            index=TARGET_STATUSES.index(
                DEFAULT_TARGET_STATUS
            ),
        )

        create_submitted = st.form_submit_button(
            "Add Target",
            use_container_width=True,
        )

    if create_submitted:
        clean_name = name.strip()
        clean_host = host.strip()
        clean_description = description.strip()

        if not clean_name:
            st.error(
                "Target name is required."
            )

        elif not clean_host:
            st.error(
                "Host or IP address is required."
            )

        elif target_host_exists(clean_host):
            st.error(
                "A target with this host already exists."
            )

        else:
            try:
                create_target(
                    clean_name,
                    clean_host,
                    clean_description,
                    status,
                )

                st.success(
                    "Target created successfully."
                )

                st.rerun()

            except sqlite3.IntegrityError:
                st.error(
                    "A target with this host already exists."
                )

    # ---------------------------------------------------------
    # Existing targets
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Managed Targets")

    targets = get_targets()

    if not targets:
        st.info(
            "No targets have been created yet."
        )
        return

    active_targets = sum(
        1
        for target in targets
        if target[4] == "Active"
    )

    inactive_targets = (
        len(targets) - active_targets
    )

    (
        total_column,
        active_column,
        inactive_column,
    ) = st.columns(3)

    total_column.metric(
        "Total Targets",
        len(targets),
    )

    active_column.metric(
        "Active",
        active_targets,
    )

    inactive_column.metric(
        "Inactive",
        inactive_targets,
    )

    formatted_targets = [
        {
            "name": name,
            "host": host,
            "status": status,
            "created": created_at,
        }
        for (
            target_id,
            name,
            host,
            description,
            status,
            created_at,
        ) in targets
    ]

    st.dataframe(
        formatted_targets,
        width="stretch",
        hide_index=True,
    )

    # ---------------------------------------------------------
    # Target management
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Manage Target")

    target_options = {
        f"{name} | {host}": target_id
        for (
            target_id,
            name,
            host,
            description,
            status,
            created_at,
        ) in targets
    }

    selected_target_label = st.selectbox(
        "Select target",
        list(target_options.keys()),
    )

    selected_target_id = target_options[
        selected_target_label
    ]

    selected_target = next(
        target
        for target in targets
        if target[0] == selected_target_id
    )

    (
        target_id,
        target_name,
        target_host,
        target_description,
        target_status,
        target_created_at,
    ) = selected_target

    with st.form(
        f"edit_target_form_{target_id}"
    ):
        edited_name = st.text_input(
            "Name",
            value=target_name,
        )

        edited_host = st.text_input(
            "Host or IP Address",
            value=target_host,
        )

        edited_description = st.text_area(
            "Description",
            value=target_description or "",
        )

        edited_status = st.selectbox(
            "Status",
            TARGET_STATUSES,
            index=TARGET_STATUSES.index(
                target_status
            ),
        )

        update_submitted = st.form_submit_button(
            "Save Changes",
            use_container_width=True,
        )

    if update_submitted:
        clean_name = edited_name.strip()
        clean_host = edited_host.strip()
        clean_description = (
            edited_description.strip()
        )

        if not clean_name:
            st.error(
                "Target name is required."
            )

        elif not clean_host:
            st.error(
                "Host or IP address is required."
            )

        elif target_host_exists(
            clean_host,
            exclude_target_id=target_id,
        ):
            st.error(
                "Another target already uses this host."
            )

        else:
            try:
                updated = update_target(
                    target_id,
                    clean_name,
                    clean_host,
                    clean_description,
                    edited_status,
                )

                if updated:
                    st.success(
                        "Target updated successfully."
                    )

                    st.rerun()

                else:
                    st.error(
                        "Target could not be updated."
                    )

            except sqlite3.IntegrityError:
                st.error(
                    "Another target already uses this host."
                )

    # ---------------------------------------------------------
    # Advanced information
    # ---------------------------------------------------------

    if interface_mode == "Advanced":
        with st.expander(
            "Target Metadata"
        ):
            st.write(
                f"**Target ID:** {target_id}"
            )

            st.write(
                f"**Created:** {target_created_at}"
            )

            st.write(
                f"**Status:** {target_status}"
            )

    # ---------------------------------------------------------
    # Delete target
    # ---------------------------------------------------------

    st.divider()

    st.subheader("Delete Target")

    st.warning(
        "Deleting a target removes it from the managed "
        "target list."
    )

    confirm_delete = st.checkbox(
        "I understand that this target will be deleted.",
        key=f"confirm_delete_target_{target_id}",
    )

    if st.button(
        "Delete Target",
        disabled=not confirm_delete,
        use_container_width=True,
        key=f"delete_target_{target_id}",
    ):
        deleted = delete_target(
            target_id
        )

        if deleted:
            st.success(
                "Target deleted successfully."
            )

            st.rerun()

        else:
            st.error(
                "Target could not be deleted."
            )
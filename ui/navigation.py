from typing import Iterable, Optional, Tuple

import streamlit as st


def sync_navigation_state(valid_pages: Iterable[str], default_page: str = "Dashboard") -> Tuple[str, Optional[int]]:
    pages = list(valid_pages)
    current = st.session_state.get("current_page", default_page)
    if current not in pages:
        current = default_page

    requested = st.session_state.pop("nav_request", None)
    manual_select = None
    if requested in pages:
        current = requested
        manual_select = pages.index(requested)

    st.session_state.current_page = current
    return current, manual_select


def go_to(page: str, **session_updates) -> None:
    for key, value in session_updates.items():
        st.session_state[key] = value
    st.session_state.current_page = page
    st.session_state.nav_request = page
    st.rerun()

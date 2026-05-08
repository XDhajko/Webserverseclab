import streamlit as st
import os
import sys
from streamlit_option_menu import option_menu

# Ensure core modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui import dashboard, targets, audit, findings, compare, hardening_plan, harden, settings
from ui.navigation import sync_navigation_state

st.set_page_config(page_title="WebServerSecLab", layout="wide", initial_sidebar_state="collapsed")

# Custom CSS for a professional scanner UI
st.markdown("""
<style>
    /* Global Container Borders */
    .stContainer {
        border-radius: 8px;
    }
    
    /* Headers & Text */
    h1, h2, h3 {
        font-weight: 600;
    }
    
    /* Hide top padding and default sidebar elements */
    .block-container {
        padding-top: 1rem;
        padding-bottom: 0rem;
    }
    header {visibility: hidden;}
    
    /* Logo alignment */
    .logo-container {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-top: 10px; /* Align vertically with the nav tabs */
    }
    .logo-title {
        font-size: 20px;
        font-weight: 700;
        color: #fff;
        letter-spacing: 0.5px;
    }
    .logo-subtitle {
        font-weight: 300;
        color: #999;
        font-size: 14px;
        margin-left: 4px;
    }
    
    /* Horizontal rule fix for full-width navbar line */
    hr.nav-divider {
        margin-top: 0px; 
        margin-bottom: 20px; 
        border: none;
        border-top: 1px solid #444;
        width: 100vw;
        position: relative;
        left: 50%;
        right: 50%;
        margin-left: -50vw;
        margin-right: -50vw;
    }
</style>
""", unsafe_allow_html=True)

# Shortened names for better fitting
pages = {
    "Dashboard": dashboard.render,
    "Targets": targets.render,
    "Scan": audit.render,
    "Findings": findings.render,
    "Catalog": hardening_plan.render,
    "Harden": harden.render,
    "Compare": compare.render,
    "Settings": settings.render,
}

current_page, manual_select = sync_navigation_state(pages.keys(), default_page="Dashboard")

# Layout: Logo and Navbar side-by-side
logo_col, nav_col = st.columns([1.5, 8.5])

with logo_col:
    # Render SVG Logo & Name (Working in 'Web' and 'Server' context correctly without extending it out)
    st.markdown("""
    <div class="logo-container">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff4b4b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        <div class="logo-title">WebSec<span class="logo-subtitle">Auditor</span></div>
    </div>
    """, unsafe_allow_html=True)

with nav_col:
    # Horizontal custom navigation using Bootstrap icons
    selection = option_menu(
        menu_title=None,
        options=list(pages.keys()),
        icons=["bar-chart", "hdd-network", "play-circle", "bug", "shield-check", "shield-lock", "columns-gap", "gear"],
        default_index=list(pages.keys()).index(current_page),
        manual_select=manual_select,
        key="nav_menu",
        orientation="horizontal",
        styles={
            "container": {
                "padding": "0!important",
                "background-color": "transparent",
                "border-radius": "0",
                "margin-top": "0px",
                "margin-bottom": "0px",
                "display": "flex",
                "justify-content": "flex-end"
            },
            "icon": {
                "color": "inherit", 
                "font-size": "13px"
            }, 
            "nav-link": {
                "font-size": "12px", 
                "text-align": "center", 
                "margin": "0px", 
                "--hover-color": "transparent",
                "border-radius": "0",
                "padding": "10px 5px",
                "color": "#ddd",
                "text-transform": "uppercase",
                "letter-spacing": "0.5px"
            },
            "nav-link-selected": {
                "background-color": "transparent", 
                "color": "#ff4b4b", 
                "border-bottom": "2px solid #ff4b4b",
                "border-radius": "0",
                "font-weight": "600"
            }
        }
)

active_page = selection or current_page
st.session_state.current_page = active_page

# Full-width line connecting the bottom of the logo row and the navbar
st.markdown("<hr class='nav-divider'>", unsafe_allow_html=True)

# Render active page
pages[active_page]()


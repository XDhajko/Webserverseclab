import json
import os
import streamlit as st

SETTINGS_FILE = "config/app_settings.json"


def _load_settings():
	if not os.path.exists(SETTINGS_FILE):
		return {"scan_profile": "standards_mode"}
	try:
		with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
			data = json.load(f)
		if not isinstance(data, dict):
			return {"scan_profile": "standards_mode"}
		return data
	except Exception:
		return {"scan_profile": "standards_mode"}


def _save_settings(settings):
	os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
	with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
		json.dump(settings, f, indent=2)


def render():
	st.title("Settings")
	st.markdown("Configure runtime behavior for standards mapping and scan speed.")

	current = _load_settings()
	profile = current.get("scan_profile", "standards_mode")
	options = ["standards_mode", "lab_mode"]
	if profile not in options:
		profile = "standards_mode"

	chosen = st.radio(
		"Scan profile",
		options=options,
		index=options.index(profile),
		help="standards_mode: full standards mapping and CVE cache usage. lab_mode: faster, simplified behavior.",
	)

	if st.button("Save Settings", type="primary"):
		_save_settings({"scan_profile": chosen})
		st.success("Settings saved.")
#!/bin/bash
PYTHONPATH="$(dirname "$0")" streamlit run "$(dirname "$0")/app.py" "$@"

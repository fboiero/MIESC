#!/usr/bin/env python3
"""
MIESC v5.1.1 - Streamlit Cloud Entry Point

Streamlit Cloud automatically detects and runs streamlit_app.py from the repo root.
This file bootstraps the webapp/app.py dashboard.

Author: Fernando Boiero
License: AGPL-3.0
"""

import sys
from pathlib import Path

# Ensure project root is in path for src/ imports
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import and run the main dashboard app
from webapp.app import *  # noqa: F401,F403

"""Vercel entry point when the project is deployed from the repository root.

Serves the team's Flask dashboard from team-project/ (see team-project/api/index.py).
"""

import os
import runpy

_entry = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "team-project", "api", "index.py")
app = runpy.run_path(_entry)["app"]

#!/usr/bin/env python3
"""Generate dashboard_snapshot.json from Excel for local API dev."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from scripts.seed_dashboard import main

if __name__ == "__main__":
    main()

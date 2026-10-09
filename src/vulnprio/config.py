"""Paths and source URLs, in one place.

Paths are relative to the directory the pipeline runs from (the repository
root) and can be moved with environment variables, e.g. in CI.
"""

import os
from datetime import date
from pathlib import Path

DATA_DIR = Path(os.environ.get("VULNPRIO_DATA_DIR", "data"))
LANDING_DIR = DATA_DIR / "landing"  # downloaded files, exactly as served
WAREHOUSE_PATH = Path(os.environ.get("VULNPRIO_WAREHOUSE", DATA_DIR / "warehouse.duckdb"))

USER_AGENT = "vuln-priority-pipeline/0.1 (+https://github.com/JoaoPedro0305/vuln-priority-pipeline)"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# One gzipped CSV per day. "current" redirects to the latest published day.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
EPSS_FIRST_DAY = date(2021, 4, 14)

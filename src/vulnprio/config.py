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
DBT_DIR = Path(os.environ.get("VULNPRIO_DBT_DIR", "dbt"))  # the dbt project (models, tests)
ASSETS_PATH = Path(os.environ.get("VULNPRIO_ASSETS", "assets.toml"))  # systems whose dependencies are scanned

USER_AGENT = "vuln-priority-pipeline/0.1 (+https://github.com/JoaoPedro0305/vuln-priority-pipeline)"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# One gzipped CSV per day. "current" redirects to the latest published day.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
EPSS_FIRST_DAY = date(2021, 4, 14)

# NVD yearly feeds (full rebuild) and CVE API (incremental updates).
# The 2002 feed also holds every older CVE (CVE-1999 to CVE-2001).
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_META_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"
NVD_FIRST_FEED_YEAR = 2002
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def nvd_api_key() -> str | None:
    """Optional free key (https://nvd.nist.gov/developers/request-an-api-key).

    Raises the API limit from 5 to 50 requests per 30 seconds. Read from the
    environment only, never from a file in the repository.
    """
    return os.environ.get("NVD_API_KEY") or None

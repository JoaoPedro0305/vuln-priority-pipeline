"""Download each source and load it into the raw layer (the E and L of ELT).

Each source is independent: one failing does not stop the others, and a
failed load leaves the warehouse exactly as it was before.
"""

from datetime import date
from pathlib import Path

import duckdb
import requests

from vulnprio import config
from vulnprio.download import download
from vulnprio.sources import epss, kev
from vulnprio.warehouse import utc_now


def ingest_kev(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    landing_dir: Path | None = None,
) -> int:
    """Load the current KEV catalog. Returns the number of CVEs in it."""
    landing_dir = landing_dir or config.LANDING_DIR
    loaded_at = utc_now()
    downloaded = download(session, config.KEV_URL, landing_dir / "kev" / "known_exploited_vulnerabilities.json")
    catalog = kev.parse(downloaded.path.read_bytes())
    return kev.load(con, catalog, downloaded, loaded_at)


def ingest_epss(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    day: date | None = None,
    landing_dir: Path | None = None,
) -> date:
    """Load the EPSS scores of `day` (default: latest published). Returns the score date."""
    if day and day < config.EPSS_FIRST_DAY:
        raise epss.EpssError(f"EPSS starts on {config.EPSS_FIRST_DAY}, there is no file for {day}")

    landing_dir = landing_dir or config.LANDING_DIR
    name = day.isoformat() if day else "current"
    downloaded = download(
        session,
        config.EPSS_URL.format(day=name),
        landing_dir / "epss" / f"epss_scores-{name}.csv.gz",
        not_found=(403, 404),  # the bucket answers 403 for days not published
    )
    return epss.load(con, downloaded, utc_now(), expected_date=day)

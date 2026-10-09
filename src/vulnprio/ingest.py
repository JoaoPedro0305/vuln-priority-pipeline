"""Download each source and load it into the raw layer (the E and L of ELT).

Each source is independent: one failing does not stop the others, and a
failed load leaves the warehouse exactly as it was before.
"""

import logging
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import date, datetime, timedelta
from pathlib import Path

import duckdb
import requests

from vulnprio import config
from vulnprio.download import DownloadError, NotPublishedError, download, make_session
from vulnprio.sources import deps, epss, kev, nvd
from vulnprio.warehouse import utc_now

log = logging.getLogger(__name__)

# Past this gap since the last NVD sync, re-reading the yearly feeds (~225 MB,
# no rate limit) is quicker than paging through months of API changes.
NVD_FULL_REBUILD_AFTER = timedelta(days=90)
# Each incremental run re-asks for the last day already covered, in case NVD
# records a change with a slightly earlier timestamp. Merging it again is harmless.
NVD_API_OVERLAP = timedelta(days=1)


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


def ingest_nvd(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    *,
    full: bool = False,
    years: list[int] | None = None,
    since: date | None = None,
    landing_dir: Path | None = None,
    now: datetime | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Bring raw.nvd up to date and return the mode used.

    - "feeds": first run, `full`, or the last sync is older than 90 days.
    - "api": everything modified since the last sync (minus a day of overlap).
    - "years": only the given yearly feeds; does not count as a complete sync.
    - "since": API changes since a given day, on request.
    """
    landing_dir = landing_dir or config.LANDING_DIR
    now = now or utc_now()
    all_years = list(range(config.NVD_FIRST_FEED_YEAR, now.year + 1))

    if years:
        unknown = sorted(set(years) - set(all_years))
        if unknown:
            raise nvd.NvdError(f"no NVD feed for {unknown}; feeds go from {all_years[0]} to {all_years[-1]}")
        nvd.sync_feeds(con, session, sorted(set(years)), landing_dir, record_sync=False)
        return "years"

    api_session = make_session(extra_retry_statuses=(403,))  # NVD answers 403 when rate limiting
    if since:
        start = datetime(since.year, since.month, since.day)
        nvd.sync_api(con, api_session, start, now, landing_dir, api_key=config.nvd_api_key(), sleep=sleep)
        return "since"

    last = nvd.watermark(con)
    if full or last is None or now - last > NVD_FULL_REBUILD_AFTER:
        reason = "requested" if full else "first sync" if last is None else f"last sync was {last:%Y-%m-%d}"
        log.info("NVD: full rebuild from the yearly feeds (%s)", reason)
        nvd.sync_feeds(con, session, all_years, landing_dir, record_sync=True)
        return "feeds"

    nvd.sync_api(con, api_session, last - NVD_API_OVERLAP, now, landing_dir, api_key=config.nvd_api_key(), sleep=sleep)
    return "api"


def month_starts(since: date, until: date) -> list[date]:
    """First day of every month from `since`'s month to `until`, inclusive."""
    day = date(since.year, since.month, 1)
    days = []
    while day <= until:
        days.append(day)
        day = date(day.year + day.month // 12, day.month % 12 + 1, 1)
    return days


def ingest_epss_history(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    since: date,
    until: date | None = None,
    landing_dir: Path | None = None,
    *,
    tries_per_month: int = 3,
) -> list[date]:
    """Load one EPSS day per month (the 1st, or the next published day).

    Months that already have a loaded day are skipped, so the backfill can be
    stopped and resumed. Returns the days loaded in this run.
    """
    until = until or utc_now().date()
    since = max(since, config.EPSS_FIRST_DAY)
    loaded_months = {(d.year, d.month) for (d,) in con.execute("SELECT DISTINCT score_date FROM raw.epss").fetchall()}

    loaded = []
    for first in month_starts(since, until):
        if (first.year, first.month) in loaded_months:
            continue
        for offset in range(tries_per_month):
            day = first + timedelta(days=offset)
            if day > until:
                break
            try:
                loaded.append(ingest_epss(con, session, day, landing_dir))
                break
            except DownloadError as err:
                if not isinstance(err, NotPublishedError):
                    raise
                log.warning("EPSS %s not published, trying the next day", day)
        else:
            log.warning("EPSS: no file in the first %d days of %s", tries_per_month, first.strftime("%Y-%m"))
    return loaded


def ingest_deps(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    assets_path: Path | None = None,
    landing_dir: Path | None = None,
) -> int:
    """Scan every asset in assets.toml. Returns the number of findings.

    One asset failing does not stop the others; the error is raised at the end.
    Assets removed from the file are removed from the warehouse.
    """
    assets = deps.load_assets(assets_path or config.ASSETS_PATH)
    landing_dir = landing_dir or config.LANDING_DIR
    loaded_at = utc_now()
    findings = 0
    failed = []

    for asset in assets:
        work = landing_dir / "deps" / re.sub(r"[^a-z0-9]+", "-", asset.name.lower()).strip("-")
        shutil.rmtree(work, ignore_errors=True)
        try:
            files = deps.fetch_requirements(session, asset, work / "requirements")
            packages = deps.resolve(asset, files, work / "pip-report.json")
            matches = deps.query_osv(session, packages)
            wanted = {osv_id: modified for vulns in matches.values() for osv_id, modified in vulns.items()}
            fetched = deps.fetch_vulnerabilities(con, session, wanted, loaded_at)
            count = deps.load_asset(con, asset, packages, matches, loaded_at)
        except (deps.DepsError, requests.RequestException, subprocess.TimeoutExpired) as err:
            log.error("dependencies of %s: %s", asset.name, err)
            failed.append(asset.name)
            continue
        findings += count
        log.info(
            "dependencies of %s: %d packages (%d direct), %d vulnerabilities (%d advisories fetched)",
            asset.name,
            len(packages),
            sum(p.direct for p in packages),
            count,
            fetched,
        )

    names = [a.name for a in assets]
    for table in ("raw.assets", "raw.asset_packages", "raw.asset_vulns"):
        con.execute(f"DELETE FROM {table} WHERE NOT list_contains(?, asset)", [names])  # noqa: S608

    if failed:
        raise deps.DepsError(f"could not scan: {', '.join(failed)}")
    return findings

"""NVD: severity (CVSS), weakness (CWE) and affected products (CPE) of every CVE.

Two ways in, one loader:

- Yearly feeds (nvdcve-2.0-YYYY.json.gz, ~225 MB compressed in total) rebuild
  everything without touching the API rate limit. Each feed has a .meta file
  with the SHA-256 of its uncompressed content, checked before loading.
- The CVE API returns what was modified in a time window (at most 120 days,
  2,000 CVEs per page). Daily runs use it: a few requests instead of 225 MB.

Both deliver the same JSON shape ({"vulnerabilities": [{"cve": {...}}]}), so
both are read by the same DuckDB query and merged the same way: a stored CVE is
only replaced by a version with an equal or later lastModified, so loads can
arrive in any order and be repeated safely.
"""

import gzip
import hashlib
import json
import logging
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import requests

from vulnprio import config
from vulnprio.download import TIMEOUT, Downloaded, download
from vulnprio.warehouse import log_load, transaction, utc_now

log = logging.getLogger(__name__)

SOURCE = "nvd"
API_PAGE_SIZE = 2000  # the API maximum
API_MAX_WINDOW = timedelta(days=120)  # the API refuses longer lastModified ranges
API_DELAY = 6.0  # seconds between requests without a key (NVD's recommendation)
API_DELAY_WITH_KEY = 0.6
# A yearly feed is one JSON object; the largest is already ~420 MB uncompressed.
MAX_FEED_BYTES = 1_500_000_000


class NvdError(Exception):
    pass


# --- Feeds -------------------------------------------------------------------


@dataclass(frozen=True)
class FeedMeta:
    last_modified: datetime  # UTC
    size: int  # uncompressed bytes
    sha256: str  # of the uncompressed JSON


def parse_meta(text: str) -> FeedMeta:
    """Parse a .meta file: "key:value" lines (lastModifiedDate, size, sha256...)."""
    fields = dict(line.strip().split(":", 1) for line in text.splitlines() if ":" in line)
    try:
        modified = datetime.fromisoformat(fields["lastModifiedDate"])
        return FeedMeta(
            last_modified=modified.astimezone(UTC).replace(tzinfo=None),
            size=int(fields["size"]),
            sha256=fields["sha256"].lower(),
        )
    except (KeyError, ValueError) as err:
        raise NvdError(f"unreadable feed metadata ({err!r}): {text[:200]!r}") from err


def verify_feed(path: Path, meta: FeedMeta) -> None:
    """Check the uncompressed size and SHA-256 against the .meta file."""
    digest = hashlib.sha256()
    size = 0
    try:
        with gzip.open(path, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as err:
        raise NvdError(f"{path.name} is not a valid gzip file: {err}") from err
    if size != meta.size or digest.hexdigest() != meta.sha256:
        raise NvdError(f"{path.name} does not match its .meta file (size {size} vs {meta.size}, or SHA-256)")


def _fetch_meta(session: requests.Session, year: int) -> FeedMeta:
    response = session.get(config.NVD_META_URL.format(year=year), timeout=TIMEOUT)
    response.raise_for_status()
    return parse_meta(response.text)


def _feed_already_loaded(con: duckdb.DuckDBPyConnection, year: int, sha256: str) -> bool:
    last = con.execute(
        "SELECT sha256 FROM raw.load_log WHERE source = ? AND version = ? ORDER BY loaded_at DESC LIMIT 1",
        [SOURCE, f"feed {year}"],
    ).fetchone()
    return last is not None and last[0] == sha256


def sync_feeds(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    years: list[int],
    landing_dir: Path,
    *,
    record_sync: bool,
) -> int:
    """Load the yearly feeds, one at a time. Returns the number of CVEs loaded.

    With `record_sync`, a completed run is recorded in raw.nvd_sync, covering
    changes up to the oldest feed's generation time.
    """
    loaded = 0
    covered_until = []
    for year in years:
        meta = _fetch_meta(session, year)
        covered_until.append(meta.last_modified)
        if _feed_already_loaded(con, year, meta.sha256):
            log.info("NVD feed %d unchanged since its last load, skipped", year)
            continue

        dest = landing_dir / "nvd" / "feeds" / f"nvdcve-2.0-{year}.json.gz"
        downloaded = download(session, config.NVD_FEED_URL.format(year=year), dest)
        try:
            verify_feed(downloaded.path, meta)
        except NvdError:
            # NVD regenerates the feeds daily; if it happened between fetching
            # the .meta and the file, both are fetched again once.
            log.warning("NVD feed %d does not match its .meta, fetching both again", year)
            meta = _fetch_meta(session, year)
            downloaded = download(session, config.NVD_FEED_URL.format(year=year), dest)
            verify_feed(downloaded.path, meta)

        # Logged with the .meta hash (uncompressed content), so an unchanged
        # feed is recognized next time before downloading it.
        downloaded = replace(downloaded, sha256=meta.sha256)
        loaded += _load_files(con, [downloaded.path], downloaded, f"feed {year}", min_rows=1)

    if record_sync:
        with transaction(con):
            _record_sync(con, "feeds", min(covered_until), loaded)
    return loaded


# --- API ---------------------------------------------------------------------


@dataclass(frozen=True)
class ApiFetch:
    pages: list[Path]
    cves: int
    sha256: str  # of all pages, in order
    size: int


def api_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Split [start, end] into windows the API accepts (at most 120 days each)."""
    if start >= end:
        raise NvdError(f"empty time window: {start} to {end}")
    windows = []
    while start < end:
        window_end = min(start + API_MAX_WINDOW, end)
        windows.append((start, window_end))
        start = window_end
    return windows


def _api_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fetch_api(
    session: requests.Session,
    start: datetime,
    end: datetime,
    dest_dir: Path,
    *,
    api_key: str | None = None,
    page_size: int = API_PAGE_SIZE,
    sleep: Callable[[float], None] = time.sleep,
) -> ApiFetch:
    """Save every page of CVEs modified between `start` and `end` (UTC) to `dest_dir`."""
    # The key travels as a header on these requests only, never in the URL,
    # so it does not end up in logs or in the load log.
    headers = {"apiKey": api_key} if api_key else {}
    delay = API_DELAY_WITH_KEY if api_key else API_DELAY

    shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.mkdir(parents=True)
    pages: list[Path] = []
    digest = hashlib.sha256()
    cves = size = 0

    for window_start, window_end in api_windows(start, end):
        start_index = 0
        while True:
            if pages:
                sleep(delay)  # stay under the rate limit
            params = {
                "lastModStartDate": _api_time(window_start),
                "lastModEndDate": _api_time(window_end),
                "startIndex": start_index,
                "resultsPerPage": page_size,
            }
            response = session.get(config.NVD_API_URL, params=params, headers=headers, timeout=TIMEOUT)
            if response.status_code != 200:
                reason = response.headers.get("message", "")
                raise NvdError(f"NVD API answered {response.status_code} {reason}".strip())

            body = response.content
            try:
                data = json.loads(body)
            except ValueError as err:
                raise NvdError(f"NVD API returned invalid JSON: {err}") from err
            vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
            total = data.get("totalResults") if isinstance(data, dict) else None
            if not isinstance(vulnerabilities, list) or not isinstance(total, int):
                raise NvdError("NVD API response has no vulnerabilities list or totalResults")

            page = dest_dir / f"page-{len(pages):04d}.json"
            page.write_bytes(body)
            pages.append(page)
            digest.update(body)
            size += len(body)
            cves += len(vulnerabilities)
            start_index += len(vulnerabilities)
            if not vulnerabilities or start_index >= total:
                break

    log.info("NVD API: %d CVEs modified between %s and %s, in %d page(s)", cves, start, end, len(pages))
    return ApiFetch(pages=pages, cves=cves, sha256=digest.hexdigest(), size=size)


def sync_api(
    con: duckdb.DuckDBPyConnection,
    session: requests.Session,
    start: datetime,
    end: datetime,
    landing_dir: Path,
    *,
    api_key: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Load CVEs modified between `start` and `end` and record the sync. Returns the CVE count."""
    api_dir = landing_dir / "nvd" / "api"
    fetched = fetch_api(session, start, end, api_dir, api_key=api_key, sleep=sleep)
    source_file = Downloaded(path=api_dir, url=config.NVD_API_URL, sha256=fetched.sha256, size=fetched.size)
    window = f"api {start:%Y-%m-%dT%H:%M} to {end:%Y-%m-%dT%H:%M}"
    return _load_files(con, fetched.pages, source_file, window, min_rows=0, sync=("api", end))


# --- Loading -----------------------------------------------------------------

STAGE_SQL = r"""
    CREATE OR REPLACE TEMP TABLE nvd_stage AS
    WITH items AS (
        SELECT unnest(vulnerabilities)->'cve' AS cve
        FROM read_json(?, maximum_object_size = ?, columns = {'vulnerabilities': 'JSON[]'})
    )
    SELECT
        cve->>'id'                                     AS cve_id,
        cve->>'sourceIdentifier'                       AS source_identifier,
        TRY_CAST(cve->>'published' AS TIMESTAMP)       AS published,
        TRY_CAST(cve->>'lastModified' AS TIMESTAMP)    AS last_modified,
        cve->>'vulnStatus'                             AS vuln_status,
        cve->'cveTags'                                 AS cve_tags,
        [d->>'value' FOR d IN CAST(cve->'descriptions' AS JSON[]) IF d->>'lang' = 'en'][1] AS description_en,
        cve->'metrics'                                 AS metrics,
        cve->'weaknesses'                              AS weaknesses,
        cve->'references'                              AS refs,
        list_sort(list_distinct([
            m->>'criteria'
            FOR m IN CAST(json_extract(cve, '$.configurations[*].nodes[*].cpeMatch[*]') AS JSON[])
            IF (m->>'vulnerable')::BOOLEAN
        ]))                                            AS cpes
    FROM items
"""

# A CVE can appear twice when it changes while the API is being paged through:
# keep its latest version.
DEDUPE_SQL = """
    DELETE FROM nvd_stage WHERE rowid IN (
        SELECT rowid FROM (
            SELECT rowid, row_number() OVER (PARTITION BY cve_id ORDER BY last_modified DESC NULLS LAST) AS n
            FROM nvd_stage
        ) WHERE n > 1
    )
"""

CHECK_SQL = r"""
    SELECT
        count(*),
        count(*) FILTER (WHERE cve_id IS NULL OR NOT regexp_full_match(cve_id, 'CVE-\d{4}-\d{4,}')),
        count(*) FILTER (WHERE published IS NULL OR last_modified IS NULL),
        count(*) FILTER (WHERE vuln_status IS NULL)
    FROM nvd_stage
"""

COUNT_CHANGES_SQL = """
    SELECT
        count(*) FILTER (WHERE t.cve_id IS NULL),
        count(*) FILTER (WHERE t.cve_id IS NOT NULL AND s.last_modified > t.last_modified)
    FROM nvd_stage s LEFT JOIN raw.nvd t ON t.cve_id = s.cve_id
"""

MERGE_SQL = """
    MERGE INTO raw.nvd AS t
    USING nvd_stage AS s
    ON t.cve_id = s.cve_id
    WHEN MATCHED AND s.last_modified >= t.last_modified THEN UPDATE SET
        source_identifier = s.source_identifier,
        published = s.published,
        last_modified = s.last_modified,
        vuln_status = s.vuln_status,
        cve_tags = s.cve_tags,
        description_en = s.description_en,
        metrics = s.metrics,
        weaknesses = s.weaknesses,
        refs = s.refs,
        cpes = s.cpes,
        loaded_at = $1
    WHEN NOT MATCHED THEN INSERT VALUES (
        s.cve_id, s.source_identifier, s.published, s.last_modified, s.vuln_status, s.cve_tags,
        s.description_en, s.metrics, s.weaknesses, s.refs, s.cpes, $1
    )
"""


def stage_files(con: duckdb.DuckDBPyConnection, paths: list[Path]) -> int:
    """Read feed or API files into the nvd_stage temp table. Returns the CVE count."""
    try:
        con.execute(STAGE_SQL, [[str(p) for p in paths], MAX_FEED_BYTES])
    except duckdb.Error as err:
        raise NvdError(f"could not read {paths[0].name}: {err}") from err
    duplicates = con.execute(DEDUPE_SQL).fetchone()[0]
    if duplicates:
        log.info("NVD: %d repeated CVE(s) collapsed to their latest version", duplicates)
    return con.execute("SELECT count(*) FROM nvd_stage").fetchone()[0]


def check_stage(con: duckdb.DuckDBPyConnection, min_rows: int) -> None:
    rows, bad_ids, bad_dates, no_status = con.execute(CHECK_SQL).fetchone()
    problems = []
    if rows < min_rows:
        problems.append(f"only {rows} CVEs (expected at least {min_rows})")
    if bad_ids:
        problems.append(f"{bad_ids} missing or malformed CVE ids")
    if bad_dates:
        problems.append(f"{bad_dates} CVEs without a valid published/lastModified date")
    if no_status:
        problems.append(f"{no_status} CVEs without vulnStatus")
    if problems:
        raise NvdError("; ".join(problems))


def _record_sync(con: duckdb.DuckDBPyConnection, mode: str, covered_until: datetime, cves: int) -> None:
    con.execute("INSERT INTO raw.nvd_sync VALUES (?, ?, ?, ?)", [mode, covered_until, cves, utc_now()])


def _load_files(
    con: duckdb.DuckDBPyConnection,
    paths: list[Path],
    source_file: Downloaded,
    version: str,
    *,
    min_rows: int,
    sync: tuple[str, datetime] | None = None,
) -> int:
    """Stage, check and merge files in one transaction. Returns the CVE count."""
    loaded_at = utc_now()
    rows = stage_files(con, paths)
    try:
        check_stage(con, min_rows)
        new, updated = con.execute(COUNT_CHANGES_SQL).fetchone()
        with transaction(con):
            con.execute(MERGE_SQL, [loaded_at])
            log_load(con, SOURCE, version, rows, source_file, loaded_at)
            if sync:
                _record_sync(con, sync[0], sync[1], rows)
    finally:
        con.execute("DROP TABLE IF EXISTS nvd_stage")

    log.info("NVD %s: %d CVEs (%d new, %d updated)", version, rows, new, updated)
    return rows


def watermark(con: duckdb.DuckDBPyConnection) -> datetime | None:
    """Modification time covered by the last complete sync, if any."""
    return con.execute("SELECT max(covered_until) FROM raw.nvd_sync").fetchone()[0]

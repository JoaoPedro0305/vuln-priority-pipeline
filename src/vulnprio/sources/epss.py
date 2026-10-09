"""EPSS: the daily probability that a CVE is exploited in the next 30 days.

FIRST publishes one gzipped CSV per day since 2021-04-14, covering every
published CVE. The file format changed twice, and all three are read:

    2021-04 .. 2021-08   cve,epss
    2021-09 .. 2022-02   cve,epss,percentile
    2022-02 onwards      #model_version:v2022.01.01,score_date:2022-02-07T00:00:00+0000
                         cve,epss,percentile

The model behind the scores also changes (v2, v3, v4...), so every row keeps
the model version that produced it when the file states it.

The CSV is parsed by DuckDB itself (read_csv), straight from the .gz file:
about 300,000 rows in well under a second, with no pandas in between.
"""

import gzip
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import duckdb

from vulnprio.download import Downloaded
from vulnprio.warehouse import log_load, transaction

log = logging.getLogger(__name__)

SOURCE = "epss"

# The smallest real file (April 2021) has ~65,000 CVEs. Far fewer means a
# broken file, not a real day of scores.
MIN_ROWS = 20_000

COLUMNS_WITH_PERCENTILE = ["cve", "epss", "percentile"]
COLUMNS_WITHOUT_PERCENTILE = ["cve", "epss"]
HEADER_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class EpssError(Exception):
    pass


@dataclass(frozen=True)
class EpssHeader:
    model_version: str | None
    score_date: date | None
    has_percentile: bool
    comment_lines: int  # lines before the column names (0 or 1)


def read_header(path: Path) -> EpssHeader:
    """Read the optional comment line and the column names of a daily file."""
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            first = fh.readline().strip()
            if first.startswith("#"):
                comment, columns_line, comment_lines = first[1:], fh.readline().strip(), 1
            else:
                comment, columns_line, comment_lines = "", first, 0
    except (OSError, UnicodeDecodeError) as err:  # gzip.BadGzipFile is an OSError
        raise EpssError(f"{path.name} is not a readable gzip text file: {err}") from err

    # "model_version:v2025.03.14,score_date:2025-03-17T12:55:00Z"
    meta = dict(part.split(":", 1) for part in comment.split(",") if ":" in part)
    date_match = HEADER_DATE.match(meta.get("score_date", ""))

    columns = columns_line.split(",")
    if columns not in (COLUMNS_WITH_PERCENTILE, COLUMNS_WITHOUT_PERCENTILE):
        raise EpssError(f"{path.name}: unexpected columns {columns}")

    return EpssHeader(
        model_version=meta.get("model_version"),
        score_date=date.fromisoformat(date_match.group()) if date_match else None,
        has_percentile=columns == COLUMNS_WITH_PERCENTILE,
        comment_lines=comment_lines,
    )


def _stage(con: duckdb.DuckDBPyConnection, path: Path, header: EpssHeader) -> None:
    """Read the CSV into a temporary table, typed but not yet validated."""
    if header.has_percentile:
        columns = "{'cve': 'VARCHAR', 'epss': 'DOUBLE', 'percentile': 'DOUBLE'}"
        percentile = "percentile"
    else:
        columns = "{'cve': 'VARCHAR', 'epss': 'DOUBLE'}"
        percentile = "NULL::DOUBLE"
    # Only the two fixed column lists above are formatted into the SQL;
    # the file path and line count are bound parameters.
    sql = f"""
        CREATE OR REPLACE TEMP TABLE epss_stage AS
        SELECT cve AS cve_id, epss, {percentile} AS percentile
        FROM read_csv(?, skip = ?, header = true, columns = {columns}, compression = 'gzip')
    """  # noqa: S608
    try:
        con.execute(sql, [str(path), header.comment_lines])
    except duckdb.Error as err:
        raise EpssError(f"{path.name}: could not read the CSV: {err}") from err


def _check_stage(con: duckdb.DuckDBPyConnection, min_rows: int) -> int:
    """Validate the staged rows. Returns the row count or raises EpssError."""
    rows, duplicates, bad_ids, bad_epss, bad_percentile = con.execute(r"""
        SELECT
            count(*),
            count(*) - count(DISTINCT cve_id),
            count(*) FILTER (WHERE cve_id IS NULL OR NOT regexp_full_match(cve_id, 'CVE-\d{4}-\d{4,}')),
            count(*) FILTER (WHERE epss IS NULL OR epss < 0 OR epss > 1),
            count(*) FILTER (WHERE percentile < 0 OR percentile > 1)
        FROM epss_stage
    """).fetchone()

    problems = []
    if rows < min_rows:
        problems.append(f"only {rows} rows (expected at least {min_rows})")
    if duplicates:
        problems.append(f"{duplicates} duplicated CVEs")
    if bad_ids:
        problems.append(f"{bad_ids} malformed CVE ids")
    if bad_epss:
        problems.append(f"{bad_epss} scores outside [0, 1]")
    if bad_percentile:
        problems.append(f"{bad_percentile} percentiles outside [0, 1]")
    if problems:
        raise EpssError("; ".join(problems))
    return rows


def load(
    con: duckdb.DuckDBPyConnection,
    downloaded: Downloaded,
    loaded_at: datetime,
    *,
    expected_date: date | None = None,
    min_rows: int = MIN_ROWS,
) -> date:
    """Validate a daily file and replace that day in raw.epss. Returns the score date.

    `expected_date` is the day that was requested; files without a comment line
    (before February 2022) only have it from the request.
    """
    header = read_header(downloaded.path)
    if header.score_date and expected_date and header.score_date != expected_date:
        raise EpssError(f"asked for {expected_date} but the file is for {header.score_date}")
    score_date = header.score_date or expected_date
    if score_date is None:
        raise EpssError(f"{downloaded.path.name} does not state its date and none was requested")

    _stage(con, downloaded.path, header)
    try:
        rows = _check_stage(con, min_rows)
        with transaction(con):
            con.execute("DELETE FROM raw.epss WHERE score_date = ?", [score_date])
            con.execute(
                """
                INSERT INTO raw.epss
                SELECT ?, cve_id, epss, percentile, ?, ? FROM epss_stage
                """,
                [score_date, header.model_version, loaded_at],
            )
            log_load(con, SOURCE, score_date.isoformat(), rows, downloaded, loaded_at)
    finally:
        con.execute("DROP TABLE IF EXISTS epss_stage")

    log.info("EPSS %s loaded: %d CVEs (model %s)", score_date, rows, header.model_version or "not stated")
    return score_date

"""Command line: `vulnprio ingest kev|epss|all` and `vulnprio status`."""

import argparse
import logging
from datetime import date
from pathlib import Path

import duckdb
import requests

from vulnprio.download import DownloadError, make_session
from vulnprio.ingest import ingest_epss, ingest_kev
from vulnprio.sources.epss import EpssError
from vulnprio.sources.kev import KevError
from vulnprio.warehouse import connect

log = logging.getLogger("vulnprio")

# What a source can fail with. Anything else is a bug and should show a traceback.
EXPECTED_ERRORS = (DownloadError, KevError, EpssError, requests.RequestException, duckdb.Error)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnprio", description="Rank CVEs by real-world exploitation risk.")
    parser.add_argument("--warehouse", type=Path, help="DuckDB file (default: data/warehouse.duckdb)")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="download sources and load them into the raw layer")
    ingest.add_argument("source", choices=["kev", "epss", "all"])
    ingest.add_argument("--date", type=date.fromisoformat, help="EPSS day to load, YYYY-MM-DD (default: latest)")

    commands.add_parser("status", help="show the latest load of each source")
    return parser


def run_ingest(con: duckdb.DuckDBPyConnection, source: str, day: date | None) -> int:
    session = make_session()
    failures = 0

    if source in ("kev", "all"):
        try:
            ingest_kev(con, session)
        except EXPECTED_ERRORS as err:
            log.error("KEV load failed: %s", err)
            failures += 1

    if source in ("epss", "all"):
        try:
            ingest_epss(con, session, day)
        except EXPECTED_ERRORS as err:
            log.error("EPSS load failed: %s", err)
            failures += 1

    return 1 if failures else 0


def show_status(con: duckdb.DuckDBPyConnection) -> int:
    latest = con.execute("""
        SELECT source, version, row_count, strftime(loaded_at, '%Y-%m-%d %H:%M UTC')
        FROM raw.load_log
        QUALIFY row_number() OVER (PARTITION BY source ORDER BY loaded_at DESC) = 1
        ORDER BY source
    """).fetchall()
    if not latest:
        print("Nothing loaded yet. Run: vulnprio ingest all")
        return 0

    print(f"{'source':<8}{'version':<14}{'rows':>10}  loaded at")
    for source, version, row_count, loaded_at in latest:
        print(f"{source:<8}{version:<14}{row_count:>10,}  {loaded_at}")

    days, first, last = con.execute(
        "SELECT count(DISTINCT score_date), min(score_date), max(score_date) FROM raw.epss"
    ).fetchone()
    if days:
        print(f"\nEPSS history: {days} day(s), from {first} to {last}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ingest" and args.date and args.source == "kev":
        parser.error("--date only applies to EPSS (KEV is always the current catalog)")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    con = connect(args.warehouse)
    try:
        if args.command == "ingest":
            return run_ingest(con, args.source, args.date)
        return show_status(con)
    finally:
        con.close()

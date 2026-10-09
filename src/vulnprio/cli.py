"""Command line: `vulnprio ingest kev|epss|nvd|all`, `vulnprio transform` and `vulnprio status`."""

import argparse
import logging
from datetime import date
from pathlib import Path

import duckdb
import requests

from vulnprio.download import DownloadError, make_session
from vulnprio.ingest import ingest_epss, ingest_kev, ingest_nvd
from vulnprio.sources.epss import EpssError
from vulnprio.sources.kev import KevError
from vulnprio.sources.nvd import NvdError
from vulnprio.transform import TransformError, run_dbt
from vulnprio.warehouse import connect

log = logging.getLogger("vulnprio")

SOURCES = ["kev", "epss", "nvd"]

# What a source can fail with. Anything else is a bug and should show a traceback.
EXPECTED_ERRORS = (DownloadError, KevError, EpssError, NvdError, requests.RequestException, duckdb.Error)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnprio", description="Rank CVEs by real-world exploitation risk.")
    parser.add_argument("--warehouse", type=Path, help="DuckDB file (default: data/warehouse.duckdb)")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="download sources and load them into the raw layer")
    ingest.add_argument("source", choices=[*SOURCES, "all"])
    ingest.add_argument("--date", type=date.fromisoformat, help="EPSS day to load, YYYY-MM-DD (default: latest)")
    nvd_mode = ingest.add_mutually_exclusive_group()
    nvd_mode.add_argument("--full", action="store_true", help="NVD: rebuild from the yearly feeds")
    nvd_mode.add_argument("--years", type=int, nargs="+", metavar="YEAR", help="NVD: load only these yearly feeds")
    nvd_mode.add_argument("--since", type=date.fromisoformat, help="NVD: load API changes since YYYY-MM-DD")

    transform = commands.add_parser("transform", help="build and test the dbt models (staging, marts)")
    transform.add_argument("--select", help="dbt selection, e.g. 'marts' or 'int_cve_cvss+'")

    commands.add_parser("status", help="show what is loaded")
    return parser


def run_ingest(con: duckdb.DuckDBPyConnection, args: argparse.Namespace) -> int:
    session = make_session()
    steps = {
        "kev": lambda: ingest_kev(con, session),
        "epss": lambda: ingest_epss(con, session, args.date),
        "nvd": lambda: ingest_nvd(con, session, full=args.full, years=args.years, since=args.since),
    }
    selected = SOURCES if args.source == "all" else [args.source]

    failures = 0
    for name in selected:
        try:
            steps[name]()
        except EXPECTED_ERRORS as err:
            log.error("%s load failed: %s", name.upper(), err)
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

    print(f"{'source':<8}{'last load':<36}{'rows':>10}  loaded at")
    for source, version, row_count, loaded_at in latest:
        print(f"{source:<8}{version:<36}{row_count:>10,}  {loaded_at}")

    kev_rows = con.execute("SELECT count(*) FROM raw.kev").fetchone()[0]
    days, first, last = con.execute(
        "SELECT count(DISTINCT score_date), min(score_date), max(score_date) FROM raw.epss"
    ).fetchone()
    nvd_rows, covered = con.execute(
        "SELECT (SELECT count(*) FROM raw.nvd), (SELECT max(covered_until) FROM raw.nvd_sync)"
    ).fetchone()

    print()
    print(f"KEV:  {kev_rows:,} CVEs")
    if days:
        print(f"EPSS: {days} day(s), from {first} to {last}")
    if nvd_rows:
        synced = f"changes covered until {covered:%Y-%m-%d %H:%M} UTC" if covered else "no complete sync yet"
        print(f"NVD:  {nvd_rows:,} CVEs, {synced}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ingest":
        if args.date and args.source in ("kev", "nvd"):
            parser.error("--date only applies to EPSS")
        if (args.full or args.years or args.since) and args.source in ("kev", "epss"):
            parser.error("--full, --years and --since only apply to NVD")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.command == "transform":
        # dbt opens the warehouse itself; no connection is held here meanwhile.
        try:
            run_dbt("build", warehouse=args.warehouse, select=args.select)
        except TransformError as err:
            log.error("%s", err)
            return 1
        return 0

    con = connect(args.warehouse)
    try:
        if args.command == "ingest":
            return run_ingest(con, args)
        return show_status(con)
    finally:
        con.close()

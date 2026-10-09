"""Command line: `vulnprio ingest`, `transform`, `top`, `report` and `status`."""

import argparse
import logging
from datetime import date
from pathlib import Path

import duckdb
import requests

from vulnprio import config, report
from vulnprio.download import DownloadError, make_session
from vulnprio.ingest import ingest_deps, ingest_epss, ingest_epss_history, ingest_kev, ingest_nvd
from vulnprio.sources.deps import DepsError
from vulnprio.sources.epss import EpssError
from vulnprio.sources.kev import KevError
from vulnprio.sources.nvd import NvdError
from vulnprio.transform import TransformError, run_dbt
from vulnprio.warehouse import connect

log = logging.getLogger("vulnprio")

SOURCES = ["kev", "epss", "nvd", "deps"]

# What a source can fail with. Anything else is a bug and should show a traceback.
EXPECTED_ERRORS = (DownloadError, KevError, EpssError, NvdError, DepsError, requests.RequestException, duckdb.Error)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnprio", description="Rank CVEs by real-world exploitation risk.")
    parser.add_argument("--warehouse", type=Path, help="DuckDB file (default: data/warehouse.duckdb)")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="download sources and load them into the raw layer")
    ingest.add_argument("source", choices=[*SOURCES, "all"])
    epss_day = ingest.add_mutually_exclusive_group()
    epss_day.add_argument("--date", type=date.fromisoformat, help="EPSS day to load, YYYY-MM-DD (default: latest)")
    epss_day.add_argument(
        "--monthly-since",
        type=date.fromisoformat,
        metavar="YYYY-MM-DD",
        help="EPSS: also load the first day of every month since then (history for the backtest)",
    )
    nvd_mode = ingest.add_mutually_exclusive_group()
    nvd_mode.add_argument("--full", action="store_true", help="NVD: rebuild from the yearly feeds")
    nvd_mode.add_argument("--years", type=int, nargs="+", metavar="YEAR", help="NVD: load only these yearly feeds")
    nvd_mode.add_argument("--since", type=date.fromisoformat, help="NVD: load API changes since YYYY-MM-DD")
    ingest.add_argument("--assets", type=Path, help="deps: the assets file (default: assets.toml)")

    transform = commands.add_parser("transform", help="build and test the dbt models (staging, marts)")
    transform.add_argument("--select", help="dbt selection, e.g. 'marts' or 'int_cve_cvss+'")
    transform.add_argument(
        "--mission-impact",
        choices=["low", "medium", "high"],
        help="SSVC mission & well-being impact of your systems (default: medium)",
    )
    transform.add_argument(
        "--publicly-exposed",
        choices=["yes", "no"],
        help="BOD 26-04: are your systems reachable from the internet? (default: yes)",
    )

    top = commands.add_parser("top", help="list the CVEs to patch first")
    top.add_argument("--limit", type=int, default=20)
    top.add_argument("--vendor", help="only this vendor (substring, case-insensitive)")
    top.add_argument("--product", help="only this product (substring, case-insensitive)")
    top.add_argument("--since", type=date.fromisoformat, help="only CVEs published since YYYY-MM-DD")

    findings = commands.add_parser("findings", help="vulnerable dependencies of the assets, and what to upgrade")
    findings.add_argument("--asset", help="only this asset (substring, case-insensitive)")
    findings.add_argument("--details", action="store_true", help="list every vulnerability, not only the upgrades")

    report_cmd = commands.add_parser("report", help="print the backtest results and draw its charts")
    report_cmd.add_argument("--out", type=Path, default=Path("docs/img"), help="folder for the charts")

    commands.add_parser("status", help="show what is loaded")
    return parser


def run_ingest(con: duckdb.DuckDBPyConnection, args: argparse.Namespace) -> int:
    session = make_session()
    steps = {
        "kev": lambda: ingest_kev(con, session),
        "epss": lambda: (
            ingest_epss_history(con, session, args.monthly_since)
            if args.monthly_since
            else ingest_epss(con, session, args.date)
        ),
        "nvd": lambda: ingest_nvd(con, session, full=args.full, years=args.years, since=args.since),
        "deps": lambda: ingest_deps(con, session, args.assets),
    }
    selected = SOURCES if args.source == "all" else [args.source]
    assets_file = args.assets or config.ASSETS_PATH
    if args.source == "all" and not assets_file.exists():
        log.info("no %s: dependency scan skipped", assets_file)
        selected = [s for s in selected if s != "deps"]

    failures = 0
    for name in selected:
        try:
            steps[name]()
        except EXPECTED_ERRORS as err:
            log.error("%s load failed: %s", name.upper(), err)
            failures += 1
    return 1 if failures else 0


def show_top(con: duckdb.DuckDBPyConnection, args: argparse.Namespace) -> int:
    try:
        rows = con.execute(
            """
            SELECT priority_rank, cve_id, coalesce(vendor || ' ' || product, '?'), remediation, ssvc_decision,
                   priority_reason
            FROM marts.cve_priorities
            WHERE ($1 IS NULL OR vendor ILIKE '%' || $1 || '%')
              AND ($2 IS NULL OR product ILIKE '%' || $2 || '%')
              AND ($3 IS NULL OR published >= $3)
            ORDER BY priority_rank
            LIMIT $4
            """,
            [args.vendor, args.product, args.since, args.limit],
        ).fetchall()
    except duckdb.CatalogException:
        print("No priorities yet. Run: vulnprio transform")
        return 1

    print(f"{'rank':>7}  {'cve':<16}{'product':<34}{'fix within':<18}{'ssvc':<8}why")
    for rank, cve_id, product, remediation, decision, reason in rows:
        fix = remediation.replace(" & forensic investigation", "+forensics")
        print(f"{rank:>7}  {cve_id:<16}{product[:32]:<34}{fix:<18}{decision:<8}{reason}")
    if not rows:
        print("(no CVE matches)")
    return 0


def _deadline(days: int | None) -> str:
    return f"{days} days" if days else "next upgrade"


def show_findings(con: duckdb.DuckDBPyConnection, asset_filter: str | None, details: bool) -> int:
    where = "WHERE ($1 IS NULL OR asset ILIKE '%' || $1 || '%')"
    try:
        assets = con.execute(
            f"""
            SELECT asset, packages, vulnerable_packages, findings, without_fix, shortest_deadline_days,
                   publicly_exposed, mission_impact
            FROM assets.asset_summary {where}
            ORDER BY findings DESC, asset
            """,  # noqa: S608
            [asset_filter],
        ).fetchall()
        upgrades = con.execute(
            f"""
            SELECT asset, package, version, upgrade_to, is_direct, vulnerabilities, without_fix,
                   ssvc_decision, deadline_days, most_urgent
            FROM assets.asset_upgrades {where}
            ORDER BY priority_rank
            """,  # noqa: S608
            [asset_filter],
        ).fetchall()
    except duckdb.CatalogException:
        print("No dependency scan yet. Run: vulnprio ingest deps, then vulnprio transform")
        return 1

    print(f"{'asset':<34}{'exposed':<9}{'impact':<8}{'packages':>9}{'vulnerable':>11}{'flaws':>7}  fix within")
    for asset, packages, vulnerable, flaws, _, deadline, exposed, impact in assets:
        fix = _deadline(deadline) if flaws else "-"
        print(f"{asset[:33]:<34}{exposed:<9}{impact:<8}{packages:>9}{vulnerable:>11}{flaws:>7}  {fix}")

    if upgrades:
        print("\nUpgrades, most urgent first:")
        for asset, package, version, target, direct, count, unfixed, decision, deadline, urgent in upgrades:
            how = "" if direct else " (comes with another package)"
            target = target or "no fixed version"
            note = f", {unfixed} without a fix" if unfixed else ""
            print(f"  {asset}: {package} {version} -> {target}{how}")
            print(
                f"      fixes {count} vulnerabilities{note}; {decision}, within {_deadline(deadline)}; worst: {urgent}"
            )

    if details:
        rows = con.execute(
            f"""
            SELECT priority_rank, asset, package, version, vuln_id, ssvc_decision, priority_reason
            FROM assets.asset_findings {where}
            ORDER BY priority_rank
            """,  # noqa: S608
            [asset_filter],
        ).fetchall()
        print("\nEvery vulnerability:")
        for rank, asset, package, version, vuln_id, decision, reason in rows:
            print(f"  {rank:>4}  {asset}: {package} {version}  {vuln_id:<20}{decision:<8}{reason}")
    return 0


def show_report(con: duckdb.DuckDBPyConnection, out: Path) -> int:
    try:
        table = report.coverage_table(con)
        periods = report.period_table(con)
        reach = report.reach_summary(con)
        charts = [
            report.plot_coverage(con, out / "backtest_coverage.png"),
            report.plot_by_year(con, out / "backtest_by_year.png"),
        ]
    except report.ReportError as err:
        print(err)
        return 1

    print("Share of the CVEs exploited in the next 30 days that each strategy had ranked within the")
    print("monthly budget (budget as a share of all open CVEs in brackets):\n")
    print(table)
    print("\nAt 1,000 CVEs a month, in each period:\n")
    print(periods)
    print("\nKEV additions in the backtest windows:")
    for reason, count in reach:
        print(f"  {count:>5}  {reason}")
    print("\nCharts: " + ", ".join(str(c) for c in charts))
    return 0


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
        if (args.date or args.monthly_since) and args.source in ("kev", "nvd", "deps"):
            parser.error("--date and --monthly-since only apply to EPSS")
        if (args.full or args.years or args.since) and args.source in ("kev", "epss", "deps"):
            parser.error("--full, --years and --since only apply to NVD")
        if args.assets and args.source not in ("deps", "all"):
            parser.error("--assets only applies to deps")

    # force: importing dbt already installs a handler, which would make this a no-op.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", force=True)
    if args.command == "transform":
        # dbt opens the warehouse itself; no connection is held here meanwhile.
        dbt_vars = {"mission_impact": args.mission_impact, "publicly_exposed": args.publicly_exposed}
        try:
            run_dbt(
                "build",
                warehouse=args.warehouse,
                select=args.select,
                dbt_vars={k: v for k, v in dbt_vars.items() if v},
            )
        except TransformError as err:
            log.error("%s", err)
            return 1
        return 0

    con = connect(args.warehouse)
    try:
        if args.command == "ingest":
            return run_ingest(con, args)
        if args.command == "top":
            return show_top(con, args)
        if args.command == "report":
            return show_report(con, args.out)
        if args.command == "findings":
            return show_findings(con, args.asset, args.details)
        return show_status(con)
    finally:
        con.close()

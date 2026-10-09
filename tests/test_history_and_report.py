from datetime import date

import pytest
import responses

from tests.conftest import epss_file, epss_rows
from vulnprio import config, report
from vulnprio.cli import main
from vulnprio.download import make_session
from vulnprio.ingest import ingest_epss_history, month_starts
from vulnprio.warehouse import connect


def epss_day(tmp_path, day: date) -> bytes:
    comment = f"#model_version:v2025.03.14,score_date:{day.isoformat()}T12:00:00Z"
    return epss_file(tmp_path / f"{day}.csv.gz", epss_rows(25_000), comment=comment).read_bytes()


def test_month_starts():
    assert month_starts(date(2025, 11, 20), date(2026, 2, 1)) == [
        date(2025, 11, 1),
        date(2025, 12, 1),
        date(2026, 1, 1),
        date(2026, 2, 1),
    ]
    assert month_starts(date(2026, 3, 5), date(2026, 3, 31)) == [date(2026, 3, 1)]


@responses.activate
def test_history_skips_loaded_months_and_falls_back_to_the_next_day(con, tmp_path):
    # January is already loaded; February 1st was never published, the 2nd was.
    responses.get(config.EPSS_URL.format(day="2026-01-01"), body=epss_day(tmp_path, date(2026, 1, 1)))
    responses.get(config.EPSS_URL.format(day="2026-02-01"), status=403)
    responses.get(config.EPSS_URL.format(day="2026-02-02"), body=epss_day(tmp_path, date(2026, 2, 2)))
    responses.get(config.EPSS_URL.format(day="2026-03-01"), body=epss_day(tmp_path, date(2026, 3, 1)))
    session = make_session()

    assert ingest_epss_history(con, session, date(2026, 1, 1), date(2026, 1, 31), tmp_path) == [date(2026, 1, 1)]
    loaded = ingest_epss_history(con, session, date(2026, 1, 1), date(2026, 3, 15), tmp_path)

    assert loaded == [date(2026, 2, 2), date(2026, 3, 1)]
    assert len([c for c in responses.calls if "2026-01-01" in c.request.url]) == 1  # not fetched twice
    days = con.execute("SELECT DISTINCT score_date FROM raw.epss ORDER BY 1").fetchall()
    assert [d for (d,) in days] == [date(2026, 1, 1), date(2026, 2, 2), date(2026, 3, 1)]


@responses.activate
def test_history_gives_up_on_a_month_without_files(con, tmp_path):
    for day in ("2026-02-01", "2026-02-02", "2026-02-03"):
        responses.get(config.EPSS_URL.format(day=day), status=403)

    assert ingest_epss_history(con, make_session(), date(2026, 2, 1), date(2026, 2, 28), tmp_path) == []


@responses.activate
def test_history_stops_on_other_errors(con, tmp_path):
    responses.get(config.EPSS_URL.format(day="2026-02-01"), status=500)

    with pytest.raises(Exception, match="500"):
        ingest_epss_history(con, make_session(), date(2026, 2, 1), date(2026, 2, 28), tmp_path)


def test_monthly_since_with_kev_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--warehouse", str(tmp_path / "w.duckdb"), "ingest", "kev", "--monthly-since", "2026-01-01"])
    assert exc.value.code == 2


# --- report ---------------------------------------------------------------------

STRATEGY_COVERAGE = {
    "priority": 0.2,
    "epss": 0.15,
    "track_star_first": 0.18,
    "timeline_first": 0.1,
    "cvss": 0.01,
    "random": 0.001,
}


@pytest.fixture
def backtest_warehouse(tmp_path):
    """A warehouse with hand-made backtest result tables (what dbt would build)."""
    path = tmp_path / "warehouse.duckdb"
    con = connect(path)
    con.execute("CREATE SCHEMA backtest")
    con.execute("""
        CREATE TABLE backtest.backtest_coverage (
            strategy VARCHAR, budget INTEGER, caught BIGINT, exploited BIGINT, coverage DOUBLE,
            efficiency DOUBLE, budget_share DOUBLE, cycles BIGINT)
    """)
    con.execute(
        "CREATE TABLE backtest.backtest_by_year "
        "(year BIGINT, strategy VARCHAR, exploited BIGINT, caught BIGINT, coverage DOUBLE)"
    )
    con.execute("""
        CREATE TABLE backtest.backtest_by_period (
            period VARCHAR, strategy VARCHAR, budget INTEGER, exploited BIGINT, caught BIGINT, coverage DOUBLE)
    """)
    con.execute(
        "CREATE TABLE backtest.backtest_reach (decision_date DATE, cve_id VARCHAR, date_added DATE, reach VARCHAR)"
    )
    for strategy, base in STRATEGY_COVERAGE.items():
        for budget in report.TABLE_BUDGETS:
            coverage = min(1.0, base * budget / 1000)
            con.execute(
                "INSERT INTO backtest.backtest_coverage VALUES (?, ?, 0, 100, ?, 0, ?, 12)",
                [strategy, budget, coverage, budget / 250_000],
            )
            for period in ("before 2025", "from 2025"):
                con.execute(
                    "INSERT INTO backtest.backtest_by_period VALUES (?, ?, ?, 50, 0, ?)",
                    [period, strategy, budget, coverage],
                )
        for year in (2024, 2025):
            con.execute("INSERT INTO backtest.backtest_by_year VALUES (?, ?, 50, 0, ?)", [year, strategy, base])
    con.execute("INSERT INTO backtest.backtest_reach VALUES ('2025-01-01', 'CVE-2025-1', '2025-01-10', 'rankable')")
    con.close()
    return path


def test_report_prints_tables_and_draws_charts(backtest_warehouse, tmp_path, capsys):
    out = tmp_path / "img"
    assert main(["--warehouse", str(backtest_warehouse), "report", "--out", str(out)]) == 0

    printed = capsys.readouterr().out
    assert "| This project: SSVC act/attend, then EPSS | 2.0% | 10.0% | 20.0% |" in printed
    assert "| Strategy | before 2025 (50 exploited) | from 2025 (50 exploited) |" in printed
    assert "1  rankable" in printed
    for chart in ("backtest_coverage.png", "backtest_by_year.png"):
        assert (out / chart).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_report_before_the_backtest_exists(tmp_path, capsys):
    assert main(["--warehouse", str(tmp_path / "w.duckdb"), "report", "--out", str(tmp_path)]) == 1
    assert "run: vulnprio transform" in capsys.readouterr().out

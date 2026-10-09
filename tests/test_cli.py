"""End to end: the command line, with both sources answered by fake HTTP responses."""

import duckdb
import pytest
import responses

from tests.conftest import epss_file, epss_rows, kev_entry, kev_feed
from vulnprio import config
from vulnprio.cli import main

EPSS_CURRENT = config.EPSS_URL.format(day="current")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LANDING_DIR", tmp_path / "landing")
    gz = epss_file(tmp_path / "fixture.csv.gz", epss_rows(25_000))
    return tmp_path / "warehouse.duckdb", gz.read_bytes()


def counts(warehouse):
    with duckdb.connect(str(warehouse), read_only=True) as con:
        return con.execute("SELECT (SELECT count(*) FROM raw.kev), (SELECT count(*) FROM raw.epss)").fetchone()


@responses.activate
def test_ingest_all_then_status(setup, capsys):
    warehouse, epss_gz = setup
    responses.get(config.KEV_URL, body=kev_feed([kev_entry("CVE-2024-0001"), kev_entry("CVE-2024-0002")]))
    responses.get(EPSS_CURRENT, body=epss_gz)

    assert main(["--warehouse", str(warehouse), "ingest", "all"]) == 0
    assert counts(warehouse) == (2, 25_000)

    assert main(["--warehouse", str(warehouse), "status"]) == 0
    out = capsys.readouterr().out
    assert "2026.01.15" in out
    assert "25,000" in out
    assert "EPSS history: 1 day(s)" in out


@responses.activate
def test_one_source_failing_does_not_stop_the_other(setup):
    warehouse, epss_gz = setup
    responses.get(config.KEV_URL, body=b"<html>maintenance</html>")
    responses.get(EPSS_CURRENT, body=epss_gz)

    assert main(["--warehouse", str(warehouse), "ingest", "all"]) == 1
    assert counts(warehouse) == (0, 25_000)


@responses.activate
def test_unpublished_epss_day_fails_cleanly(setup):
    warehouse, _ = setup
    responses.get(config.EPSS_URL.format(day="2026-12-01"), status=403)

    assert main(["--warehouse", str(warehouse), "ingest", "epss", "--date", "2026-12-01"]) == 1


def test_epss_day_before_the_first_file_is_refused(setup):
    warehouse, _ = setup
    assert main(["--warehouse", str(warehouse), "ingest", "epss", "--date", "2020-01-01"]) == 1


def test_date_with_kev_is_a_usage_error(setup):
    warehouse, _ = setup
    with pytest.raises(SystemExit) as exc:
        main(["--warehouse", str(warehouse), "ingest", "kev", "--date", "2026-01-01"])
    assert exc.value.code == 2


def test_status_on_an_empty_warehouse(setup, capsys):
    warehouse, _ = setup
    assert main(["--warehouse", str(warehouse), "status"]) == 0
    assert "Nothing loaded yet" in capsys.readouterr().out

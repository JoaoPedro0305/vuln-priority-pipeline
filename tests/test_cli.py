"""End to end: the command line, with every source answered by fake HTTP responses."""

import re

import duckdb
import pytest
import responses

from tests.conftest import epss_file, epss_rows, kev_entry, kev_feed, nvd_cve, nvd_feed
from vulnprio import config
from vulnprio.cli import main

EPSS_CURRENT = config.EPSS_URL.format(day="current")
ANY_YEAR = r"\d{4}"


def serve_nvd_feeds():
    """The same small feed for every year, so a first (full) NVD sync succeeds."""
    gz, meta = nvd_feed([nvd_cve("CVE-2024-0001"), nvd_cve("CVE-2024-0002"), nvd_cve("CVE-2024-0003")])
    responses.get(re.compile(re.escape(config.NVD_META_URL).replace(r"\{year\}", ANY_YEAR)), body=meta)
    responses.get(re.compile(re.escape(config.NVD_FEED_URL).replace(r"\{year\}", ANY_YEAR)), body=gz)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LANDING_DIR", tmp_path / "landing")
    monkeypatch.setattr(config, "ASSETS_PATH", tmp_path / "no-assets.toml")  # deps scan skipped
    gz = epss_file(tmp_path / "fixture.csv.gz", epss_rows(25_000))
    return tmp_path / "warehouse.duckdb", gz.read_bytes()


def counts(warehouse):
    with duckdb.connect(str(warehouse), read_only=True) as con:
        return con.execute(
            "SELECT (SELECT count(*) FROM raw.kev), (SELECT count(*) FROM raw.epss), (SELECT count(*) FROM raw.nvd)"
        ).fetchone()


@responses.activate
def test_ingest_all_then_status(setup, capsys):
    warehouse, epss_gz = setup
    responses.get(config.KEV_URL, body=kev_feed([kev_entry("CVE-2024-0001"), kev_entry("CVE-2024-0002")]))
    responses.get(EPSS_CURRENT, body=epss_gz)
    serve_nvd_feeds()

    assert main(["--warehouse", str(warehouse), "ingest", "all"]) == 0
    assert counts(warehouse) == (2, 25_000, 3)
    # Progress is logged (importing dbt must not silence the CLI's logging).
    assert "KEV catalog 2026.01.15 loaded: 2 CVEs" in capsys.readouterr().err

    assert main(["--warehouse", str(warehouse), "status"]) == 0
    out = capsys.readouterr().out
    assert "2026.01.15" in out
    assert "25,000" in out
    assert "EPSS: 1 day(s)" in out
    assert "NVD:  3 CVEs, changes covered until 2024-02-01 00:00 UTC" in out


@responses.activate
def test_one_source_failing_does_not_stop_the_other(setup):
    warehouse, epss_gz = setup
    responses.get(config.KEV_URL, body=b"<html>maintenance</html>")
    responses.get(EPSS_CURRENT, body=epss_gz)
    serve_nvd_feeds()

    assert main(["--warehouse", str(warehouse), "ingest", "all"]) == 1
    assert counts(warehouse) == (0, 25_000, 3)


@responses.activate
def test_unpublished_epss_day_fails_cleanly(setup):
    warehouse, _ = setup
    responses.get(config.EPSS_URL.format(day="2026-12-01"), status=403)

    assert main(["--warehouse", str(warehouse), "ingest", "epss", "--date", "2026-12-01"]) == 1


def test_epss_day_before_the_first_file_is_refused(setup):
    warehouse, _ = setup
    assert main(["--warehouse", str(warehouse), "ingest", "epss", "--date", "2020-01-01"]) == 1


@pytest.mark.parametrize(
    "args",
    [
        ["ingest", "kev", "--date", "2026-01-01"],
        ["ingest", "nvd", "--date", "2026-01-01"],
        ["ingest", "epss", "--full"],
        ["ingest", "kev", "--years", "2024"],
        ["ingest", "nvd", "--full", "--since", "2026-01-01"],
    ],
)
def test_options_for_the_wrong_source_are_usage_errors(setup, args):
    warehouse, _ = setup
    with pytest.raises(SystemExit) as exc:
        main(["--warehouse", str(warehouse), *args])
    assert exc.value.code == 2


def test_status_on_an_empty_warehouse(setup, capsys):
    warehouse, _ = setup
    assert main(["--warehouse", str(warehouse), "status"]) == 0
    assert "Nothing loaded yet" in capsys.readouterr().out


def test_explicit_deps_scan_without_assets_file_fails(setup):
    warehouse, _ = setup
    assert main(["--warehouse", str(warehouse), "ingest", "deps"]) == 1

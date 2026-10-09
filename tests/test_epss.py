from datetime import date

import pytest

from tests.conftest import LOADED_AT, as_downloaded, epss_file, epss_rows
from vulnprio.sources import epss

ROWS = [("CVE-2024-0001", 0.5, 0.99), ("CVE-2024-0002", 0.01, 0.5), ("CVE-2021-44228", 0.97, 1.0)]


def load(con, path, expected_date=None):
    return epss.load(con, as_downloaded(path), LOADED_AT, expected_date=expected_date, min_rows=1)


@pytest.mark.parametrize(
    ("comment", "columns", "expected"),
    [
        (
            "#model_version:v2025.03.14,score_date:2025-03-17T12:55:00Z",
            "cve,epss,percentile",
            epss.EpssHeader("v2025.03.14", date(2025, 3, 17), has_percentile=True, comment_lines=1),
        ),
        (
            "#model_version:v2022.01.01,score_date:2022-02-07T00:00:00+0000",
            "cve,epss,percentile",
            epss.EpssHeader("v2022.01.01", date(2022, 2, 7), has_percentile=True, comment_lines=1),
        ),
        (None, "cve,epss,percentile", epss.EpssHeader(None, None, has_percentile=True, comment_lines=0)),
        (None, "cve,epss", epss.EpssHeader(None, None, has_percentile=False, comment_lines=0)),
    ],
)
def test_read_header_understands_every_format(tmp_path, comment, columns, expected):
    path = epss_file(tmp_path / "e.csv.gz", ROWS, comment=comment, columns=columns)
    assert epss.read_header(path) == expected


def test_read_header_rejects_unknown_columns(tmp_path):
    path = epss_file(tmp_path / "e.csv.gz", [], columns="cve,score")
    with pytest.raises(epss.EpssError, match="unexpected columns"):
        epss.read_header(path)


def test_read_header_rejects_a_file_that_is_not_gzip(tmp_path):
    path = tmp_path / "e.csv.gz"
    path.write_text("<html>Access Denied</html>")
    with pytest.raises(epss.EpssError, match="not a readable gzip"):
        epss.read_header(path)


def test_load_current_format(con, tmp_path):
    score_date = load(con, epss_file(tmp_path / "e.csv.gz", ROWS))

    assert score_date == date(2026, 1, 15)
    rows = con.execute("SELECT * EXCLUDE (loaded_at) FROM raw.epss ORDER BY cve_id").fetchall()
    assert rows[0] == (date(2026, 1, 15), "CVE-2021-44228", 0.97, 1.0, "v2025.03.14")
    assert len(rows) == 3
    log = con.execute("SELECT source, version, row_count FROM raw.load_log").fetchall()
    assert log == [("epss", "2026-01-15", 3)]


def test_load_oldest_format_takes_the_date_from_the_request(con, tmp_path):
    path = epss_file(tmp_path / "e.csv.gz", [(cve, score) for cve, score, _ in ROWS], comment=None, columns="cve,epss")
    load(con, path, expected_date=date(2021, 5, 1))

    rows = con.execute("SELECT DISTINCT score_date, percentile, model_version FROM raw.epss").fetchall()
    assert rows == [(date(2021, 5, 1), None, None)]


def test_load_without_any_date_fails(con, tmp_path):
    path = epss_file(tmp_path / "e.csv.gz", ROWS, comment=None)
    with pytest.raises(epss.EpssError, match="does not state its date"):
        load(con, path)


def test_load_rejects_a_file_for_another_day(con, tmp_path):
    with pytest.raises(epss.EpssError, match="asked for 2026-01-14"):
        load(con, epss_file(tmp_path / "e.csv.gz", ROWS), expected_date=date(2026, 1, 14))


def test_reloading_a_day_replaces_it(con, tmp_path):
    load(con, epss_file(tmp_path / "a.csv.gz", ROWS))
    load(con, epss_file(tmp_path / "b.csv.gz", ROWS[:1]))

    assert con.execute("SELECT count(*) FROM raw.epss").fetchone()[0] == 1


def test_days_accumulate(con, tmp_path):
    load(con, epss_file(tmp_path / "a.csv.gz", ROWS))
    other_day = "#model_version:v2025.03.14,score_date:2026-01-16T12:55:00Z"
    load(con, epss_file(tmp_path / "b.csv.gz", ROWS, comment=other_day))

    assert con.execute("SELECT count(DISTINCT score_date), count(*) FROM raw.epss").fetchone() == (2, 6)


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([("CVE-2024-0001", 1.5, 0.9)], "scores outside"),
        ([("CVE-2024-0001", 0.5, -0.1)], "percentiles outside"),
        ([("CVE-2024-0001", 0.5, 0.9), ("CVE-2024-0001", 0.4, 0.8)], "duplicated"),
        ([("NOT-A-CVE", 0.5, 0.9)], "malformed CVE ids"),
        ([("CVE-2024-0001", "high", 0.9)], "could not read the CSV"),
    ],
)
def test_invalid_file_leaves_the_table_untouched(con, tmp_path, rows, message):
    load(con, epss_file(tmp_path / "good.csv.gz", ROWS))

    with pytest.raises(epss.EpssError, match=message):
        load(con, epss_file(tmp_path / "bad.csv.gz", rows))

    assert con.execute("SELECT count(*) FROM raw.epss").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM raw.load_log").fetchone()[0] == 1


def test_too_few_rows_is_refused(con, tmp_path):
    path = epss_file(tmp_path / "e.csv.gz", epss_rows(10))
    with pytest.raises(epss.EpssError, match="only 10 rows"):
        epss.load(con, as_downloaded(path), LOADED_AT)

import pytest

from tests.conftest import LOADED_AT, as_downloaded, kev_entry, kev_feed
from vulnprio.sources import kev


def load_feed(con, tmp_path, entries, version="2026.01.15"):
    path = tmp_path / f"kev-{version}.json"
    path.write_bytes(kev_feed(entries, version))
    return kev.load(con, kev.parse(path.read_bytes()), as_downloaded(path), LOADED_AT)


def test_parse_valid_feed():
    catalog = kev.parse(kev_feed([kev_entry("CVE-2024-0001"), kev_entry("CVE-2024-0002", cwes=[], dueDate="")]))

    assert catalog.version == "2026.01.15"
    assert [row["cve_id"] for row in catalog.rows] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert catalog.rows[0]["date_added"] == "2024-03-01"
    assert catalog.rows[1]["due_date"] is None
    assert catalog.rows[1]["cwes"] == []


def test_parse_reports_every_problem_at_once():
    entries = [
        kev_entry("CVE-2024-0001"),
        kev_entry("CVE-2024-0001"),  # duplicate
        kev_entry("CVE-24-1"),  # malformed id
        kev_entry("CVE-2024-0003", dateAdded="03/01/2024"),  # not ISO
        kev_entry("CVE-2024-0004", product=""),  # required field empty
    ]
    with pytest.raises(kev.KevError) as err:
        kev.parse(kev_feed(entries))

    message = str(err.value)
    assert "4 problem(s)" in message
    assert "appears more than once" in message
    assert "malformed CVE id" in message
    assert "bad date" in message
    assert "missing product" in message


def test_parse_rejects_count_mismatch():
    with pytest.raises(kev.KevError, match="header count is 5"):
        kev.parse(kev_feed([kev_entry("CVE-2024-0001")], count=5))


@pytest.mark.parametrize(
    "raw",
    [b"<html>maintenance</html>", b'{"title": "no catalog"}', b"[]", b'{"catalogVersion": "x", "count": 0, '],
)
def test_parse_rejects_broken_feeds(raw):
    with pytest.raises(kev.KevError):
        kev.parse(raw)


def test_parse_rejects_empty_catalog():
    with pytest.raises(kev.KevError, match="empty"):
        kev.parse(kev_feed([]))


def test_load_replaces_the_whole_catalog(con, tmp_path):
    load_feed(con, tmp_path, [kev_entry("CVE-2024-0001"), kev_entry("CVE-2024-0002")], "2026.01.14")
    load_feed(con, tmp_path, [kev_entry("CVE-2024-0002"), kev_entry("CVE-2024-0003")], "2026.01.15")

    rows = con.execute("SELECT cve_id, catalog_version FROM raw.kev ORDER BY cve_id").fetchall()
    assert rows == [("CVE-2024-0002", "2026.01.15"), ("CVE-2024-0003", "2026.01.15")]
    log = con.execute("SELECT source, version, row_count FROM raw.load_log ORDER BY version").fetchall()
    assert log == [("kev", "2026.01.14", 2), ("kev", "2026.01.15", 2)]


def test_load_keeps_types_and_text_as_published(con, tmp_path):
    entry = kev_entry("CVE-2024-0001", vulnerabilityName=" Padded Name", cwes=["CWE-20", "CWE-502"])
    load_feed(con, tmp_path, [entry])

    name, added, cwes = con.execute("SELECT vulnerability_name, date_added, cwes FROM raw.kev").fetchone()
    assert name == " Padded Name"  # trimmed later, in dbt staging
    assert str(added) == "2024-03-01"
    assert cwes == ["CWE-20", "CWE-502"]


def test_load_refuses_a_catalog_that_shrank(con, tmp_path):
    load_feed(con, tmp_path, [kev_entry(f"CVE-2024-{i:04d}") for i in range(20)], "2026.01.14")

    with pytest.raises(kev.KevError, match="refusing"):
        load_feed(con, tmp_path, [kev_entry("CVE-2024-0001")], "2026.01.15")
    assert con.execute("SELECT count(*) FROM raw.kev").fetchone()[0] == 20


def test_failed_load_rolls_back(con, tmp_path, monkeypatch):
    load_feed(con, tmp_path, [kev_entry("CVE-2024-0001")], "2026.01.14")

    def broken_log(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(kev, "log_load", broken_log)
    with pytest.raises(RuntimeError):
        load_feed(con, tmp_path, [kev_entry("CVE-2024-0009")], "2026.01.15")

    # The DELETE and INSERT were undone together with the failed log write.
    assert con.execute("SELECT cve_id, catalog_version FROM raw.kev").fetchall() == [("CVE-2024-0001", "2026.01.14")]

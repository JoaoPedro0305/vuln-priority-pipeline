import re
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from tests.conftest import nvd_cve, nvd_doc, nvd_feed
from vulnprio import config
from vulnprio.download import make_session
from vulnprio.ingest import ingest_nvd
from vulnprio.sources import nvd


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)


def no_sleep(seconds):
    pass


def serve_feed(year, cves, modified="2026-01-15T03:00:00-05:00", meta=None):
    gz, real_meta = nvd_feed(cves, modified)
    responses.get(config.NVD_META_URL.format(year=year), body=meta or real_meta)
    responses.get(config.NVD_FEED_URL.format(year=year), body=gz)


def load_years(con, tmp_path, years):
    return nvd.sync_feeds(con, make_session(), years, tmp_path, record_sync=False)


def requests_to(url):
    return [call for call in responses.calls if call.request.url.split("?")[0] == url]


# --- metadata and verification ------------------------------------------------


def test_parse_meta_converts_to_utc_and_normalizes_the_hash():
    meta = nvd.parse_meta("lastModifiedDate:2026-10-09T03:01:30-04:00\r\nsize:123\r\ngzSize:45\r\nsha256:ABCDEF\r\n")
    assert meta == nvd.FeedMeta(last_modified=datetime(2026, 10, 9, 7, 1, 30), size=123, sha256="abcdef")


def test_parse_meta_rejects_garbage():
    with pytest.raises(nvd.NvdError, match="unreadable feed metadata"):
        nvd.parse_meta("<html>Service Unavailable</html>")


def test_verify_feed(tmp_path):
    gz, meta_text = nvd_feed([nvd_cve("CVE-2024-0001")])
    path = tmp_path / "feed.json.gz"
    path.write_bytes(gz)
    meta = nvd.parse_meta(meta_text)

    nvd.verify_feed(path, meta)  # matches
    with pytest.raises(nvd.NvdError, match="does not match"):
        nvd.verify_feed(path, nvd.FeedMeta(meta.last_modified, meta.size, "0" * 64))
    path.write_bytes(b"not gzip")
    with pytest.raises(nvd.NvdError, match="not a valid gzip"):
        nvd.verify_feed(path, meta)


def test_api_windows_respect_the_120_day_limit():
    start = datetime(2026, 1, 1)
    windows = nvd.api_windows(start, start + timedelta(days=300))

    assert [(end - begin).days for begin, end in windows] == [120, 120, 60]
    assert all(windows[i][1] == windows[i + 1][0] for i in range(len(windows) - 1))
    with pytest.raises(nvd.NvdError, match="empty time window"):
        nvd.api_windows(start, start)


# --- feeds --------------------------------------------------------------------


@responses.activate
def test_feed_load_extracts_the_fields(con, tmp_path):
    serve_feed(2024, [nvd_cve("CVE-2024-0001")])
    assert load_years(con, tmp_path, [2024]) == 1

    row = con.execute("""
        SELECT cve_id, vuln_status, description_en, cpes,
               metrics->'cvssMetricV31'->0->'cvssData'->>'baseScore',
               weaknesses->0->'description'->0->>'value',
               refs->0->'tags'->>0,
               published, last_modified
        FROM raw.nvd
    """).fetchone()
    assert row == (
        "CVE-2024-0001",
        "Analyzed",
        "A test.",  # English description only
        ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],  # vulnerable entries only, without repeats
        "9.8",
        "CWE-78",
        "Exploit",
        datetime(2024, 1, 15, 10, 0),
        datetime(2024, 2, 1),
    )
    # A partial load (chosen years) is not a complete sync.
    assert con.execute("SELECT count(*) FROM raw.nvd_sync").fetchone()[0] == 0


@responses.activate
def test_unchanged_feed_is_not_downloaded_again(con, tmp_path):
    serve_feed(2024, [nvd_cve("CVE-2024-0001")])
    load_years(con, tmp_path, [2024])
    load_years(con, tmp_path, [2024])

    assert len(requests_to(config.NVD_META_URL.format(year=2024))) == 2
    assert len(requests_to(config.NVD_FEED_URL.format(year=2024))) == 1


@responses.activate
def test_feed_that_never_matches_its_meta_is_refused(con, tmp_path):
    wrong_meta = "lastModifiedDate:2026-01-15T03:00:00-05:00\nsize:1\nsha256:" + "0" * 64
    serve_feed(2024, [nvd_cve("CVE-2024-0001")], meta=wrong_meta)

    with pytest.raises(nvd.NvdError, match="does not match"):
        load_years(con, tmp_path, [2024])
    # Fetched twice (NVD may have regenerated it in between), then refused.
    assert len(requests_to(config.NVD_FEED_URL.format(year=2024))) == 2
    assert con.execute("SELECT count(*) FROM raw.nvd").fetchone()[0] == 0


@responses.activate
def test_complete_sync_covers_up_to_the_latest_change_loaded(con, tmp_path):
    # The 2023 feed is weeks old: NVD only regenerates a feed when one of its CVEs changes.
    serve_feed(2023, [nvd_cve("CVE-2023-0001", "2025-11-20T10:00:00.000")], modified="2025-11-20T03:05:00-05:00")
    serve_feed(2024, [nvd_cve("CVE-2024-0001", "2026-01-15T07:30:00.000")], modified="2026-01-15T03:01:00-05:00")

    nvd.sync_feeds(con, make_session(), [2023, 2024], tmp_path, record_sync=True)

    assert con.execute("SELECT mode, covered_until, cve_count FROM raw.nvd_sync").fetchone() == (
        "feeds",
        datetime(2026, 1, 15, 7, 30),
        2,
    )
    assert nvd.watermark(con) == datetime(2026, 1, 15, 7, 30)


@responses.activate
def test_newer_version_wins_whatever_the_load_order(con, tmp_path):
    serve_feed(2024, [nvd_cve("CVE-2024-0001", "2024-03-01T00:00:00.000", vulnStatus="Modified")])
    serve_feed(2023, [nvd_cve("CVE-2024-0001", "2024-02-01T00:00:00.000", vulnStatus="Analyzed")])
    serve_feed(2025, [nvd_cve("CVE-2024-0001", "2024-04-01T00:00:00.000", vulnStatus="Rejected")])

    load_years(con, tmp_path, [2024])
    load_years(con, tmp_path, [2023])  # older version arrives later: ignored
    assert con.execute("SELECT vuln_status FROM raw.nvd").fetchone()[0] == "Modified"

    load_years(con, tmp_path, [2025])  # newer version: replaces it
    assert con.execute("SELECT count(*), any_value(vuln_status) FROM raw.nvd").fetchone() == (1, "Rejected")


@pytest.mark.parametrize(
    ("bad_cve", "message"),
    [
        (nvd_cve("CVE-2024-0002", "not a date"), "without a valid published/lastModified"),
        (nvd_cve("CVE-24-2"), "malformed CVE ids"),
        ({k: v for k, v in nvd_cve("CVE-2024-0002").items() if k != "vulnStatus"}, "without vulnStatus"),
    ],
)
@responses.activate
def test_invalid_feed_leaves_the_table_untouched(con, tmp_path, bad_cve, message):
    serve_feed(2023, [nvd_cve("CVE-2023-0001")])
    serve_feed(2024, [nvd_cve("CVE-2024-0001"), bad_cve])
    load_years(con, tmp_path, [2023])

    with pytest.raises(nvd.NvdError, match=message):
        load_years(con, tmp_path, [2024])
    assert con.execute("SELECT list(cve_id) FROM raw.nvd").fetchone()[0] == ["CVE-2023-0001"]
    assert con.execute("SELECT count(*) FROM raw.load_log").fetchone()[0] == 1


# --- API ----------------------------------------------------------------------


def api_pages(cves, page_size):
    """Answer API requests from `cves`, honouring startIndex like the real API."""

    def callback(request):
        start = int(parse_qs(urlparse(request.url).query)["startIndex"][0])
        page = cves[start : start + page_size]
        return 200, {}, nvd_doc(page, total=len(cves), start=start)

    return callback


@responses.activate
def test_fetch_api_pages_through_results_and_pauses_between_requests(tmp_path):
    cves = [nvd_cve(f"CVE-2026-000{i}") for i in range(5)]
    responses.add_callback(responses.GET, config.NVD_API_URL, callback=api_pages(cves, 2))
    pauses = []

    fetched = nvd.fetch_api(
        make_session(), datetime(2026, 1, 1), datetime(2026, 1, 2), tmp_path, page_size=2, sleep=pauses.append
    )

    assert fetched.cves == 5
    assert len(fetched.pages) == 3
    assert pauses == [nvd.API_DELAY, nvd.API_DELAY]
    query = parse_qs(urlparse(responses.calls[0].request.url).query)
    assert query["lastModStartDate"] == ["2026-01-01T00:00:00.000Z"]
    assert query["lastModEndDate"] == ["2026-01-02T00:00:00.000Z"]
    assert [parse_qs(urlparse(c.request.url).query)["startIndex"][0] for c in responses.calls] == ["0", "2", "4"]
    assert "apiKey" not in responses.calls[0].request.headers


@responses.activate
def test_api_key_goes_in_a_header_and_shortens_the_pause(tmp_path):
    cves = [nvd_cve(f"CVE-2026-000{i}") for i in range(3)]
    responses.add_callback(responses.GET, config.NVD_API_URL, callback=api_pages(cves, 2))
    pauses = []

    nvd.fetch_api(
        make_session(),
        datetime(2026, 1, 1),
        datetime(2026, 1, 2),
        tmp_path,
        api_key="secret-key",
        page_size=2,
        sleep=pauses.append,
    )

    request = responses.calls[0].request
    assert request.headers["apiKey"] == "secret-key"
    assert "secret-key" not in request.url
    assert pauses == [nvd.API_DELAY_WITH_KEY]


@responses.activate
def test_api_error_reports_the_nvd_message(tmp_path):
    responses.get(config.NVD_API_URL, status=404, headers={"message": "Date range cannot exceed 120 days."})

    with pytest.raises(nvd.NvdError, match="404 Date range cannot exceed 120 days"):
        nvd.fetch_api(make_session(), datetime(2026, 1, 1), datetime(2026, 1, 2), tmp_path, sleep=no_sleep)


@responses.activate
def test_api_load_keeps_the_latest_copy_of_a_repeated_cve(con, tmp_path):
    # The CVE changed while the pages were being read, so it appears twice.
    cves = [
        nvd_cve("CVE-2026-0001", "2026-01-01T10:00:00.000", vulnStatus="Received"),
        nvd_cve("CVE-2026-0002"),
        nvd_cve("CVE-2026-0001", "2026-01-01T11:00:00.000", vulnStatus="Analyzed"),
    ]
    # The fake server answers 2 CVEs per page whatever page size is asked for;
    # the client advances by what it actually received, like with the real API.
    responses.add_callback(responses.GET, config.NVD_API_URL, callback=api_pages(cves, 2))
    rows = nvd.sync_api(con, make_session(), datetime(2026, 1, 1), datetime(2026, 1, 2), tmp_path, sleep=no_sleep)

    assert rows == 2
    assert con.execute("SELECT vuln_status FROM raw.nvd WHERE cve_id = 'CVE-2026-0001'").fetchone()[0] == "Analyzed"
    assert con.execute("SELECT mode, covered_until, cve_count FROM raw.nvd_sync").fetchone() == (
        "api",
        datetime(2026, 1, 2),
        2,
    )


@responses.activate
def test_api_with_no_changes_still_records_the_sync(con, tmp_path):
    responses.get(config.NVD_API_URL, body=nvd_doc([]))

    assert nvd.sync_api(con, make_session(), datetime(2026, 1, 1), datetime(2026, 1, 2), tmp_path) == 0
    assert nvd.watermark(con) == datetime(2026, 1, 2)


# --- choosing between full and incremental -----------------------------------


@responses.activate
def test_ingest_nvd_picks_the_mode_from_the_last_sync(con, tmp_path):
    # Feeds exist for 2002 and 2003 when "now" is in 2003.
    serve_feed(2002, [nvd_cve("CVE-2002-0001", "2002-12-01T00:00:00.000")], modified="2002-12-01T03:00:00-05:00")
    serve_feed(2003, [nvd_cve("CVE-2003-0001", "2003-01-10T08:00:00.000")], modified="2003-01-10T03:00:00-05:00")
    responses.get(config.NVD_API_URL, body=nvd_doc([nvd_cve("CVE-2003-0002", "2003-01-11T00:00:00.000")]))
    now = datetime(2003, 1, 10, 12, 0)

    def run(**kwargs):
        return ingest_nvd(con, make_session(), landing_dir=tmp_path, sleep=no_sleep, **kwargs)

    assert run(now=now) == "feeds"  # first sync
    watermark = datetime(2003, 1, 10, 8, 0)
    assert nvd.watermark(con) == watermark

    assert run(now=now + timedelta(days=1)) == "api"  # recent sync: only the changes
    query = parse_qs(urlparse(requests_to(config.NVD_API_URL)[-1].request.url).query)
    assert query["lastModStartDate"] == ["2003-01-09T08:00:00.000Z"]  # one day of overlap
    assert con.execute("SELECT count(*) FROM raw.nvd").fetchone()[0] == 3

    assert run(now=now + timedelta(days=100)) == "feeds"  # too long ago: rebuild
    assert run(now=now + timedelta(days=101), full=True) == "feeds"
    assert run(now=now, years=[2003]) == "years"
    assert run(now=now, since=now.date()) == "since"


def test_ingest_nvd_rejects_years_without_a_feed(con, tmp_path):
    with pytest.raises(nvd.NvdError, match=re.escape("no NVD feed for [1999]")):
        ingest_nvd(con, make_session(), years=[1999], landing_dir=tmp_path, now=datetime(2026, 1, 1))

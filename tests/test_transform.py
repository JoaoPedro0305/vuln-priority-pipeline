"""The dbt project end to end: a small warehouse loaded with the real loaders,
then `dbt build` (models, data tests and unit tests) on it."""

from datetime import date
from decimal import Decimal

import pytest
import responses

from tests.conftest import LOADED_AT, as_downloaded, epss_file, kev_entry, kev_feed, nvd_cve, nvd_feed
from vulnprio import config
from vulnprio.download import make_session
from vulnprio.sources import epss, kev, nvd
from vulnprio.transform import TransformError, run_dbt
from vulnprio.warehouse import connect

SSVC_ACTIVE = [
    {
        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
        "ssvcData": {
            "timestamp": "2026-01-10T12:00:00.000000Z",
            "id": "CVE-2024-0003",
            "options": [{"exploitation": "active"}, {"automatable": "yes"}, {"technicalImpact": "total"}],
            "role": "CISA Coordinator",
            "version": "2.0.3",
        },
    }
]
CNA_ONLY = {
    "cvssMetricV31": [
        {
            "source": "cna@example.test",
            "type": "Secondary",
            "cvssData": {"version": "3.1", "baseScore": 5.3, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/x"},
        }
    ],
    "ssvcV203": SSVC_ACTIVE,
}


@pytest.fixture
def warehouse(tmp_path):
    path = tmp_path / "warehouse.duckdb"
    con = connect(path)

    kev_path = tmp_path / "kev.json"
    kev_path.write_bytes(kev_feed([kev_entry("CVE-2024-0001", vendorProject=" Acme ", product="Widget")]))
    kev.load(con, kev.parse(kev_path.read_bytes()), as_downloaded(kev_path), LOADED_AT)

    rows = [("CVE-2024-0001", 0.94, 0.999), ("CVE-2024-0003", 0.02, 0.6)]
    epss.load(con, as_downloaded(epss_file(tmp_path / "epss.csv.gz", rows)), LOADED_AT, min_rows=1)

    cves = [
        nvd_cve("CVE-2024-0001"),
        nvd_cve("CVE-2024-0002", vulnStatus="Rejected"),
        nvd_cve("CVE-2024-0003", metrics=CNA_ONLY, configurations=[], references=[], weaknesses=[]),
    ]
    gz, meta = nvd_feed(cves)
    with responses.RequestsMock() as mock:
        mock.get(config.NVD_META_URL.format(year=2024), body=meta)
        mock.get(config.NVD_FEED_URL.format(year=2024), body=gz)
        nvd.sync_feeds(con, make_session(), [2024], tmp_path, record_sync=False)

    con.close()
    return path


def test_build_produces_the_cves_mart(warehouse, tmp_path):
    run_dbt("build", warehouse=warehouse, target_dir=tmp_path / "dbt")

    con = connect(warehouse)
    rows = con.execute("""
        SELECT cve_id, vendor, product, cvss_score, cvss3_provider, in_kev, has_exploit_reference,
               ssvc_exploitation, epss, epss_date, cwe_ids, products
        FROM marts.cves ORDER BY cve_id
    """).fetchall()
    con.close()

    assert rows == [
        (
            "CVE-2024-0001",
            "Acme",  # KEV's name, trimmed
            "Widget",
            Decimal("9.8"),
            "nvd",
            True,
            True,
            None,
            0.94,
            date(2026, 1, 15),
            ["CWE-78"],
            ["acme:widget"],
        ),
        # CVE-2024-0002 is rejected: not in the mart.
        (
            "CVE-2024-0003",
            None,
            None,
            Decimal("5.3"),
            "cna",
            False,
            False,
            "active",
            0.02,
            date(2026, 1, 15),
            [],
            [],
        ),
    ]


def test_failing_data_test_fails_the_transform(warehouse, tmp_path):
    con = connect(warehouse)
    con.execute("UPDATE raw.nvd SET vuln_status = 'Unknown status' WHERE cve_id = 'CVE-2024-0003'")
    con.close()

    with pytest.raises(TransformError, match="dbt build failed"):
        run_dbt("build", warehouse=warehouse, target_dir=tmp_path / "dbt")


def test_missing_warehouse_is_reported(tmp_path):
    with pytest.raises(TransformError, match="no warehouse"):
        run_dbt("build", warehouse=tmp_path / "missing.duckdb")

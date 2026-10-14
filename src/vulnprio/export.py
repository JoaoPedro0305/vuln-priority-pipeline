"""Export the marts the dashboard shows as small JSON files.

The site (site/) is static: it reads these files and nothing else, so it can
be served by GitHub Pages with no server and no access to the warehouse.
"""

import json
import logging
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import duckdb

from vulnprio.warehouse import utc_now

log = logging.getLogger(__name__)

QUERIES = {
    "status": """
        SELECT
            (SELECT max(loaded_at) FROM raw.load_log) AS updated_at,
            (SELECT count(*) FROM marts.cves) AS cves,
            (SELECT count(*) FROM raw.kev) AS kev,
            (SELECT max(catalog_version) FROM raw.kev) AS kev_version,
            (SELECT max(epss_date) FROM marts.cves) AS epss_date,
            (SELECT count(DISTINCT score_date) FROM raw.epss) AS epss_days,
            (SELECT max(covered_until) FROM raw.nvd_sync) AS nvd_covered_until
    """,
    "priorities": """
        SELECT priority_rank, cve_id, vendor, product, published::DATE AS published, remediation,
               ssvc_decision, priority_reason, in_kev, kev_ransomware, epss, epss_percentile, cvss_score
        FROM marts.cve_priorities
        ORDER BY priority_rank
        LIMIT 100
    """,
    "not_yet_exploited": """
        SELECT priority_rank, cve_id, vendor, product, published::DATE AS published, remediation,
               ssvc_decision, priority_reason, epss, epss_percentile, cvss_score
        FROM marts.cve_priorities
        WHERE NOT in_kev
        ORDER BY priority_rank
        LIMIT 100
    """,
    "recent_kev": """
        SELECT c.cve_id, c.vendor, c.product, c.kev_date_added, c.kev_ransomware, c.published::DATE AS published,
               c.epss, c.epss_percentile, c.cvss_score, c.cvss_severity, p.priority_rank
        FROM marts.cves AS c
        INNER JOIN marts.cve_priorities AS p USING (cve_id)
        WHERE c.kev_date_added >= (SELECT max(date_added) FROM staging.stg_kev) - 60  -- the last 60 days of the catalog
        ORDER BY c.kev_date_added DESC, c.cve_id
    """,
    "backtest_coverage": """
        SELECT strategy, budget, coverage, efficiency, budget_share, exploited, cycles
        FROM backtest.backtest_coverage ORDER BY strategy, budget
    """,
    "backtest_by_period": """
        SELECT period, strategy, budget, coverage, exploited
        FROM backtest.backtest_by_period WHERE budget = 1000 ORDER BY period, strategy
    """,
    "backtest_by_year": "SELECT year, strategy, coverage, exploited FROM backtest.backtest_by_year ORDER BY year",
    "backtest_reach": "SELECT reach, count(*) AS kev_additions FROM backtest.backtest_reach GROUP BY reach",
    "cvss_sources": """
        SELECT year(published) AS year, count(*) AS cves,
               round(avg((cvss3_provider = 'nvd')::INT), 3) AS nvd,
               round(avg((cvss3_provider = 'cna')::INT), 3) AS cna,
               round(avg((cvss3_provider = 'other')::INT), 3) AS other,
               round(avg((cvss3_score IS NULL)::INT), 3) AS none
        FROM marts.cves
        WHERE year(published) >= 2018
        GROUP BY 1 ORDER BY 1
    """,
    "assets": """
        SELECT asset, location, publicly_exposed, mission_impact, packages, direct_packages,
               vulnerable_packages, findings, in_kev, act_or_attend, without_fix, shortest_deadline_days,
               scanned_at
        FROM assets.asset_summary ORDER BY findings DESC, asset
    """,
    "upgrades": """
        SELECT asset, package, version, upgrade_to, is_direct, vulnerabilities, without_fix, in_kev,
               ssvc_decision, deadline_days, most_urgent
        FROM assets.asset_upgrades ORDER BY priority_rank
    """,
}


def _plain(value):
    """JSON-friendly values: dates as ISO text, decimals as numbers."""
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def query(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    cursor = con.execute(sql)
    columns = [d[0] for d in cursor.description]
    return [{c: _plain(v) for c, v in zip(columns, row, strict=True)} for row in cursor.fetchall()]


def export(con: duckdb.DuckDBPyConnection, out_dir: Path) -> list[Path]:
    """Write one JSON file per dataset. Missing tables (e.g. no backtest yet) give empty lists."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, sql in QUERIES.items():
        try:
            rows = query(con, sql)
        except duckdb.CatalogException as err:
            log.warning("export %s: %s; writing an empty list", name, str(err).splitlines()[0])
            rows = []
        data = rows[0] if name == "status" and rows else rows
        if name == "status":
            data = {**data, "exported_at": utc_now().isoformat(timespec="seconds")}
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        written.append(path)
    log.info("exported %d datasets to %s", len(written), out_dir)
    return written


ALERTS_SQL = """
    SELECT alert_key, asset, package, version, upgrade_to, fixed_in, vuln_id, cve_id, summary, in_kev,
           kev_date_added, ssvc_decision, remediation, remediation_days, epss, priority_reason
    FROM assets.asset_alerts
    ORDER BY priority_rank
"""


def export_alerts(con: duckdb.DuckDBPyConnection, path: Path) -> list[dict]:
    """Write the alerts that should have an open GitHub issue (read by vulnprio.issues)."""
    rows = query(con, ALERTS_SQL)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    return rows

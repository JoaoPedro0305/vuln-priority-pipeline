"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The feed is one JSON file with the whole catalog: every CVE that CISA has
evidence of being exploited in the wild. In this project KEV is the ground
truth for "this vulnerability was exploited", and `dateAdded` says when.

Text fields are kept exactly as published (some names have stray spaces);
trimming happens in the dbt staging models.
"""

import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime

import duckdb

from vulnprio.download import Downloaded
from vulnprio.warehouse import log_load, transaction

log = logging.getLogger(__name__)

SOURCE = "kev"
REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")

# Entries are almost never removed from KEV. A new catalog much smaller than the
# one already loaded means a broken feed, not a real change, so it is refused.
MIN_SHARE_OF_CURRENT = 0.95


INSERT_SQL = """
    INSERT INTO raw.kev
    SELECT
        e.cve_id, e.vendor_project, e.product, e.vulnerability_name, e.date_added::DATE,
        e.short_description, e.required_action, e.due_date::DATE, e.known_ransomware_use,
        e.notes, e.cwes, $2, $3
    FROM (
        SELECT unnest(from_json($1, '[{
            "cve_id": "VARCHAR", "vendor_project": "VARCHAR", "product": "VARCHAR",
            "vulnerability_name": "VARCHAR", "date_added": "VARCHAR", "short_description": "VARCHAR",
            "required_action": "VARCHAR", "due_date": "VARCHAR", "known_ransomware_use": "VARCHAR",
            "notes": "VARCHAR", "cwes": ["VARCHAR"]
        }]')) AS e
    )
"""


class KevError(Exception):
    pass


@dataclass(frozen=True)
class KevCatalog:
    version: str
    rows: list[dict]  # raw.kev columns, without catalog_version/loaded_at


def parse(raw: bytes) -> KevCatalog:
    """Parse and validate the feed. Raises KevError listing every problem found."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise KevError(f"feed is not valid JSON: {err}") from err

    version = data.get("catalogVersion") if isinstance(data, dict) else None
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(version, str) or not isinstance(entries, list):
        raise KevError("feed has no catalogVersion or vulnerabilities list")

    problems = []
    if data.get("count") != len(entries):
        problems.append(f"header count is {data.get('count')} but the file has {len(entries)} entries")

    rows = []
    seen = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"entry {i}: not an object")
            continue
        missing = [field for field in REQUIRED if not entry.get(field)]
        if missing:
            problems.append(f"entry {i}: missing {', '.join(missing)}")
            continue
        cve_id = entry["cveID"]
        if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id):
            problems.append(f"entry {i}: malformed CVE id {cve_id!r}")
            continue
        if cve_id in seen:
            problems.append(f"{cve_id} appears more than once")
            continue
        seen.add(cve_id)
        try:
            date_added = date.fromisoformat(entry["dateAdded"])
            due_date = date.fromisoformat(entry["dueDate"]) if entry.get("dueDate") else None
        except (TypeError, ValueError) as err:
            problems.append(f"{cve_id}: bad date ({err})")
            continue

        rows.append(
            {
                "cve_id": cve_id,
                "vendor_project": entry["vendorProject"],
                "product": entry["product"],
                "vulnerability_name": entry["vulnerabilityName"],
                "date_added": date_added.isoformat(),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": due_date.isoformat() if due_date else None,
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "notes": entry.get("notes"),
                "cwes": entry.get("cwes") or [],
            }
        )

    if problems:
        shown = "; ".join(problems[:10])
        raise KevError(f"{len(problems)} problem(s) in KEV catalog {version}: {shown}")
    if not rows:
        raise KevError(f"KEV catalog {version} is empty")
    return KevCatalog(version=version, rows=rows)


def load(
    con: duckdb.DuckDBPyConnection,
    catalog: KevCatalog,
    downloaded: Downloaded,
    loaded_at: datetime,
) -> int:
    """Replace raw.kev with `catalog` in one transaction. Returns the row count."""
    current = con.execute("SELECT count(*) FROM raw.kev").fetchone()[0]
    if len(catalog.rows) < current * MIN_SHARE_OF_CURRENT:
        raise KevError(
            f"KEV catalog {catalog.version} has {len(catalog.rows)} entries, "
            f"far fewer than the {current} already loaded; refusing to replace them"
        )

    with transaction(con):
        con.execute("DELETE FROM raw.kev")
        # All rows go in as one JSON parameter: one statement instead of one per
        # row (executemany took ~20 s for the 1,700 rows; this takes ~20 ms).
        con.execute(INSERT_SQL, [json.dumps(catalog.rows), catalog.version, loaded_at])
        log_load(con, SOURCE, catalog.version, len(catalog.rows), downloaded, loaded_at)

    log.info("KEV catalog %s loaded: %d CVEs", catalog.version, len(catalog.rows))
    return len(catalog.rows)

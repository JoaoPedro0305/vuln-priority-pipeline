import gzip
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

from vulnprio.download import Downloaded
from vulnprio.warehouse import connect

LOADED_AT = datetime(2026, 1, 15, 12, 0)


@pytest.fixture
def con(tmp_path):
    con = connect(tmp_path / "warehouse.duckdb")
    yield con
    con.close()


def as_downloaded(path: Path, url: str = "https://example.test/file") -> Downloaded:
    data = path.read_bytes()
    return Downloaded(path=path, url=url, sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def kev_entry(cve_id: str, **overrides) -> dict:
    entry = {
        "cveID": cve_id,
        "vendorProject": "Acme",
        "product": "Widget",
        "vulnerabilityName": "Acme Widget Remote Code Execution",
        "dateAdded": "2024-03-01",
        "shortDescription": "A test vulnerability.",
        "requiredAction": "Apply updates.",
        "dueDate": "2024-03-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": ["CWE-94"],
    }
    entry.update(overrides)
    return entry


def kev_feed(entries: list[dict], version: str = "2026.01.15", count: int | None = None) -> bytes:
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": version,
            "dateReleased": "2026-01-15T12:00:00.000Z",
            "count": len(entries) if count is None else count,
            "vulnerabilities": entries,
        }
    ).encode("utf-8")


def epss_file(
    path: Path,
    rows: list[tuple],
    *,
    comment: str | None = "#model_version:v2025.03.14,score_date:2026-01-15T12:55:00Z",
    columns: str = "cve,epss,percentile",
) -> Path:
    """Write a daily EPSS file in any of its historical formats."""
    lines = [comment] if comment else []
    lines.append(columns)
    lines += [",".join(str(value) for value in row) for row in rows]
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def epss_rows(n: int) -> list[tuple]:
    return [(f"CVE-2024-{i:05d}", 0.001 + i / (n * 2), i / n) for i in range(n)]

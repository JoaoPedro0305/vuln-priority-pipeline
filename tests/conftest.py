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


def nvd_cve(cve_id: str, last_modified: str = "2024-02-01T00:00:00.000", **overrides) -> dict:
    cve = {
        "id": cve_id,
        "sourceIdentifier": "cna@example.test",
        "published": "2024-01-15T10:00:00.000",
        "lastModified": last_modified,
        "vulnStatus": "Analyzed",
        "cveTags": [],
        "descriptions": [{"lang": "es", "value": "Una prueba."}, {"lang": "en", "value": "A test."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "weaknesses": [
            {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-78"}]}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
                            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.test/poc", "source": "cna@example.test", "tags": ["Exploit"]}],
    }
    cve.update(overrides)
    return cve


def nvd_doc(cves: list[dict], total: int | None = None, start: int = 0) -> bytes:
    """A feed or API page: both have the same shape."""
    return json.dumps(
        {
            "resultsPerPage": len(cves),
            "startIndex": start,
            "totalResults": len(cves) if total is None else total,
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": [{"cve": cve} for cve in cves],
        }
    ).encode("utf-8")


def nvd_feed(cves: list[dict], modified: str = "2026-01-15T03:00:00-05:00") -> tuple[bytes, str]:
    """A gzipped yearly feed and its matching .meta text."""
    raw = nvd_doc(cves)
    meta = (
        f"lastModifiedDate:{modified}\r\nsize:{len(raw)}\r\nzipSize:0\r\ngzSize:0\r\n"
        f"sha256:{hashlib.sha256(raw).hexdigest().upper()}\r\n"
    )
    return gzip.compress(raw), meta

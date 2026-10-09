"""The DuckDB warehouse: one file, no server.

DuckDB runs inside the Python process, like SQLite, but stores data by column,
which makes aggregations over millions of rows (EPSS history) fast.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from vulnprio.config import WAREHOUSE_PATH
from vulnprio.download import Downloaded

SCHEMA_SQL = Path(__file__).with_name("schema.sql")


def connect(path: Path | str | None = None) -> duckdb.DuckDBPyConnection:
    """Open (or create) the warehouse and make sure the raw tables exist."""
    path = Path(path or WAREHOUSE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    con.execute(SCHEMA_SQL.read_text(encoding="utf-8"))
    return con


def utc_now() -> datetime:
    """Current UTC time without tzinfo, as stored in TIMESTAMP columns."""
    return datetime.now(UTC).replace(tzinfo=None)


@contextmanager
def transaction(con: duckdb.DuckDBPyConnection) -> Iterator[None]:
    """All statements inside commit together, or none of them do."""
    con.begin()
    try:
        yield
    except BaseException:
        con.rollback()
        raise
    con.commit()


def log_load(
    con: duckdb.DuckDBPyConnection,
    source: str,
    version: str,
    row_count: int,
    downloaded: Downloaded,
    loaded_at: datetime,
) -> None:
    con.execute(
        "INSERT INTO raw.load_log VALUES (?, ?, ?, ?, ?, ?)",
        [source, version, row_count, downloaded.url, downloaded.sha256, loaded_at],
    )

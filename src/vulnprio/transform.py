"""Run the dbt project (the T of ELT) against the warehouse.

`dbt build` runs every model and its tests in dependency order: a model whose
tests fail stops everything built on top of it.
"""

import logging
import os
from pathlib import Path

from dbt.cli.main import dbtRunner

from vulnprio import config

log = logging.getLogger(__name__)


class TransformError(Exception):
    pass


def run_dbt(
    command: str = "build",
    *,
    warehouse: Path | None = None,
    select: str | None = None,
    target_dir: Path | None = None,
) -> None:
    """Run a dbt command (build, run, test, docs generate...) on `warehouse`."""
    warehouse = Path(warehouse or config.WAREHOUSE_PATH).resolve()
    if not warehouse.exists():
        raise TransformError(f"no warehouse at {warehouse}; run `vulnprio ingest all` first")

    args = [*command.split(), "--project-dir", str(config.DBT_DIR), "--profiles-dir", str(config.DBT_DIR)]
    if select:
        args += ["--select", select]
    if target_dir:
        args += ["--target-path", str(target_dir), "--log-path", str(target_dir / "logs")]

    # profiles.yml reads the warehouse path from this variable.
    previous = os.environ.get("VULNPRIO_WAREHOUSE")
    os.environ["VULNPRIO_WAREHOUSE"] = str(warehouse)
    try:
        result = dbtRunner().invoke(args)
    finally:
        if previous is None:
            os.environ.pop("VULNPRIO_WAREHOUSE", None)
        else:
            os.environ["VULNPRIO_WAREHOUSE"] = previous

    if not result.success:
        raise TransformError(f"dbt {command} failed") from result.exception

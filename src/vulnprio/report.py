"""Backtest report: the coverage table and two charts for the README."""

from pathlib import Path

import duckdb
import matplotlib

matplotlib.use("Agg")  # files only, no window
import matplotlib.pyplot as plt  # noqa: E402

# label, colour, drawn on the coverage chart
STRATEGIES = {
    "priority": ("This project: SSVC act/attend, then EPSS", "#1b5e20", True),
    "epss": ("EPSS alone", "#1565c0", True),
    "track_star_first": ("Act, attend, track*, then EPSS (dropped)", "#6a1b9a", False),
    "timeline_first": ("BOD 26-04 timeline first (dropped)", "#9e9d24", True),
    "cvss": ("CVSS alone", "#c62828", True),
    "random": ("Random", "#9e9e9e", True),
}
TABLE_BUDGETS = [100, 500, 1000, 5000, 10000]


class ReportError(Exception):
    pass


def _fetch(con: duckdb.DuckDBPyConnection, sql: str) -> list[tuple]:
    try:
        return con.execute(sql).fetchall()
    except duckdb.CatalogException as err:
        raise ReportError("no backtest tables yet; run: vulnprio transform") from err


def coverage_table(con: duckdb.DuckDBPyConnection) -> str:
    """Coverage per strategy and budget, as a Markdown table."""
    rows = _fetch(con, "SELECT strategy, budget, coverage, budget_share, cycles FROM backtest.backtest_coverage")
    if not rows:
        raise ReportError("the backtest is empty: load EPSS history with `vulnprio ingest epss --monthly-since`")
    coverage = {(strategy, budget): value for strategy, budget, value, _, _ in rows}
    shares = {budget: share for _, budget, _, share, _ in rows}
    budgets = [b for b in TABLE_BUDGETS if b in shares]

    header = "| Strategy | " + " | ".join(f"{b:,} ({shares[b]:.2%})" for b in budgets) + " |"
    lines = [header, "|---|" + "---:|" * len(budgets)]
    for strategy, (label, _, _) in STRATEGIES.items():
        cells = " | ".join(f"{coverage[(strategy, b)]:.1%}" for b in budgets)
        lines.append(f"| {label} | {cells} |")
    return "\n".join(lines)


def period_table(con: duckdb.DuckDBPyConnection, budget: int = 1000) -> str:
    """Coverage per strategy in each period, at one budget, as a Markdown table."""
    rows = _fetch(
        con,
        f"SELECT period, strategy, coverage, exploited FROM backtest.backtest_by_period WHERE budget = {int(budget)}",  # noqa: S608
    )
    periods = sorted({period for period, *_ in rows}, key=lambda p: not p.startswith("before"))
    coverage = {(period, strategy): value for period, strategy, value, _ in rows}
    exploited = {period: n for period, _, _, n in rows}

    header = "| Strategy | " + " | ".join(f"{p} ({exploited[p]} exploited)" for p in periods) + " |"
    lines = [header, "|---|" + "---:|" * len(periods)]
    for strategy, (label, _, _) in STRATEGIES.items():
        cells = " | ".join(f"{coverage[(p, strategy)]:.1%}" for p in periods)
        lines.append(f"| {label} | {cells} |")
    return "\n".join(lines)


def plot_coverage(con: duckdb.DuckDBPyConnection, path: Path) -> Path:
    rows = _fetch(con, "SELECT strategy, budget, coverage FROM backtest.backtest_coverage ORDER BY budget")
    cycles, exploited = _fetch(con, "SELECT any_value(cycles), any_value(exploited) FROM backtest.backtest_coverage")[0]

    fig, ax = plt.subplots(figsize=(8, 4.8), dpi=150)
    for strategy, (label, color, drawn) in STRATEGIES.items():
        if not drawn:
            continue
        points = [(budget, coverage * 100) for s, budget, coverage in rows if s == strategy]
        ax.plot(*zip(*points, strict=True), marker="o", markersize=3.5, linewidth=2, color=color, label=label)

    ax.set_xscale("log")
    ax.set_xlabel("CVEs patched per month (log scale)")
    ax.set_ylabel("Exploited CVEs caught (%)")
    ax.set_title(
        f"Which CVEs entered CISA KEV in the next 30 days?\n{exploited} exploited CVEs over {cycles} monthly cycles",
        fontsize=11,
        loc="left",
    )
    ax.grid(True, which="major", alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def plot_by_year(con: duckdb.DuckDBPyConnection, path: Path) -> Path:
    rows = _fetch(con, "SELECT year, strategy, coverage, exploited FROM backtest.backtest_by_year ORDER BY year")
    years = sorted({year for year, *_ in rows})
    exploited = {year: n for year, _, _, n in rows}
    shown = ["priority", "epss", "cvss"]
    width = 0.8 / len(shown)

    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150)
    for i, strategy in enumerate(shown):
        label, color, _ = STRATEGIES[strategy]
        values = {year: coverage * 100 for year, s, coverage, _ in rows if s == strategy}
        positions = [x + (i - (len(shown) - 1) / 2) * width for x in range(len(years))]
        ax.bar(positions, [values.get(y, 0) for y in years], width=width, color=color, label=label)

    ax.set_xticks(range(len(years)), [f"{y}\n({exploited[y]} exploited)" for y in years])
    ax.set_ylabel("Exploited CVEs caught (%)")
    ax.set_title("Coverage per year, patching 1,000 CVEs a month", fontsize=11, loc="left")
    ax.grid(True, axis="y", alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def reach_summary(con: duckdb.DuckDBPyConnection) -> list[tuple[str, int]]:
    return _fetch(con, "SELECT reach, count(*) FROM backtest.backtest_reach GROUP BY reach ORDER BY count(*) DESC")

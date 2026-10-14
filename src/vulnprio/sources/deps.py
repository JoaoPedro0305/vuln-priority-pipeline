"""Dependencies of real systems, matched against OSV.dev.

For each asset in assets.toml:

1. Fetch its requirement files (from GitHub or a local folder), following
   `-r` / `-c` includes. The files are untrusted input: only package
   requirements and includes inside the same tree are accepted; options that
   point pip elsewhere (--index-url, --find-links, -e, URLs) are refused.
2. Resolve the full dependency set, transitive packages included, with
   `pip install --dry-run --report`: for Linux and the asset's Python version,
   wheels only, so nothing is installed and no package code runs. A package
   published only as source needs its build script run to know its own
   dependencies; that is allowed only for assets marked trust_build_scripts,
   and then pip resolves for the running interpreter and platform.
3. Ask OSV.dev which known vulnerabilities affect each (package, version), and
   fetch the details of each vulnerability (cached by its "modified" time).
4. Group advisories that describe the same flaw (GHSA, PYSEC, CVE aliases) and
   compute the first version that fixes it.
"""

import json
import logging
import posixpath
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import duckdb
import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from vulnprio.download import TIMEOUT
from vulnprio.warehouse import transaction

log = logging.getLogger(__name__)

SOURCE = "deps"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
OSV_BATCH_SIZE = 1000  # the API limit per request
RESOLVE_TIMEOUT = 300  # seconds for pip to resolve one asset

# A modern Linux accepts wheels for glibc 2.17 to 2.39.
LINUX_PLATFORMS = [f"manylinux_2_{minor}_x86_64" for minor in range(39, 16, -1)]

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
REF = re.compile(r"[A-Za-z0-9_./-]+")
PYTHON = re.compile(r"3\.\d{1,2}")
INCLUDE = re.compile(r"^(-r|--requirement|-c|--constraint)(?:\s+|=)(\S+)$")
HASH_OPTION = re.compile(r"\s+--hash[=\s]\S+")


class DepsError(Exception):
    pass


# --- assets ------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    name: str
    requirements: tuple[str, ...]
    python: str
    publicly_exposed: str
    mission_impact: str
    trust_build_scripts: bool = False
    repo: str | None = None  # "owner/name" on GitHub
    ref: str | None = None
    path: Path | None = None  # a local folder instead

    @property
    def location(self) -> str:
        return f"github:{self.repo}@{self.ref}" if self.repo else f"local:{self.path.as_posix()}"


def load_assets(config_path: Path) -> list[Asset]:
    """Read and validate assets.toml. Local paths are relative to its folder."""
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as err:
        raise DepsError(f"cannot read {config_path}: {err}") from err

    assets = []
    for i, entry in enumerate(data.get("asset", [])):
        where = f"{config_path.name}, asset {i + 1}"
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise DepsError(f"{where}: missing name")
        if bool(entry.get("repo")) == bool(entry.get("path")):
            raise DepsError(f"{where} ({name}): give either repo (GitHub) or path (local), not both")
        requirements = entry.get("requirements")
        if not requirements or not all(isinstance(r, str) for r in requirements):
            raise DepsError(f"{where} ({name}): requirements must be a list of files")
        python = str(entry.get("python", "3.13"))
        exposed = entry.get("publicly_exposed")
        mission = entry.get("mission_impact")
        if not PYTHON.fullmatch(python):
            raise DepsError(f"{where} ({name}): python must look like 3.13")
        if exposed not in ("yes", "no"):
            raise DepsError(f'{where} ({name}): publicly_exposed must be "yes" or "no"')
        if mission not in ("low", "medium", "high"):
            raise DepsError(f'{where} ({name}): mission_impact must be "low", "medium" or "high"')

        trust = entry.get("trust_build_scripts", False)
        if not isinstance(trust, bool):
            raise DepsError(f"{where} ({name}): trust_build_scripts must be true or false")
        repo = entry.get("repo")
        ref = entry.get("ref", "main")
        if repo and not (REPO.fullmatch(repo) and REF.fullmatch(ref) and ".." not in ref):
            raise DepsError(f"{where} ({name}): invalid repo or ref")
        assets.append(
            Asset(
                name=name.strip(),
                requirements=tuple(_safe_relative(r, where) for r in requirements),
                python=python,
                publicly_exposed=exposed,
                mission_impact=mission,
                trust_build_scripts=trust,
                repo=repo,
                ref=ref if repo else None,
                path=None if repo else (config_path.parent / entry["path"]),
            )
        )

    names = [a.name for a in assets]
    if len(set(names)) != len(names):
        raise DepsError(f"{config_path.name}: asset names must be unique")
    if not assets:
        raise DepsError(f"{config_path.name}: no [[asset]] entries")
    return assets


def _safe_relative(path: str, where: str) -> str:
    """Normalize a path inside the asset's tree; refuse absolute paths and '..' escapes."""
    normalized = posixpath.normpath(path.replace("\\", "/"))
    if normalized.startswith(("/", "../")) or normalized == ".." or ":" in normalized:
        raise DepsError(f"{where}: {path!r} points outside the asset")
    return normalized


# --- requirement files ---------------------------------------------------------


def check_requirements(text: str, filename: str) -> list[str]:
    """Validate a requirements file. Returns the files it includes (-r / -c)."""
    includes = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split(" #", 1)[0].strip()
        line = HASH_OPTION.sub("", line)  # pip-compile --generate-hashes output
        if not line or line.startswith("#"):
            continue
        where = f"{filename}:{number}"
        if line.startswith("-"):
            match = INCLUDE.match(line)
            if not match:
                raise DepsError(f"{where}: option not allowed in a scanned file: {line!r}")
            base = posixpath.dirname(filename)
            includes.append(_safe_relative(posixpath.join(base, match.group(2)), where))
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement as err:
            raise DepsError(f"{where}: not a package requirement: {line!r} ({err})") from err
        if requirement.url:
            raise DepsError(f"{where}: direct URL requirements are not allowed: {line!r}")
    return includes


def fetch_requirements(session: requests.Session, asset: Asset, dest: Path) -> list[Path]:
    """Copy the asset's requirement files (and their includes) into `dest`, validated."""
    pending = list(asset.requirements)
    seen: set[str] = set()
    entry_points = []
    while pending:
        relative = pending.pop(0)
        if relative in seen:
            continue
        seen.add(relative)
        if len(seen) > 50:
            raise DepsError(f"{asset.name}: more than 50 requirement files")

        if asset.repo:
            url = GITHUB_RAW_URL.format(repo=asset.repo, ref=asset.ref, path=relative)
            response = session.get(url, timeout=TIMEOUT)
            if response.status_code == 404:
                raise DepsError(f"{asset.name}: {relative} not found in {asset.repo}@{asset.ref}")
            response.raise_for_status()
            text = response.text
        else:
            try:
                text = (asset.path / relative).read_text(encoding="utf-8")
            except OSError as err:
                raise DepsError(f"{asset.name}: cannot read {relative}: {err}") from err

        pending += check_requirements(text, relative)
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        if relative in asset.requirements:
            entry_points.append(target)
    return entry_points


# --- resolution ----------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    name: str  # canonical (PEP 503) name
    version: str
    direct: bool


def resolve(asset: Asset, files: list[Path], report_path: Path) -> list[Package]:
    """Resolve the full dependency set with pip, without installing anything."""
    command = [
        sys.executable, "-m", "pip", "install",
        "--dry-run", "--quiet", "--isolated", "--disable-pip-version-check", "--no-input",
        "--ignore-installed",
        "--report", str(report_path),
    ]  # fmt: skip
    if not asset.trust_build_scripts:
        command += [
            "--only-binary=:all:",  # wheels only: no setup.py, no package code runs
            *[arg for platform in LINUX_PLATFORMS for arg in ("--platform", platform)],
            "--python-version", asset.python,
            "--implementation", "cp",
        ]  # fmt: skip
    for file in files:
        command += ["-r", str(file)]

    result = subprocess.run(command, capture_output=True, text=True, timeout=RESOLVE_TIMEOUT, check=False)  # noqa: S603
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise DepsError(f"{asset.name}: pip could not resolve the dependencies: {' '.join(detail[-3:])}")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    return sorted(
        {
            Package(
                name=canonicalize_name(item["metadata"]["name"]),
                version=item["metadata"]["version"],
                direct=bool(item.get("requested")),
            )
            for item in report["install"]
        },
        key=lambda p: p.name,
    )


# --- OSV -----------------------------------------------------------------------


def query_osv(session: requests.Session, packages: list[Package]) -> dict[tuple[str, str], dict[str, str]]:
    """{(package, version): {vulnerability id: modified}} for the affected packages."""
    found: dict[tuple[str, str], dict[str, str]] = {}
    for start in range(0, len(packages), OSV_BATCH_SIZE):
        batch = packages[start : start + OSV_BATCH_SIZE]
        queries = [{"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version} for p in batch]
        response = session.post(OSV_QUERYBATCH_URL, json={"queries": queries}, timeout=TIMEOUT)
        response.raise_for_status()
        results = response.json().get("results")
        if not isinstance(results, list) or len(results) != len(batch):
            raise DepsError("OSV querybatch returned an unexpected number of results")
        for package, result in zip(batch, results, strict=True):
            vulns = {v["id"]: v.get("modified", "") for v in result.get("vulns", [])}
            if vulns:
                found[(package.name, package.version)] = vulns
    return found


def fetch_vulnerabilities(
    con: duckdb.DuckDBPyConnection, session: requests.Session, wanted: dict[str, str], loaded_at: datetime
) -> int:
    """Store the details of OSV vulnerabilities not cached yet (or modified since). Returns how many."""
    cached = dict(con.execute("SELECT osv_id, modified FROM raw.osv_vulns").fetchall())
    stale = sorted(osv_id for osv_id, modified in wanted.items() if cached.get(osv_id) != modified)
    for osv_id in stale:
        response = session.get(OSV_VULN_URL.format(id=osv_id), timeout=TIMEOUT)
        response.raise_for_status()
        vuln = response.json()
        aliases = sorted({vuln.get("id", osv_id), *vuln.get("aliases", [])})
        severity = {s.get("type"): s.get("score") for s in vuln.get("severity", [])}
        con.execute(
            "INSERT OR REPLACE INTO raw.osv_vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                osv_id,
                vuln_key(osv_id, aliases),
                aliases,
                vuln.get("summary"),
                severity.get("CVSS_V3"),
                severity.get("CVSS_V4"),
                wanted[osv_id],
                json.dumps(vuln.get("affected", [])),
                loaded_at,
            ],
        )
    return len(stale)


def vuln_key(osv_id: str, aliases: Iterable[str]) -> str:
    """One key per flaw: its CVE id when there is one, else the smallest advisory id."""
    ids = sorted({osv_id, *aliases})
    cves = [i for i in ids if i.startswith("CVE-")]
    return cves[0] if cves else ids[0]


def fixed_in(affected: list[dict], package: str, version: str) -> str | None:
    """The first version that fixes `version` of `package`, from OSV's affected ranges."""
    try:
        current = Version(version)
    except InvalidVersion:
        return None
    fixes = []
    for entry in affected:
        pkg = entry.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or canonicalize_name(pkg.get("name", "")) != package:
            continue
        for rng in entry.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events", []):
                try:
                    if "fixed" in event and Version(event["fixed"]) > current:
                        fixes.append(Version(event["fixed"]))
                except InvalidVersion:
                    continue
    return str(min(fixes)) if fixes else None


# --- loading -------------------------------------------------------------------


def load_asset(
    con: duckdb.DuckDBPyConnection,
    asset: Asset,
    packages: list[Package],
    matches: dict[tuple[str, str], dict[str, str]],
    loaded_at: datetime,
) -> int:
    """Replace the asset's packages and findings in one transaction. Returns the finding count."""
    findings: dict[tuple[str, str, str], dict] = {}
    for (package, version), vulns in matches.items():
        for osv_id in vulns:
            key, affected = con.execute(
                "SELECT vuln_key, affected FROM raw.osv_vulns WHERE osv_id = ?", [osv_id]
            ).fetchone()
            finding = findings.setdefault((package, version, key), {"osv_ids": [], "fixes": []})
            finding["osv_ids"].append(osv_id)
            fix = fixed_in(json.loads(affected), package, version)
            if fix:
                finding["fixes"].append(Version(fix))

    # The fix for a flaw is the highest of its advisories' fixes, so all of them are covered.
    flaw_fixes = {k: max(f["fixes"]) if f["fixes"] else None for k, f in findings.items()}
    rows = []
    for (package, version, key), finding in sorted(findings.items()):
        fix = flaw_fixes[(package, version, key)]
        rows.append(
            (asset.name, package, version, key, sorted(finding["osv_ids"]), str(fix) if fix else None, loaded_at)
        )
    # Upgrading a package to the highest fix among its flaws fixes all of them (except those
    # without a fix yet). Computed here because versions do not sort as text ("2.10" > "2.9").
    upgrade_to: dict[str, Version] = {}
    for (package, _, _), fix in flaw_fixes.items():
        if fix and (package not in upgrade_to or fix > upgrade_to[package]):
            upgrade_to[package] = fix
    with transaction(con):
        con.execute("DELETE FROM raw.assets WHERE asset = ?", [asset.name])
        con.execute(
            "INSERT INTO raw.assets VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                asset.name,
                asset.location,
                list(asset.requirements),
                asset.python,
                asset.publicly_exposed,
                asset.mission_impact,
                loaded_at,
            ],
        )
        con.execute("DELETE FROM raw.asset_packages WHERE asset = ?", [asset.name])
        con.executemany(
            "INSERT INTO raw.asset_packages VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    asset.name,
                    p.name,
                    p.version,
                    p.direct,
                    str(upgrade_to[p.name]) if p.name in upgrade_to else None,
                    loaded_at,
                )
                for p in packages
            ],
        )
        con.execute("DELETE FROM raw.asset_vulns WHERE asset = ?", [asset.name])
        if rows:
            con.executemany("INSERT INTO raw.asset_vulns VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)

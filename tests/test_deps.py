import json
import subprocess

import pytest
import responses

from tests.conftest import LOADED_AT, as_downloaded, kev_entry, kev_feed, nvd_cve, nvd_feed
from vulnprio import config
from vulnprio.cli import main
from vulnprio.download import make_session
from vulnprio.ingest import ingest_deps
from vulnprio.sources import deps, kev, nvd
from vulnprio.transform import run_dbt
from vulnprio.warehouse import connect

ASSETS = """
[[asset]]
name = "api"
repo = "acme/api"
ref = "main"
requirements = ["requirements.txt"]
publicly_exposed = "yes"
mission_impact = "high"

[[asset]]
name = "batch"
path = "batch"
requirements = ["reqs/base.txt"]
python = "3.12"
publicly_exposed = "no"
mission_impact = "low"
"""


def write_assets(tmp_path, text=ASSETS):
    path = tmp_path / "assets.toml"
    path.write_text(text, encoding="utf-8")
    return path


# --- assets.toml ---------------------------------------------------------------


def test_load_assets(tmp_path):
    api, batch = deps.load_assets(write_assets(tmp_path))

    assert api.location == "github:acme/api@main"
    assert api.python == "3.13"  # default
    assert api.trust_build_scripts is False
    assert batch.path == tmp_path / "batch"
    assert batch.requirements == ("reqs/base.txt",)
    assert (batch.publicly_exposed, batch.mission_impact) == ("no", "low")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (('path = "batch"', 'path = "batch"\nrepo = "acme/x"'), "either repo"),
        (('mission_impact = "low"', 'mission_impact = "critical"'), "mission_impact"),
        (('publicly_exposed = "no"', "publicly_exposed = true"), "publicly_exposed"),
        (('name = "batch"', 'name = "api"'), "unique"),
        (('["reqs/base.txt"]', '["../../etc/passwd"]'), "outside the asset"),
        (('repo = "acme/api"', 'repo = "acme/api; rm -rf"'), "invalid repo"),
        (('python = "3.12"', 'python = "latest"'), "python"),
    ],
)
def test_load_assets_rejects_invalid_entries(tmp_path, change, message):
    with pytest.raises(deps.DepsError, match=message):
        deps.load_assets(write_assets(tmp_path, ASSETS.replace(*change)))


# --- requirement files ----------------------------------------------------------


def test_check_requirements_accepts_packages_and_includes():
    text = """
        # comment
        requests==2.32.0  # trailing comment
        pandas[performance]>=2.2 ; python_version >= "3.11"
        jinja2==3.1.6 --hash=sha256:abc123 \\
        -r base.txt
        --constraint=../constraints.txt
    """.replace("\\", "")
    assert deps.check_requirements(text, "reqs/dev.txt") == ["reqs/base.txt", "constraints.txt"]


@pytest.mark.parametrize(
    "line",
    [
        "--index-url https://evil.example/simple",
        "--extra-index-url https://evil.example/simple",
        "-i https://evil.example/simple",
        "--find-links /tmp/wheels",
        "-e git+https://example.com/repo.git#egg=x",
        "package @ https://evil.example/package.whl",
        "-r ../../outside.txt",
        "not a requirement!",
    ],
)
def test_check_requirements_refuses_what_could_redirect_pip(line):
    with pytest.raises(deps.DepsError):
        deps.check_requirements(line, "requirements.txt")


@responses.activate
def test_fetch_requirements_from_github_follows_includes(tmp_path):
    asset = deps.load_assets(write_assets(tmp_path))[0]
    base = "https://raw.githubusercontent.com/acme/api/main/"
    responses.get(base + "requirements.txt", body="-r requirements-base.txt\nflask==3.1.0\n")
    responses.get(base + "requirements-base.txt", body="requests==2.32.0\n")

    files = deps.fetch_requirements(make_session(), asset, tmp_path / "work")

    assert files == [tmp_path / "work" / "requirements.txt"]
    assert (tmp_path / "work" / "requirements-base.txt").read_text() == "requests==2.32.0\n"


@responses.activate
def test_fetch_requirements_reports_a_missing_file(tmp_path):
    asset = deps.load_assets(write_assets(tmp_path))[0]
    responses.get("https://raw.githubusercontent.com/acme/api/main/requirements.txt", status=404)

    with pytest.raises(deps.DepsError, match="not found in acme/api@main"):
        deps.fetch_requirements(make_session(), asset, tmp_path / "work")


def test_fetch_requirements_from_a_local_folder(tmp_path):
    (tmp_path / "batch" / "reqs").mkdir(parents=True)
    (tmp_path / "batch" / "reqs" / "base.txt").write_text("-c pins.txt\nrequests\n")
    (tmp_path / "batch" / "reqs" / "pins.txt").write_text("requests==2.32.0\n")
    asset = deps.load_assets(write_assets(tmp_path))[1]

    files = deps.fetch_requirements(make_session(), asset, tmp_path / "work")

    assert files == [tmp_path / "work" / "reqs" / "base.txt"]
    assert (tmp_path / "work" / "reqs" / "pins.txt").exists()


# --- resolution -----------------------------------------------------------------


def fake_pip(report, returncode=0, stderr=""):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        report_path = command[command.index("--report") + 1]
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        return subprocess.CompletedProcess(command, returncode, "", stderr)

    return run, calls


PIP_REPORT = {
    "version": "1",
    "install": [
        {"metadata": {"name": "Requests", "version": "2.19.0"}, "requested": True},
        {"metadata": {"name": "urllib3", "version": "1.23"}, "requested": False},
    ],
}


def test_resolve_uses_wheels_only_for_linux(tmp_path, monkeypatch):
    run, calls = fake_pip(PIP_REPORT)
    monkeypatch.setattr(subprocess, "run", run)
    asset = deps.load_assets(write_assets(tmp_path))[1]

    packages = deps.resolve(asset, [tmp_path / "base.txt"], tmp_path / "report.json")

    assert packages == [deps.Package("requests", "2.19.0", True), deps.Package("urllib3", "1.23", False)]
    command = calls[0]
    assert "--only-binary=:all:" in command and "--dry-run" in command
    assert "manylinux_2_28_x86_64" in command and "manylinux_2_17_x86_64" in command
    assert command[command.index("--python-version") + 1] == "3.12"


def test_resolve_may_run_build_scripts_only_when_trusted(tmp_path, monkeypatch):
    run, calls = fake_pip(PIP_REPORT)
    monkeypatch.setattr(subprocess, "run", run)
    text = ASSETS.replace('mission_impact = "high"', 'mission_impact = "high"\ntrust_build_scripts = true')
    asset = deps.load_assets(write_assets(tmp_path, text))[0]

    deps.resolve(asset, [tmp_path / "requirements.txt"], tmp_path / "report.json")

    assert "--only-binary=:all:" not in calls[0]
    assert "--platform" not in calls[0]


def test_resolve_reports_pip_errors(tmp_path, monkeypatch):
    run, _ = fake_pip(PIP_REPORT, returncode=1, stderr="ERROR: No matching distribution found for nothing==9")
    monkeypatch.setattr(subprocess, "run", run)
    asset = deps.load_assets(write_assets(tmp_path))[0]

    with pytest.raises(deps.DepsError, match="No matching distribution"):
        deps.resolve(asset, [tmp_path / "requirements.txt"], tmp_path / "report.json")


# --- OSV ------------------------------------------------------------------------


def test_vuln_key_prefers_the_cve():
    assert deps.vuln_key("GHSA-x84v-xcm2-53pg", ["PYSEC-2018-28", "CVE-2018-18074"]) == "CVE-2018-18074"
    assert deps.vuln_key("PYSEC-2024-1", ["GHSA-aaaa-bbbb-cccc"]) == "GHSA-aaaa-bbbb-cccc"


AFFECTED = [
    {
        "package": {"name": "Django", "ecosystem": "PyPI"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.2"}, {"fixed": "2.2.10"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"fixed": "3.0.3"}]},
        ],
    },
    {"package": {"name": "flask", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9"}]}]},
]


@pytest.mark.parametrize(
    ("version", "expected"),
    [("2.2", "2.2.10"), ("2.2.9", "2.2.10"), ("3.0.1", "3.0.3"), ("4.0", None), ("not-a-version", None)],
)
def test_fixed_in(version, expected):
    assert deps.fixed_in(AFFECTED, "django", version) == expected


@responses.activate
def test_query_osv_maps_results_to_packages():
    responses.post(
        deps.OSV_QUERYBATCH_URL,
        json={"results": [{"vulns": [{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}]}, {}]},
    )
    packages = [deps.Package("requests", "2.19.0", True), deps.Package("idna", "3.10", False)]

    assert deps.query_osv(make_session(), packages) == {("requests", "2.19.0"): {"GHSA-1": "2026-01-01T00:00:00Z"}}
    sent = json.loads(responses.calls[0].request.body)
    assert sent["queries"][1] == {"package": {"name": "idna", "ecosystem": "PyPI"}, "version": "3.10"}


@responses.activate
def test_query_osv_rejects_a_short_answer():
    responses.post(deps.OSV_QUERYBATCH_URL, json={"results": []})
    with pytest.raises(deps.DepsError, match="unexpected number"):
        deps.query_osv(make_session(), [deps.Package("requests", "2.19.0", True)])


# --- end to end -----------------------------------------------------------------

LOCAL_ONLY = """
[[asset]]
name = "legacy"
path = "legacy"
requirements = ["requirements.txt"]
publicly_exposed = "yes"
mission_impact = "high"
"""

OSV_VULNS = {
    # Two advisories for one flaw, with different fixed versions on record.
    "GHSA-x84v-xcm2-53pg": {
        "id": "GHSA-x84v-xcm2-53pg",
        "aliases": ["CVE-2024-0001", "PYSEC-2018-28"],
        "summary": "Credentials leak in Requests",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
            }
        ],
    },
    "PYSEC-2018-28": {
        "id": "PYSEC-2018-28",
        "aliases": ["CVE-2024-0001", "GHSA-x84v-xcm2-53pg"],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.1"}]}],
            }
        ],
    },
    # A second flaw, without a CVE, fixed later.
    "GHSA-aaaa-bbbb-cccc": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Another flaw",
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]}],
            }
        ],
    },
}


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "requirements.txt").write_text("requests==2.19.0\n")
    assets = write_assets(tmp_path, LOCAL_ONLY)
    monkeypatch.setattr(
        deps,
        "resolve",
        lambda asset, files, report: [deps.Package("requests", "2.19.0", True), deps.Package("idna", "2.7", False)],
    )
    responses.post(
        deps.OSV_QUERYBATCH_URL,
        json={"results": [{"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in OSV_VULNS]}, {}]},
    )
    for osv_id, body in OSV_VULNS.items():
        responses.get(deps.OSV_VULN_URL.format(id=osv_id), json=body)
    return assets


@responses.activate
def test_ingest_deps_groups_advisories_and_computes_upgrades(con, tmp_path, legacy):
    assert ingest_deps(con, make_session(), legacy, tmp_path / "landing") == 2

    vulns = con.execute("SELECT vuln_key, osv_ids, fixed_in FROM raw.asset_vulns ORDER BY vuln_key").fetchall()
    assert vulns == [
        # The flaw's fix is the highest of its advisories' fixes.
        ("CVE-2024-0001", ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"], "2.20.1"),
        ("GHSA-aaaa-bbbb-cccc", ["GHSA-aaaa-bbbb-cccc"], "2.32.4"),
    ]
    packages = con.execute("SELECT package, is_direct, upgrade_to FROM raw.asset_packages ORDER BY package").fetchall()
    assert packages == [("idna", False, None), ("requests", True, "2.32.4")]

    # Second scan: the OSV records are cached, nothing is fetched again.
    calls = len(responses.calls)
    ingest_deps(con, make_session(), legacy, tmp_path / "landing")
    assert [c.request.method for c in responses.calls[calls:]] == ["POST"]


@responses.activate
def test_assets_removed_from_the_file_are_removed(con, tmp_path, legacy):
    ingest_deps(con, make_session(), legacy, tmp_path / "landing")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "requirements.txt").write_text("requests==2.19.0\n")
    write_assets(tmp_path, LOCAL_ONLY.replace('"legacy"', '"other"'))

    ingest_deps(con, make_session(), legacy, tmp_path / "landing")

    assert con.execute("SELECT DISTINCT asset FROM raw.asset_packages").fetchall() == [("other",)]


@responses.activate
def test_one_failing_asset_does_not_stop_the_others(con, tmp_path, legacy):
    text = LOCAL_ONLY + LOCAL_ONLY.replace('name = "legacy"', 'name = "broken"').replace(
        'path = "legacy"', 'path = "missing"'
    )
    write_assets(tmp_path, text)

    with pytest.raises(deps.DepsError, match="could not scan: broken"):
        ingest_deps(con, make_session(), legacy, tmp_path / "landing")
    assert con.execute("SELECT DISTINCT asset FROM raw.asset_packages").fetchall() == [("legacy",)]


@responses.activate
def test_findings_end_to_end(tmp_path, legacy, capsys):
    warehouse = tmp_path / "warehouse.duckdb"
    con = connect(warehouse)
    ingest_deps(con, make_session(), legacy, tmp_path / "landing")
    # The CVE is in KEV and NVD, so it gets KEV status and NVD's inputs.
    kev_path = tmp_path / "kev.json"
    kev_path.write_bytes(kev_feed([kev_entry("CVE-2024-0001")]))
    kev.load(con, kev.parse(kev_path.read_bytes()), as_downloaded(kev_path), LOADED_AT)
    gz, meta = nvd_feed([nvd_cve("CVE-2024-0001")])
    responses.get(config.NVD_META_URL.format(year=2024), body=meta)
    responses.get(config.NVD_FEED_URL.format(year=2024), body=gz)
    nvd.sync_feeds(con, make_session(), [2024], tmp_path, record_sync=False)
    con.close()

    run_dbt("build", warehouse=warehouse, target_dir=tmp_path / "dbt")
    assert main(["--warehouse", str(warehouse), "findings", "--details"]) == 0

    out = capsys.readouterr().out
    assert "legacy: requests 2.19.0 -> 2.32.4" in out
    assert "fixes 2 vulnerabilities; act, within 3 days; worst: CVE-2024-0001" in out
    assert "exploited in the wild (KEV)" in out


def test_findings_before_a_scan(tmp_path, capsys):
    assert main(["--warehouse", str(tmp_path / "w.duckdb"), "findings"]) == 1
    assert "Run: vulnprio ingest deps" in capsys.readouterr().out

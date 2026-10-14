import json

import pytest
import responses

from vulnprio import issues

REPO = "acme/app"
BASE = f"{issues.API}/repos/{REPO}"


def alert(**overrides) -> dict:
    row = {
        "alert_key": "api|requests|CVE-2024-0001",
        "asset": "api",
        "package": "requests",
        "version": "2.19.0",
        "upgrade_to": "2.32.4",
        "fixed_in": "2.20.0",
        "vuln_id": "CVE-2024-0001",
        "cve_id": "CVE-2024-0001",
        "summary": "Credentials leak",
        "in_kev": True,
        "kev_date_added": "2026-10-01",
        "ssvc_decision": "act",
        "remediation": "3 days",
        "remediation_days": 3,
        "epss": 0.94,
        "priority_reason": "exploited in the wild (KEV); automatable",
    }
    row.update(overrides)
    return row


def issue(number: int, key: str, body_extra: str = "") -> dict:
    return {"number": number, "title": "old", "body": f"text{body_extra}\n<!-- vulnprio-alert:{key} -->"}


# --- rendering --------------------------------------------------------------------


def test_render_builds_title_body_and_marker():
    rendered = issues.render(alert())

    assert rendered.key == "api|requests|CVE-2024-0001"
    assert rendered.title == "Exploited: CVE-2024-0001 in requests 2.19.0 (api)"
    assert "[CVE-2024-0001 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0001)" in rendered.body
    assert "act, fix within 3 days" in rendered.body
    assert "`requests` `2.32.4`" in rendered.body
    assert rendered.body.endswith("<!-- vulnprio-alert:api|requests|CVE-2024-0001 -->")


def test_render_for_an_act_decision_without_fix_or_cve():
    rendered = issues.render(
        alert(in_kev=False, vuln_id="GHSA-aaaa-bbbb-cccc", upgrade_to=None, fixed_in=None, kev_date_added=None)
    )
    assert rendered.title.startswith("Act now: GHSA-aaaa-bbbb-cccc")
    assert "no fixed version released yet" in rendered.body
    assert "nvd.nist.gov" not in rendered.body


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ping @octocat now", "`ping @​octocat now`"),  # no notification
        ("close` [click](https://evil.example)", "`close [click](https://evil.example)`"),  # stays in the span
        ("line one\nline two | cell", "`line one line two cell`"),  # cannot break the table
        ("", "–"),
        (None, "–"),
    ],
)
def test_untrusted_text_is_made_inert(text, expected):
    assert issues.safe(text) == expected


def test_long_text_is_cut():
    assert len(issues.safe("x" * 1000, limit=50)) == 52  # 50 characters plus the two backticks


# --- planning ---------------------------------------------------------------------


def test_plan_creates_updates_and_closes():
    current = issues.render(alert())
    changed = issues.render(alert(alert_key="api|jinja2|CVE-2024-0002", package="jinja2", vuln_id="CVE-2024-0002"))
    new = issues.render(alert(alert_key="api|flask|CVE-2024-0003", package="flask", vuln_id="CVE-2024-0003"))
    open_issues = {
        current.key: {"number": 1, "title": current.title, "body": current.body},  # unchanged
        changed.key: {"number": 2, "title": "old title", "body": "old body"},  # changed
        "api|pyjwt|CVE-2017-11424": {"number": 3, "title": "gone", "body": "gone"},  # fixed since
    }

    todo = issues.plan([current, changed, new], open_issues)

    assert [a.key for a in todo.create] == [new.key]
    assert [(n, a.key) for n, a in todo.update] == [(2, changed.key)]
    assert todo.close == [(3, "api|pyjwt|CVE-2017-11424")]


# --- GitHub -----------------------------------------------------------------------


@responses.activate
def test_sync_against_the_github_api():
    responses.post(f"{BASE}/labels", status=422, json={"message": "already_exists"})
    responses.get(
        f"{BASE}/issues",
        json=[
            issue(7, "api|pyjwt|CVE-2017-11424"),
            {"number": 8, "title": "a PR", "body": "<!-- vulnprio-alert:x -->", "pull_request": {}},
            {"number": 9, "title": "unrelated", "body": None},
        ],
    )
    responses.post(f"{BASE}/issues", json={"number": 10})
    responses.post(f"{BASE}/issues/7/comments", json={})
    responses.patch(f"{BASE}/issues/7", json={})

    todo = issues.sync(issues.GitHub(REPO, "token-123"), [issues.render(alert())])

    assert len(todo.create) == 1 and todo.close == [(7, "api|pyjwt|CVE-2017-11424")]
    created = json.loads(responses.calls[2].request.body)
    assert created["labels"] == [issues.LABEL]
    assert responses.calls[2].request.headers["Authorization"] == "Bearer token-123"
    assert json.loads(responses.calls[-1].request.body) == {"state": "closed", "state_reason": "completed"}
    query = responses.calls[1].request.url
    assert "labels=kev-alert" in query and "state=open" in query


@responses.activate
def test_dry_run_changes_nothing():
    responses.get(f"{BASE}/issues", json=[issue(7, "api|pyjwt|CVE-2017-11424")])

    todo = issues.sync(issues.GitHub(REPO, "t"), [issues.render(alert())], dry_run=True)

    assert len(todo.create) == 1 and len(todo.close) == 1
    assert [c.request.method for c in responses.calls] == ["GET"]


@responses.activate
def test_open_issues_follows_pages():
    first = [issue(n, f"key-{n}") for n in range(100)]
    responses.get(f"{BASE}/issues", json=first)
    responses.get(f"{BASE}/issues", json=[issue(100, "key-100")])

    assert len(issues.GitHub(REPO, "t").open_issues()) == 101


@responses.activate
def test_api_errors_are_reported():
    responses.get(f"{BASE}/issues", status=403, json={"message": "Resource not accessible by integration"})
    with pytest.raises(issues.IssuesError, match="HTTP 403"):
        issues.GitHub(REPO, "t").open_issues()


def test_invalid_repository_is_refused():
    with pytest.raises(issues.IssuesError, match="invalid repository"):
        issues.GitHub("acme/app/../../other", "t")


def test_main_needs_a_token(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    path = tmp_path / "alerts.json"
    path.write_text("[]")
    assert issues.main(["--alerts", str(path), "--repo", REPO]) == 1
    assert "GITHUB_TOKEN is not set" in capsys.readouterr().err


@responses.activate
def test_main_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps([alert()]))
    responses.post(f"{BASE}/labels", status=201, json={})
    responses.get(f"{BASE}/issues", json=[])
    responses.post(f"{BASE}/issues", json={"number": 1})

    assert issues.main(["--alerts", str(path), "--repo", REPO]) == 0
    assert json.loads(responses.calls[-1].request.body)["title"].startswith("Exploited: CVE-2024-0001")

"""Keep one GitHub issue open per alert, and close it when the alert is gone.

Reads the alerts written by `vulnprio alerts` (assets.asset_alerts as JSON) and
syncs the repository's open issues labelled `kev-alert`:

- an alert without an issue gets one;
- an issue whose alert changed (new deadline, upgrade target...) is updated;
- an issue whose alert is gone (the package was upgraded) is closed, with a comment.

Each issue body ends with a hidden marker holding the alert key, which is how
issues and alerts are matched across runs.

Runs with only `requests` installed (`python -m vulnprio.issues`), so the CI job
that can write issues needs no other dependency. The token comes from the
GITHUB_TOKEN environment variable and is sent only to api.github.com.
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

log = logging.getLogger("vulnprio.issues")

API = "https://api.github.com"
LABEL = "kev-alert"
LABEL_COLOR = "b42318"
DASHBOARD = "https://joaopedro0305.github.io/vuln-priority-pipeline/"
MARKER = re.compile(r"<!-- vulnprio-alert:(.+?) -->")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


class IssuesError(Exception):
    pass


def safe(text: object, limit: int = 300) -> str:
    """Untrusted text (advisory summaries, names) made inert in Markdown.

    Inside a code span nothing is rendered: no links, images or HTML. "@name"
    would still notify a GitHub user, so the @ is followed by a zero-width
    space; backticks and line breaks are removed so the span cannot be closed.
    """
    value = re.sub(r"[`|\s]+", " ", str(text or "")).strip()
    value = value.replace("@", "@​")
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return f"`{value}`" if value else "–"


@dataclass(frozen=True)
class Alert:
    key: str
    title: str
    body: str


def render(alert: dict) -> Alert:
    vuln = alert["vuln_id"]
    exploited = alert.get("in_kev")
    why = "is listed by CISA as exploited in the wild" if exploited else "gets an SSVC decision of act"
    deadline = f"within {alert['remediation_days']} days" if alert.get("remediation_days") else "at the next upgrade"
    target = alert.get("upgrade_to") or alert.get("fixed_in")
    link = f"[{vuln} on NVD](https://nvd.nist.gov/vuln/detail/{vuln})" if CVE_ID.fullmatch(vuln) else f"`{vuln}`"
    rows = [
        ("Decision", f"{alert['ssvc_decision']}, fix {deadline} (CISA SSVC and BOD 26-04 for this system)"),
        ("Upgrade to", f"{safe(alert['package'])} {safe(target)}" if target else "no fixed version released yet"),
        ("In KEV since", alert["kev_date_added"] if alert.get("kev_date_added") else "–"),
        ("Why", safe(alert.get("priority_reason"))),
        ("Advisory", safe(alert.get("summary"))),
    ]
    body = "\n".join(
        [
            f"{safe(alert['package'])} {safe(alert['version'])} in **{safe(alert['asset'])}** has {link}, which {why}.",
            "",
            "| | |",
            "|---|---|",
            *[f"| {label} | {value} |" for label, value in rows],
            "",
            f"Opened by the daily dependency scan. Ranking and method: [dashboard]({DASHBOARD}).",
            "This issue closes itself when the flaw no longer appears in the scan.",
            "",
            f"<!-- vulnprio-alert:{alert['alert_key']} -->",
        ]
    )
    title = (
        f"{'Exploited' if exploited else 'Act now'}: {vuln} in {alert['package']} {alert['version']} ({alert['asset']})"
    )
    return Alert(key=alert["alert_key"], title=title[:250], body=body)


class GitHub:
    def __init__(self, repo: str, token: str, session: requests.Session | None = None):
        if not REPO.fullmatch(repo):
            raise IssuesError(f"invalid repository: {repo!r}")
        self.repo = repo
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "vuln-priority-pipeline",
            }
        )

    def _call(self, method: str, path: str, **kwargs) -> requests.Response:
        response = self.session.request(method, f"{API}/repos/{self.repo}{path}", timeout=30, **kwargs)
        if response.status_code >= 400 and not (method == "POST" and path == "/labels" and response.status_code == 422):
            raise IssuesError(f"GitHub {method} {path}: HTTP {response.status_code} {response.text[:200]}")
        return response

    def ensure_label(self) -> None:
        # 422 = the label already exists.
        self._call(
            "POST",
            "/labels",
            json={"name": LABEL, "color": LABEL_COLOR, "description": "Exploited flaw in a dependency"},
        )

    def open_issues(self) -> dict[str, dict]:
        """Open issues with the label, by alert key."""
        issues: dict[str, dict] = {}
        page = 1
        while True:
            batch = self._call(
                "GET", "/issues", params={"labels": LABEL, "state": "open", "per_page": 100, "page": page}
            ).json()
            for issue in batch:
                match = MARKER.search(issue.get("body") or "")
                if match and "pull_request" not in issue:
                    issues[match.group(1)] = issue
            if len(batch) < 100:
                return issues
            page += 1

    def create(self, alert: Alert) -> int:
        return self._call("POST", "/issues", json={"title": alert.title, "body": alert.body, "labels": [LABEL]}).json()[
            "number"
        ]

    def update(self, number: int, alert: Alert) -> None:
        self._call("PATCH", f"/issues/{number}", json={"title": alert.title, "body": alert.body})

    def close(self, number: int, comment: str) -> None:
        self._call("POST", f"/issues/{number}/comments", json={"body": comment})
        self._call("PATCH", f"/issues/{number}", json={"state": "closed", "state_reason": "completed"})


@dataclass(frozen=True)
class Plan:
    create: list[Alert]
    update: list[tuple[int, Alert]]
    close: list[tuple[int, str]]  # (issue number, alert key)


def plan(alerts: list[Alert], issues: dict[str, dict]) -> Plan:
    wanted = {a.key: a for a in alerts}
    return Plan(
        create=[a for key, a in wanted.items() if key not in issues],
        update=[
            (issues[key]["number"], a)
            for key, a in wanted.items()
            if key in issues and (issues[key].get("body") != a.body or issues[key].get("title") != a.title)
        ],
        close=[(issue["number"], key) for key, issue in issues.items() if key not in wanted],
    )


def sync(github: GitHub, alerts: list[Alert], *, dry_run: bool = False) -> Plan:
    if not dry_run:
        github.ensure_label()
    todo = plan(alerts, github.open_issues())
    today = datetime.now(UTC).date().isoformat()
    for alert in todo.create:
        log.info("open: %s", alert.title)
        if not dry_run:
            log.info("opened #%d", github.create(alert))
    for number, alert in todo.update:
        log.info("update #%d: %s", number, alert.title)
        if not dry_run:
            github.update(number, alert)
    for number, key in todo.close:
        log.info("close #%d (%s no longer found)", number, key)
        if not dry_run:
            github.close(number, f"Not found in the dependency scan of {today}: the package was upgraded or removed.")
    return todo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m vulnprio.issues", description=__doc__.splitlines()[0])
    parser.add_argument("--alerts", type=Path, required=True, help="JSON written by `vulnprio alerts`")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", force=True)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.error("GITHUB_TOKEN is not set")
        return 1
    try:
        alerts = [render(a) for a in json.loads(args.alerts.read_text(encoding="utf-8"))]
        todo = sync(GitHub(args.repo, token), alerts, dry_run=args.dry_run)
    except (IssuesError, requests.RequestException, OSError, ValueError, KeyError) as err:
        log.error("%s", err)
        return 1
    verbs = ("would open", "would update", "would close") if args.dry_run else ("opened", "updated", "closed")
    counts = (len(todo.create), len(todo.update), len(todo.close))
    log.info("%d alert(s): %s", len(alerts), ", ".join(f"{n} {verb}" for n, verb in zip(counts, verbs, strict=True)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

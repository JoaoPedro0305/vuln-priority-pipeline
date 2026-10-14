# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub:
**[Report a vulnerability](https://github.com/JoaoPedro0305/vuln-priority-pipeline/security/advisories/new)**
(Security tab, "Report a vulnerability"). Do not open a public issue.

Useful to include: what is affected (the pipeline, a workflow, the dashboard), how to reproduce it,
and what an attacker could do with it.

This is a project maintained by one person. You can expect an answer within 7 days, a fix or a
plan within 30 days for confirmed problems, and credit in the advisory if you want it.

## Scope

In scope:

- the Python package (`src/vulnprio`) and the dbt project;
- the GitHub Actions workflows (for example, a way to run code or steal the token from a pull request);
- the dashboard on GitHub Pages (for example, a way to inject script through data from the sources);
- the dependency scan (for example, a requirement file that makes it run code or fetch from elsewhere).

Out of scope: flaws in the data sources themselves (CISA KEV, FIRST EPSS, NVD, OSV.dev) or in
third-party packages. Report those to their maintainers. Disagreement with a ranking is not a
vulnerability; open a regular issue.

## Supported versions

The `main` branch and the latest release. Fixes are not backported.

## What is already in place

Dependencies pinned by hash, GitHub Actions pinned by commit, read-only workflow tokens with write
permissions granted per job, CodeQL and `pip-audit` on every pull request, OpenSSF Scorecard
weekly, and a Content Security Policy on the dashboard. See the README, section "Quality and
security of the repository itself".

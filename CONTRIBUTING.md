# Contributing

Thanks for taking the time. Bug reports, questions about the method and pull requests are all
welcome.

## Reporting

- **Bugs, questions and ideas:** open an [issue](https://github.com/JoaoPedro0305/vuln-priority-pipeline/issues).
  For a bug, include the command you ran, what you expected and what happened (the log lines help).
- **Security problems:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).

Issues get a first answer within 7 days.

## Development setup

Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements-dev.txt
pip install --no-deps -e .
```

## Requirements for a pull request

1. **Tests.** New behaviour comes with tests that fail without it, and every bug fix comes with a
   test that reproduces the bug. Python code is tested with pytest (`tests/`); SQL logic with dbt
   data tests or unit tests (`dbt/`). Coverage of `src/vulnprio` must stay at 90% or more; CI fails
   below that.
2. **Checks pass locally:**
   ```bash
   ruff check . && ruff format --check .
   coverage run -m pytest && coverage report
   ```
3. **CI is green.** `main` only accepts pull requests whose required checks pass: lint, tests on
   Python 3.11 to 3.13, dependency audit and CodeQL.
4. **Dependencies.** Change the pins in a `requirements*.in` file and regenerate the matching
   `requirements*.txt` with the command in its header (`uv pip compile ... --generate-hashes`).
   Never edit a `requirements*.txt` by hand.
5. **Warehouse schema.** The daily run keeps its warehouse between runs, so a new column in
   `src/vulnprio/schema.sql` also needs an `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
6. **Data from outside is untrusted.** Validate it before loading, never build SQL or HTML from it
   as text, and keep secrets out of URLs, logs and the repository.

## Style

Code is formatted and linted with ruff (configuration in `pyproject.toml`, including the bandit
security rules). Comments explain why, not what. Commit messages say what changed and why, in the
imperative ("Add", "Fix").

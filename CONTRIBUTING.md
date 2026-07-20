# Contributing

Thanks for taking the time to contribute! This document describes the local
workflow and conventions for this repository.

## Development setup

Dependencies are managed with [uv](https://docs.astral.sh/uv/) (`pyproject.toml`
+ `uv.lock`, as in suitenumerique/messages):

```bash
uv sync                        # create .venv from the lockfile (runtime + dev)
uv run pre-commit install      # run the linters on every commit
```

You also need a `clamd` (or [exav](https://github.com/sylvinus/exav)) daemon on
`localhost:3310` to run the scan tests — the simplest way is `make bootstrap`.

## Checks

Everything CI runs, you can run locally:

```bash
make lint       # ruff check + ruff format --check
make lint-fix   # ruff --fix + ruff format
make audit      # pip-audit dependency vulnerability scan
make test       # test suite (in docker)

# or directly:
APP_CONFIG=config.CiConfig uv run pytest
```

Please keep the test suite green and add tests for new behaviour. Security-
sensitive code (SSRF guard, verdict classification, size/time limits) must be
covered.

## Commit messages

Commits follow the [gitmoji](https://gitmoji.dev/) convention with an optional
scope:

```
✨(scanner) add exav extended-verdict support
🐛(ci) wait for clamd before running tests
🔒️(scanner) validate webhook_url against the SSRF guard
```

## Pull requests

- Target the default branch.
- Make sure `make lint` and the tests pass.

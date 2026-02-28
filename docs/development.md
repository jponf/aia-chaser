# Development

## Prerequisites

To set up the development environment for this project you need the following tools:

  * Python >= 3.8 (excluding 3.9.0 and 3.9.1)
  * Git
  * Make
  * [Poetry](https://python-poetry.org/docs/#installation) (version 2 or newer)

Optionally, you can use one of the following tools to manage Python versions:

  * [Pyenv](https://github.com/pyenv/pyenv)
  * [Mise](https://mise.jdx.dev/)

## Setup

With the tools already installed on your device, first clone the repository:

```shell
git clone https://github.com/jponf/aia-chaser.git
cd aia-chaser
```

Then, set up the virtual environment and install dependencies:

```shell
poetry install --with dev --with test
```

Additionally, if you plan to create new commits, install the pre-commit hooks.
These will verify your files before committing them:

```shell
poetry run pre-commit install
```

Happy coding!

## Common Tasks

### Run Tests

```shell
poetry run pytest
```

With coverage:

```shell
poetry run pytest --cov=aia_chaser --cov-report=term-missing
```

### Run Linters

```shell
poetry run ruff check .
poetry run mypy .
```

### Build Documentation

```shell
poetry install --with docs
poetry run mkdocs serve
```

## Coding Guidelines

This project uses automated tools to enforce consistent code style:

| Tool | Purpose |
|------|---------|
| [Black](https://github.com/psf/black) | Code formatting |
| [isort](https://pycqa.github.io/isort/) | Import sorting |
| [Ruff](https://github.com/astral-sh/ruff) | Linting |
| [mypy](https://mypy-lang.org/) | Static type checking |

Pre-commit hooks and CI pipelines run these tools automatically. Type hints are
encouraged as they help catch bugs early and improve IDE support.

Tools can be disabled per-file or per-line when necessary, but use this sparingly.

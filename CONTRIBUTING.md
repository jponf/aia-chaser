# Contributing

## Prerequisites

- Python >= 3.9
- [Poetry](https://python-poetry.org/docs/#installation) >= 2
- Make
    - macOS: `xcode-select --install`
    - Linux: [https://www.gnu.org/software/make](https://www.gnu.org/software/make)
    - Windows: [https://mingw.org/download/installer](https://mingw.org/download/installer)

## Getting started

```sh
# Install all dependencies (dev, test, and docs groups)
make install-dev

# Install pre-commit hooks
poetry run pre-commit install
```

## Development workflow

1. Create a feature branch from `main`.
2. Make your changes.
3. Ensure all checks pass locally before pushing:

    ```sh
    # Format code
    make format

    # Run linters and type checking
    poetry run ruff check .
    poetry run mypy --install-types --non-interactive .

    # Run tests with coverage
    poetry run pytest -s --cov=aia_chaser --cov-report=term-missing
    ```

Pre-commit hooks run automatically on `git commit` and enforce formatting
(`black`, `isort`), linting (`ruff`), type checking (`mypy`), and a
vulnerability audit (`pip-audit`).

You can also run all pre-commit hooks manually at any time:

```sh
make pre-commit
```

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

```text
<type>(<optional scope>): <description>

# Examples
feat: add support for custom HTTP adapters
fix(aia): handle missing AIA extension gracefully
chore(deps): update cryptography to 45.0.0
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `chore`, `ci`, `perf`.

## CI pipeline

| Workflow              | Trigger                  | What it does                                            |
|-----------------------|--------------------------|---------------------------------------------------------|
| `python-ci.yml`       | Every push               | Lint (`ruff`), type check (`mypy`), tests with coverage |
| `python-publish.yml`  | GitHub release published | Builds and publishes the package to PyPI                |

## Releasing

See [RELEASING.md](RELEASING.md) for the full release process.

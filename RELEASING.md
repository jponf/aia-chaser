# Releasing

This document describes the release process for aia-chaser.

## Prerequisites

- Push access to the repository
- PyPI API token configured as `PYPI_API_TOKEN` secret

## Version Bumping

This project uses [poetry-bumpversion](https://github.com/monim67/poetry-bumpversion)
to manage versions. The version is defined in `pyproject.toml` and automatically
synced to `aia_chaser/__init__.py`.

Bump the version using poetry:

```shell
# Patch release (e.g., 3.3.0 -> 3.3.1)
poetry version patch

# Minor release (e.g., 3.3.0 -> 3.4.0)
poetry version minor

# Major release (e.g., 3.3.0 -> 4.0.0)
poetry version major
```

## Release Process

1. **Update changelog** - Add release notes to `docs/changelog.md`

2. **Bump version** - Run `poetry version <patch|minor|major>`

3. **Commit changes** - Create a commit with the version bump:
   ```shell
   git add pyproject.toml aia_chaser/__init__.py docs/changelog.md
   git commit -m "chore: Bump version to X.Y.Z"
   ```

4. **Push to main** - Push the commit to the main branch

5. **Create GitHub release** - Go to GitHub releases and create a new release:
   - Tag: `vX.Y.Z` (e.g., `v3.4.0`)
   - Title: `vX.Y.Z`
   - Description: Copy from changelog

6. **Automatic deployment** - The `python-publish.yml` workflow automatically
   builds and publishes to PyPI when the release is published.

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `python-ci.yml` | Push | Run tests, linting, type checking |
| `python-publish.yml` | Release published | Build and publish to PyPI |

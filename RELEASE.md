# Release

Before publishing, update `version` in `pyproject.toml`, then build and check the package:

```bash
uv sync --group dev
uv run --group dev pytest
uv run --group dev ruff check
uv build
uv run --group dev python -m twine check dist/*
```

Upload to TestPyPI first:

```bash
uv publish --publish-url https://test.pypi.org/legacy/ dist/*
```

After validating the TestPyPI install, upload to PyPI:

```bash
uv publish dist/*
```

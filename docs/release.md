# Release Process

Red Widow should publish to PyPI through GitHub Trusted Publishing. Do not use a
long-lived PyPI API token from a local shell unless there is an incident-level
reason to bypass CI.

Official references:

- PyPI Trusted Publishing: <https://docs.pypi.org/trusted-publishers/>
- Publishing with the PyPA action: <https://docs.pypi.org/trusted-publishers/using-a-publisher/>
- Python packaging flow: <https://packaging.python.org/en/latest/flow/>

## One-Time PyPI Setup

Create a PyPI account and configure a pending Trusted Publisher for the project.

Use these values:

| Field | Value |
| --- | --- |
| PyPI project name | `red-widow` |
| GitHub owner | `duriantaco` |
| GitHub repository | `red-widow` |
| Workflow filename | `release.yml` |
| Environment | `pypi` |

Pending publishers do not reserve the package name until the first publish. If
someone else registers `red-widow` before the first release, choose a different
package name and update `pyproject.toml`.

In GitHub, create an environment named `pypi`. Require reviewer approval on that
environment if you want a human checkpoint before upload.

## Release Checklist

1. Start from a clean `main`.

   ```bash
   git switch main
   git pull --ff-only
   git status --short --branch
   ```

2. Update both versions to the same value:

   - `pyproject.toml`: `[project].version`
   - `red_widow/__init__.py`: `__version__`

3. Run local validation.

   ```bash
   python3 -m unittest
   python3 -m red_widow gate --workspace . --offline
   npm --prefix vscode-extension test
   ```

4. Build locally if you have `build` installed.

   ```bash
   python3 -m pip install --upgrade build
   python3 -m build
   ```

5. Commit the version bump.

   ```bash
   git add pyproject.toml red_widow/__init__.py
   git commit -m "chore: release v0.1.0"
   ```

6. Tag and push.

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin main
   git push origin v0.1.0
   ```

7. Create a GitHub Release for the tag.

   ```bash
   gh release create v0.1.0 \
     --title "v0.1.0" \
     --notes "Initial Red Widow release."
   ```

8. The `Release` workflow runs tests, builds the sdist and wheel, and publishes
   to PyPI through Trusted Publishing after the `pypi` environment is approved.

## Install Smoke Test

After the workflow publishes, verify the package from a clean environment:

```bash
python3 -m pipx run red-widow --help
python3 -m pipx run red-widow gate --offline --workspace .
```

If `pipx` is not installed:

```bash
python3 -m venv /tmp/red-widow-smoke
/tmp/red-widow-smoke/bin/python -m pip install red-widow
/tmp/red-widow-smoke/bin/red-widow --help
```

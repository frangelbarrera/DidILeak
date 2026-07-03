# Releasing DidILeak

This document describes how to cut a new release of DidILeak and publish it to PyPI.

## Prerequisites (one-time setup)

### 1. PyPI account + Trusted Publishing

DidILeak uses [Trusted Publishing (OIDC)](https://docs.pypi.org/trusted-publishers/) — no API tokens needed.

1. Create a PyPI account at <https://pypi.org/account/register/> if you don't have one.
2. Go to <https://pypi.org/manage/project/didileak/create/> (you may need to first claim the name by uploading once manually — see "First release only" below).
3. Add a publisher with these values:
   - **PyPI Project Name:** `DidILeak`
   - **Owner:** `frangelbarrera`
   - **Repository:** `DidILeak`
   - **Workflow filename:** `publish.yml`
   - **Environment name:** `pypi`

### 2. First release only — manual upload

Trusted Publishing requires the project to already exist on PyPI. For the very first release, you have two options:

**Option A (recommended):** Reserve the name with an empty upload first.

```bash
pip install build twine
python -m build
python -m twine upload dist/* --repository-url https://upload.pypi.org/legacy/
```

You'll be prompted for your PyPI username + password (or API token). After this, configure Trusted Publishing as described above.

**Option B:** Skip Trusted Publishing for the first release and use an API token for every release.

```bash
# Create API token at https://pypi.org/manage/account/token/
# Scope: "Entire account" or "Project: DidILeak"
# Then add it as a GitHub secret named PYPI_API_TOKEN and use it in publish.yml
```

## Cutting a release

Once the prerequisites are done, releasing is fully automated:

### 1. Bump version

Edit `pyproject.toml`:

```toml
version = "0.2.0"  # was 0.1.0
```

Update `CHANGELOG.md` with the new version entry.

Commit and push:

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "bump: v0.2.0"
git push origin main
```

### 2. Create the GitHub release

```bash
# Tag the commit
git tag -a v0.2.0 -m "v0.2.0"

# Push the tag
git push origin v0.2.0

# Create the release on GitHub (or use the web UI)
gh release create v0.2.0 --title "v0.2.0" --notes-file CHANGELOG.md
```

Alternatively, go to <https://github.com/frangelbarrera/DidILeak/releases/new> and create the release with the tag `v0.2.0`.

### 3. The publish workflow runs automatically

When the release is published, the `publish.yml` workflow triggers:

1. Builds the package (`python -m build`)
2. Validates it (`twine check`)
3. Uploads to PyPI using Trusted Publishing (OIDC, no token)

You can watch it at <https://github.com/frangelbarrera/DidILeak/actions/workflows/publish.yml>.

### 4. Verify on PyPI

After the workflow completes (~2 min):

```bash
pip install didileak==0.2.0
didileak --version
```

The package page is at <https://pypi.org/project/DidILeak/>.

## Versioning

DidILeak follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): incompatible API changes
- **MINOR** (0.2.0): new features, backwards-compatible
- **PATCH** (0.1.1): bug fixes only

While at `0.x`, breaking changes are allowed in minor bumps.

## Pre-releases

For release candidates:

```bash
# In pyproject.toml: version = "0.2.0rc1"
git tag -a v0.2.0rc1 -m "v0.2.0rc1"
git push origin v0.2.0rc1
gh release create v0.2.0rc1 --prerelease --title "v0.2.0rc1" --notes "Release candidate"
```

PyPI supports pre-release versions. Users can install them with:

```bash
pip install --pre didileak
```

## Rollback

PyPI does not allow re-uploading the same version. If a release is broken:

1. **Yank it** (keeps it installable but hides it from default search):
   ```bash
   # Via web UI: https://pypi.org/manage/project/didileak/releases/
   ```
2. **Bump to a patch version** and release the fix:
   ```bash
   # 0.2.0 broken -> release 0.2.1
   ```

Never delete a release — yank instead. Other projects may depend on the exact version.

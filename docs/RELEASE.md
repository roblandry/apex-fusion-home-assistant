# Releasing

Releases are cut by CI when a pull request that bumps the version is merged to
`main`. Nobody tags by hand and nothing is committed to `main` directly.

## Versioning policy

The project uses [semver](https://semver.org/) and is still on `0.x`:

- **Minor** (`0.1.6` to `0.2.0`): behaviour changes, new entities that change
  existing setups, or anything that needs a migration or user action.
- **Patch** (`0.1.6` to `0.1.7`): bug fixes and small additions that need
  nothing from users.
- **Pre-releases** use a PEP 440 suffix: `aN`, `bN` or `rcN` (for example
  `0.2.0b1`, `0.2.0rc1`). No dashes or dots. They order as
  `0.1.6 < 0.2.0b1 < 0.2.0b2 < 0.2.0rc1 < 0.2.0`, and are published as GitHub
  pre-releases (tag `v0.2.0b1`).

The version is stored in `custom_components/apex_fusion/manifest.json`, and
`scripts/bump-version.py` is the only thing that should edit it.

## Making a release

1. Branch from `main` and bump the version:

   ```sh
   python3 scripts/bump-version.py --bump patch    # or minor / major
   python3 scripts/bump-version.py --set 0.2.0b1   # an exact version
   ```

   `--get` prints the current version and `--check` fails if the version
   sources disagree.

2. Add a section for the new version at the top of `CHANGELOG.md`, under the
   header. Either write it by hand or draft it from the commit history with
   [git-cliff](https://git-cliff.org/) and then tidy it:

   ```sh
   git cliff --unreleased --tag v0.1.7 --prepend CHANGELOG.md
   ```

   The heading must be `## v0.1.7` (the same version as the manifest).

3. Open a pull request titled like `chore: release v0.1.7`. The **Version
   check** workflow confirms the version is an increase over `main` and that
   the changelog section exists.

4. Merge it. The **Release on version bump** workflow then creates the annotated
   tag `v0.1.7` and a GitHub release. The release notes are the `CHANGELOG.md`
   section. If there is none, notes are generated from the Conventional Commit
   subjects since the previous tag.

## Beta to stable

1. Cut the beta: bump to `0.2.0b1` and merge as above. CI publishes it as a
   pre-release.
2. Test it. If it needs fixes, merge them and cut `0.2.0b2`, and so on.
3. When it is good, bump to `0.2.0` and merge. CI publishes a normal release.

HACS only offers pre-releases to users who enable **Show beta versions** for
this repository in HACS. Everyone else stays on the latest stable release.

HACS shows the GitHub release to users, so the release notes are what they see
when an update is offered.

## If the release did not happen

- Check the workflow run under **Actions**. If the release step failed, fix the
  cause and run **Release on version bump** manually on `main`; it releases the
  version currently on `main` and does nothing if the tag already exists.
- To release without CI, tag and publish by hand from the merged commit:

  ```sh
  git tag -a v0.1.7 -m v0.1.7 <commit>
  git push origin v0.1.7
  gh release create v0.1.7 --verify-tag --title v0.1.7 --notes-file notes.md
  ```

  Add `--prerelease` for `aN`, `bN` and `rcN` versions.

There are no backports: fixes ship as a new release from `main`.

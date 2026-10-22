# Releasing

Releases are cut by CI when a pull request that bumps the version is merged to
`main`. Nobody tags by hand and nothing is committed to `main` directly.

## Versioning policy

Versions are calendar based: `YYYY.M.D`, with an optional beta suffix.

| Version        | Meaning                    | GitHub release |
| -------------- | -------------------------- | -------------- |
| `2026.10.22b1` | beta 1, cut on 22 Oct 2026 | pre-release    |
| `2026.10.25`   | stable, cut on 25 Oct 2026 | normal release |

- Month and day have no leading zeros (`2026.3.5`, not `2026.03.05`).
- Use the date you cut the release (UTC).
- Pre-release suffixes are `aN`, `bN`, `rcN` and `.devN`. Betas (`bN`) are the
  normal choice. They order as
  `2026.10.22.dev1 < a1 < b1 < b2 < rc1 < 2026.10.22`.
- **Never go past `b9`.** If a day's betas run out, roll the date forward to a
  later day and start again at `b1`. The tooling refuses `b10` and higher.
- Versions before the switch were `0.1.x`. The first CalVer release follows
  `0.1.6` directly, and new `0.x` versions are not accepted.
- There are no backports. Fixes ship as a new release from `main`.

The version is stored in `custom_components/apex_fusion/manifest.json`, and
`scripts/bump-version.py` is the only thing that should edit it.

### Two-digit days: do not reuse the date

Home Assistant, HACS and the Supervisor rank versions with AwesomeVersion, and
it does not understand the `bN` suffix when the day is 10 to 31. Two releases on
the same date then compare as equal, so HACS would never offer the newer one
(single-digit days are fine, and different dates always work).

The practical rule: **on a day from 10 to 31, a new release (beta or stable)
must not share its date with the previous release.** Cut it on a later day.
Promoting a beta to stable follows the same rule, for example
`2026.10.22b1` to `2026.10.25`. CI checks this and fails the PR if HACS would
not see the update.

## Making a release

1. Branch from `main` and set the version:

   ```sh
   python3 scripts/bump-version.py --next-beta        # today's next beta
   python3 scripts/bump-version.py --set 2026.10.25   # an exact version
   ```

   `--next-beta` gives `bN+1` if the current version is a beta from today,
   otherwise `b1` for today's date. `--get` prints the current version and
   `--check` fails if the version sources disagree.

2. Add a section for the new version at the top of `CHANGELOG.md`, under the
   header. Either write it by hand or draft it from the commit history with
   [git-cliff](https://git-cliff.org/) and then tidy it:

   ```sh
   git cliff --unreleased --tag v2026.10.25 --prepend CHANGELOG.md
   ```

   The heading must be `## v2026.10.25` (the same version as the manifest).

3. Open a pull request titled like `chore: release v2026.10.25`. The **Version
   check** workflow confirms the version is an increase over `main` (including
   the AwesomeVersion rule above) and that the changelog section exists.

4. Merge it. The **Release on version bump** workflow then creates the annotated
   tag `v2026.10.25` and a GitHub release, marked as a pre-release for any
   suffixed version. The release notes are the `CHANGELOG.md` section. If there
   is none, notes are generated from the Conventional Commit subjects since the
   previous tag.

HACS shows the GitHub release to users, so the release notes are what they see
when an update is offered.

## Beta to stable

1. Cut a beta, for example `2026.10.22b1`, and merge it. CI publishes a
   pre-release.
2. Test it. If it needs fixes, merge them and cut the next beta on a later day
   if the day is 10 to 31 (for example `2026.10.23b1`, or `b2` on a
   single-digit day).
3. When it is good, set the plain date, for example `2026.10.25`, and merge. CI
   publishes a normal release.

HACS only offers pre-releases to users who enable **Show beta versions** for
this repository in HACS. Everyone else stays on the latest stable release.

## If the release did not happen

There is no manual release workflow. If the automatic release was missed or
failed, check the run under **Actions**, then tag and publish by hand from the
merged commit on `main`:

```sh
git tag -a v2026.10.25 -m v2026.10.25 <commit>
git push origin v2026.10.25
gh release create v2026.10.25 --verify-tag --title v2026.10.25 \
  --notes-file notes.md
```

Add `--prerelease` for suffixed versions such as `2026.10.22b1`. Take the notes
from the version's `CHANGELOG.md` section. Never push a release commit to
`main` to do this.

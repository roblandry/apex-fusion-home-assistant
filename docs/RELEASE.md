# Releasing

Releases are cut by CI when a pull request that bumps the version is merged to
`main`. Nobody tags by hand and nothing is committed to `main` directly.

## Versioning policy

Versions are calendar based: `YYYY.M.D`, with an optional pre-release suffix.

| Version             | Meaning                    | GitHub release |
| ------------------- | -------------------------- | -------------- |
| `2026.10.22-beta.1` | beta 1, cut on 22 Oct 2026 | pre-release    |
| `2026.10.25`        | stable, cut on 25 Oct 2026 | normal release |

- Month and day have no leading zeros (`2026.3.5`, not `2026.03.05`).
- Use the date you cut the release (UTC). A version dated after today (UTC) is
  rejected; an earlier date is fine, so a PR opened yesterday can merge today.
- Suffixes are `-alpha.N`, `-beta.N` and `-rc.N`. Betas are the normal choice.
  They order as `-alpha.1 < -beta.1 < -beta.2 < -rc.1 < stable`.
- **Never go past `beta.9`** (the cap is for betas; alpha and rc numbers are not capped). If a day's betas run out, roll the date forward to
  today and start again at `beta.1`. The tooling refuses `beta.10` and higher.
- The dash form is deliberate: Home Assistant and HACS rank it correctly on
  every day of the month, which they do not for a compact `b1` suffix.
- Earlier versions (`0.1.x`) stay readable as the previous version, and the
  first CalVer release follows `0.1.6` directly. New `0.x` versions and the
  `b1` style are not accepted.
- There are no backports. Fixes ship as a new release from `main`.

The version is stored in `custom_components/apex_fusion/manifest.json`, and
`scripts/bump-version.py` is the only thing that should edit it.

## Making a release

1. Branch from `main` and set the version:

   ```sh
   python3 scripts/bump-version.py --next-beta               # today's next beta
   python3 scripts/bump-version.py --stable                  # today, no suffix
   python3 scripts/bump-version.py --set 2026.10.25          # an exact version
   ```

   `--next-beta` gives `-beta.N+1` if the current version is a beta from today,
   otherwise `-beta.1` for today's date. `--stable` writes today's date with no
   suffix. `--get` prints the current version and `--check` fails if the
   version sources disagree.

2. Add a section for the new version at the top of `CHANGELOG.md`, under the
   header. Either write it by hand or draft it from the commit history with
   [git-cliff](https://git-cliff.org/) and then tidy it:

   ```sh
   git cliff --unreleased --tag v2026.10.25 --prepend CHANGELOG.md
   ```

   The heading must be `## v2026.10.25` (the same version as the manifest).

3. Open a pull request titled like `chore: release v2026.10.25`. The **Version
   check** workflow confirms the version is an increase over `main` (by both
   PEP 440 and AwesomeVersion ordering, the latter being what Home Assistant
   and HACS use) and that the changelog section exists.

4. Merge it. The **Release on version bump** workflow then, if this push
   raised the version, creates the annotated
   tag `v2026.10.25` and a GitHub release, marked as a pre-release for any
   suffixed version. The release notes are the `CHANGELOG.md` section. If there
   is none, notes are generated from the Conventional Commit subjects since the
   previous tag.

HACS shows the GitHub release to users, so the release notes are what they see
when an update is offered.

## Beta to stable

1. Cut a beta, for example `2026.10.22-beta.1`, and merge it. CI publishes a
   pre-release.
2. Test it. If it needs fixes, merge them and cut `2026.10.22-beta.2`, and so
   on (up to `beta.9`).
3. When it is good, run `--stable` (or `--set`) for a plain date such as
   `2026.10.25` and merge. CI publishes a normal release.

HACS only offers pre-releases to users who enable **Show beta versions** for
this repository in HACS. Everyone else stays on the latest stable release.

## If the release did not happen

There is no manual release workflow. The automatic release only happens when a
push to `main` raises the version, so re-running it or pushing an unrelated
change will not release anything. If the automatic release was missed or
failed, check the run under **Actions**, then finish it by hand.

The workflow can fail after pushing the tag but before creating the GitHub
release, so the snippet below checks the tag on the **remote** and only then
decides what to do. Fill in the three variables, then paste the whole block. It
runs in a subshell and stops at the first failure, so nothing after a failed
check can run. `COMMIT` is the merge commit on `main` that raised the version,
and the notes come from the version's `CHANGELOG.md` section.

```sh
(
  set -euo pipefail
  TAG=v2026.10.25
  COMMIT=<release merge commit sha>
  NOTES=notes.md
  PRERELEASE=false   # true for suffixed versions such as 2026.10.22-beta.1

  release() {
    if [ "$PRERELEASE" = true ]; then
      gh release create "$TAG" --verify-tag --title "$TAG" \
        --notes-file "$NOTES" --prerelease
    else
      gh release create "$TAG" --verify-tag --title "$TAG" --notes-file "$NOTES"
    fi
  }

  git fetch origin main
  want=$(git rev-parse "$COMMIT^{commit}")
  # Where the tag points on the remote: the peeled commit of an annotated tag,
  # or the tag itself if it is lightweight.
  remote=$(git ls-remote origin "refs/tags/$TAG^{}" | cut -f1)
  if [ -z "$remote" ]; then
    remote=$(git ls-remote origin "refs/tags/$TAG" | cut -f1)
  fi

  if [ -z "$remote" ]; then
    git tag -a "$TAG" -m "$TAG" "$want"
    git push origin "refs/tags/$TAG"
    release
  elif [ "$remote" = "$want" ]; then
    release
  else
    echo "error: $TAG on the remote points at $remote, not $want; not touching it" >&2
    exit 1
  fi
)
```

If it reports a mismatch, stop and ask before changing the tag. Never push a
release commit to `main` to do this.

#!/usr/bin/env python3
"""Read, bump and validate the project version.

The version lives in ``custom_components/apex_fusion/manifest.json``. To track
another file, add a ``VersionFile`` entry to ``SOURCES``.

Usage (run from anywhere; paths resolve relative to the repo root):

    scripts/bump-version.py --get
    scripts/bump-version.py --check
    scripts/bump-version.py --set 0.2.0
    scripts/bump-version.py --bump patch
    scripts/bump-version.py --check-increase 0.1.6
    scripts/bump-version.py --check-changelog
    scripts/bump-version.py --changelog-notes

Versions are ``X.Y.Z``, optionally with a PEP 440 pre-release suffix ``aN``,
``bN`` or ``rcN`` (``0.2.0b1``, ``0.2.0rc1``). Ordering is
``0.1.6 < 0.2.0a1 < 0.2.0b1 < 0.2.0b2 < 0.2.0rc1 < 0.2.0``.
The script never commits, tags or releases. CI does that after the bump merges.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$",
)
_PRERELEASE_RANK = {"a": 0, "b": 1, "rc": 2}


@dataclass(frozen=True)
class VersionFile:
    """One file that carries the project version literal."""

    path: str  # relative to the repo root
    pattern: re.Pattern[str]  # group 1 is the version
    template: str  # the replacement for the whole match, with {version}


SOURCES: list[VersionFile] = [
    VersionFile(
        path="custom_components/apex_fusion/manifest.json",
        pattern=re.compile(r'^  "version": "([^"]+)"', re.MULTILINE),
        template='  "version": "{version}"',
    ),
]


def is_valid(version: str) -> bool:
    """Return True if *version* is plain semver or has a supported suffix."""
    return _SEMVER_RE.fullmatch(version) is not None


def is_prerelease(version: str) -> bool:
    """Return True if *version* carries an a/b/rc suffix."""
    match = _SEMVER_RE.fullmatch(version)
    return match is not None and match.group(4) is not None


def sort_key(version: str) -> tuple[int, int, int, int, int, int]:
    """Return a key that orders valid versions (PEP 440 pre-release order)."""
    match = _SEMVER_RE.fullmatch(version)
    if match is None:
        raise SystemExit(f"error: {version!r} is not a valid version")
    major, minor, patch, tag, num = match.groups()
    if tag is None:
        return (int(major), int(minor), int(patch), 1, 0, 0)
    return (int(major), int(minor), int(patch), 0, _PRERELEASE_RANK[tag], int(num))


def _read_current(source: VersionFile, root: Path) -> str:
    text = (root / source.path).read_text(encoding="utf-8")
    match = source.pattern.search(text)
    if match is None:
        raise SystemExit(
            f"error: version pattern did not match in {source.path}; "
            "update the regex in scripts/bump-version.py"
        )
    return match.group(1)


def _write_new(source: VersionFile, root: Path, version: str) -> bool:
    path = root / source.path
    if _read_current(source, root) == version:
        return False
    text = path.read_text(encoding="utf-8")
    line = source.template.format(version=version)
    path.write_text(source.pattern.sub(lambda _m: line, text, count=1), "utf-8")
    return True


def synchronized_version(root: Path = REPO_ROOT) -> str | None:
    """Return the version every source agrees on, or None after reporting drift."""
    versions = {s.path: _read_current(s, root) for s in SOURCES}
    if len(set(versions.values())) != 1:
        print("error: version drift across sources:", file=sys.stderr)
        for path, ver in versions.items():
            print(f"  {path}: {ver}", file=sys.stderr)
        return None
    return next(iter(versions.values()))


def changelog_section(version: str, root: Path = REPO_ROOT) -> str | None:
    """Return the CHANGELOG.md body for *version*, or None if there is none.

    Matches ``## 0.2.0`` and ``## v0.2.0`` (optionally followed by more text).
    """
    path = root / "CHANGELOG.md"
    if not path.exists():
        return None
    heading = re.compile(rf"^##\s+v?{re.escape(version)}(?:\s.*)?$")
    body: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if body is None:
            if heading.match(line):
                body = []
        elif line.startswith("## "):
            break
        else:
            body.append(line)
    if body is None:
        return None
    return "\n".join(body).strip() or None


def _set_version(version: str, root: Path) -> int:
    if not is_valid(version):
        print(
            f"error: {version!r} is not valid; expected X.Y.Z or X.Y.Z(a|b|rc)N",
            file=sys.stderr,
        )
        return 1
    changed = [s.path for s in SOURCES if _write_new(s, root, version)]
    if not changed:
        print(f"ok: all sources already on {version}")
        return 0
    print(f"set {len(changed)} file(s) to {version}:")
    for path in changed:
        print(f"  {path}")
    return 0


def _bump(part: str, root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    if is_prerelease(current):
        print(
            f"error: current version {current} is a pre-release; use --set",
            file=sys.stderr,
        )
        return 1
    major, minor, patch = (int(n) for n in current.split("."))
    if part == "major":
        new = f"{major + 1}.0.0"
    elif part == "minor":
        new = f"{major}.{minor + 1}.0"
    else:
        new = f"{major}.{minor}.{patch + 1}"
    return _set_version(new, root)


def _check(root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    if not is_valid(current):
        print(f"error: {current!r} is not a valid version", file=sys.stderr)
        return 1
    print(f"ok: {len(SOURCES)} source(s) on {current}")
    return 0


def _check_increase(base: str, root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    for label, value in (("current", current), ("base", base)):
        if not is_valid(value):
            print(f"error: {label} version {value!r} is not valid", file=sys.stderr)
            return 1
    if sort_key(current) <= sort_key(base):
        print(
            f"error: version {current} is not greater than base version {base}",
            file=sys.stderr,
        )
        return 1
    print(f"ok: {base} -> {current}")
    return 0


def _check_changelog(root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    if changelog_section(current, root) is None:
        print(
            f"error: CHANGELOG.md has no section (or an empty one) for {current}; "
            f"add a '## v{current}' heading with notes",
            file=sys.stderr,
        )
        return 1
    print(f"ok: CHANGELOG.md has a section for {current}")
    return 0


def _changelog_notes(root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    section = changelog_section(current, root)
    if section is not None:
        print(section)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; see the module docstring."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repo checkout to operate on (default: this repo).",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--get", action="store_true", help="Print the version.")
    action.add_argument("--check", action="store_true", help="Fail on drift.")
    action.add_argument("--set", metavar="X.Y.Z", help="Write a version.")
    action.add_argument(
        "--bump", choices=("major", "minor", "patch"), help="Increment the version."
    )
    action.add_argument(
        "--check-increase",
        metavar="BASE",
        help="Fail unless the version is greater than BASE.",
    )
    action.add_argument(
        "--check-changelog",
        action="store_true",
        help="Fail unless CHANGELOG.md has a section for the version.",
    )
    action.add_argument(
        "--changelog-notes",
        action="store_true",
        help="Print the CHANGELOG.md section for the version (empty if none).",
    )
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()

    if args.get:
        current = synchronized_version(root)
        if current is None:
            return 1
        print(current)
        return 0
    if args.check:
        return _check(root)
    if args.set is not None:
        return _set_version(args.set, root)
    if args.bump is not None:
        return _bump(args.bump, root)
    if args.check_increase is not None:
        return _check_increase(args.check_increase, root)
    if args.check_changelog:
        return _check_changelog(root)
    return _changelog_notes(root)


if __name__ == "__main__":
    sys.exit(main())

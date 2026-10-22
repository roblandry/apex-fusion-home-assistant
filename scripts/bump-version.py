#!/usr/bin/env python3
"""Read, set and validate the project version.

The version lives in ``custom_components/apex_fusion/manifest.json``. To track
another file, add a ``VersionFile`` entry to ``SOURCES``.

Versions are CalVer, ``YYYY.M.D`` with an optional pre-release suffix:

    2026.10.22-beta.1    beta 1 (also -alpha.N and -rc.N)
    2026.10.25           stable

Month and day have no leading zeros. Pre-release numbers run 1 to 9: there is
no ``beta.10``. When a day's betas run out, roll the date forward and start at
``beta.1``. Plain ``0.x.y`` versions and the earlier ``bN`` style (for example
``2026.10.22b1``) stay readable as the *previous* version, so moving from
``0.1.6`` to CalVer is allowed, but no new version may use them.

Usage (paths resolve relative to the repo root):

    scripts/bump-version.py --get
    scripts/bump-version.py --check
    scripts/bump-version.py --set 2026.10.22-beta.1
    scripts/bump-version.py --next-beta
    scripts/bump-version.py --stable
    scripts/bump-version.py --check-increase 0.1.6
    scripts/bump-version.py --check-changelog
    scripts/bump-version.py --changelog-notes

The script never commits, tags or releases. CI does that after the bump merges.

Ordering is checked two ways: PEP 440 precedence via ``packaging`` (alpha <
beta < rc < stable) and AwesomeVersion, which Home Assistant and HACS use to
decide "update available". ``--check-increase`` requires both to agree, and
fails if either package is not installed. The dash form is used
because AwesomeVersion ranks it correctly on every day of the month, which it
does not for ``bN`` suffixes on days 10 to 31.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# New style: 2026.10.22-beta.1. Old style (previous versions only): 2026.10.22b1.
_VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:-(alpha|beta|rc)\.(\d+)|(a|b|rc)(\d+)|\.dev(\d+))?$",
)
_OLD_STAGE = {"a": "alpha", "b": "beta", "rc": "rc"}
_PRERELEASE_CAP = 9

# The ordering checks need these. CI installs them with these pins (the
# awesomeversion pin matches Home Assistant's own).
AWESOMEVERSION_PIN = "25.8.0"
PACKAGING_PIN = "26.3"


class Parsed(NamedTuple):
    """A version split into its parts."""

    major: int
    minor: int
    patch: int
    stage: str  # "", "alpha", "beta", "rc" or "dev"
    num: int  # pre-release number, 0 for a final release
    dash: bool  # written as -beta.N (the only style new versions may use)


class VersionError(Exception):
    """A version is malformed or a transition is not allowed."""


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


def parse(version: str) -> Parsed | None:
    """Split *version* into parts, or return None if it has the wrong shape."""
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        return None
    major, minor, patch, stage, num, old_stage, old_num, dev = match.groups()
    if stage is not None:
        suffix = (stage, int(num), True)
    elif old_stage is not None:
        suffix = (_OLD_STAGE[old_stage], int(old_num), False)
    elif dev is not None:
        suffix = ("dev", int(dev), False)
    else:
        suffix = ("", 0, True)
    return Parsed(int(major), int(minor), int(patch), *suffix)


def _plain(number: str) -> bool:
    """Return True if *number* is written without leading zeros."""
    return str(int(number)) == number


def calver_problem(version: str) -> str | None:
    """Return why *version* is not an acceptable new CalVer version, or None."""
    parsed = parse(version)
    if parsed is None:
        return (
            f"{version!r} is not YYYY.M.D with an optional -alpha.N, -beta.N or "
            "-rc.N suffix (for example 2026.10.22-beta.1 or 2026.10.25)"
        )
    if not parsed.dash:
        return (
            f"{version!r} uses the old suffix style; write 2026.10.22-beta.1, "
            "not 2026.10.22b1"
        )
    if any(not _plain(n) for n in re.findall(r"\d+", version)):
        return f"{version!r} has a leading zero; write 2026.3.5, not 2026.03.05"
    if parsed.major == 0:
        return f"{version!r} looks like the old 0.x scheme; new versions are CalVer"
    try:
        dt.date(parsed.major, parsed.minor, parsed.patch)
    except ValueError:
        return f"{version!r} is not a real calendar date"
    if parsed.stage and parsed.num < 1:
        return f"{version!r}: pre-release numbers start at 1"
    if parsed.stage == "beta" and parsed.num > _PRERELEASE_CAP:
        return (
            f"{version!r} exceeds the beta.{_PRERELEASE_CAP} cap. Roll the date "
            "forward to today and reset to beta.1 instead"
        )
    return None


def future_problem(version: str, today: dt.date) -> str | None:
    """Return why *version* is dated after *today*, or None."""
    parsed = parse(version)
    if parsed is not None and _date(parsed) > (today.year, today.month, today.day):
        return (
            f"{version} is dated after today ({_stamp(today)}, UTC); "
            "use today's date or earlier"
        )
    return None


def is_legacy(version: str) -> bool:
    """Return True for versions that may only appear as the previous version.

    That is plain ``0.x.y`` and anything written in the old ``bN`` style.
    """
    parsed = parse(version)
    return parsed is not None and (
        (parsed.major == 0 and parsed.stage == "") or not parsed.dash
    )


def is_valid(version: str) -> bool:
    """Return True if *version* is CalVer or a readable previous version."""
    return is_legacy(version) or calver_problem(version) is None


def is_prerelease(version: str) -> bool:
    """Return True if *version* carries a pre-release suffix."""
    parsed = parse(version)
    return parsed is not None and parsed.stage != ""


def _import(module: str, package: str, pin: str) -> Any:
    """Import *module*, or fail with the exact install command for *package*."""
    try:
        return importlib.import_module(module)
    except ImportError:
        raise VersionError(
            f"{package} is required for version ordering; "
            f"run: python3 -m pip install {package}=={pin}"
        ) from None


def pep440(version: str) -> Any:
    """Return *version* as a ``packaging.version.Version`` (PEP 440 ordering)."""
    if parse(version) is None:
        raise VersionError(f"{version!r} is not a valid version")
    return _import("packaging.version", "packaging", PACKAGING_PIN).Version(version)


def awesome_greater(new: str, base: str) -> bool:
    """Return whether AwesomeVersion (used by HA and HACS) ranks *new* above *base*."""
    awesome = _import(
        "awesomeversion", "awesomeversion", AWESOMEVERSION_PIN
    ).AwesomeVersion
    return bool(awesome(new) > awesome(base))


def _stamp(today: dt.date) -> str:
    return f"{today.year}.{today.month}.{today.day}"


def _date(parsed: Parsed) -> tuple[int, int, int]:
    return (parsed.major, parsed.minor, parsed.patch)


def next_beta(current: str, today: dt.date) -> str:
    """Return the next beta after *current* for *today*."""
    parsed = parse(current)
    if parsed is None:
        raise VersionError(f"current version {current!r} is not valid")
    stamp = _stamp(today)
    if _date(parsed) < (today.year, today.month, today.day):
        return f"{stamp}-beta.1"
    if _date(parsed) > (today.year, today.month, today.day):
        raise VersionError(
            f"current version {current} is dated after today ({stamp}); use --set"
        )
    if parsed.stage != "beta":
        raise VersionError(
            f"{current} already has today's date and is not a beta; "
            "wait until tomorrow or use --set"
        )
    if parsed.num >= _PRERELEASE_CAP:
        raise VersionError(
            f"{current} is already beta.{_PRERELEASE_CAP}, the cap. Roll the "
            "date forward (a later day) and start at beta.1 with --set"
        )
    return f"{stamp}-beta.{parsed.num + 1}"


def stable(current: str, today: dt.date) -> str:
    """Return today's stable version, which must rank above *current*."""
    if parse(current) is None:
        raise VersionError(f"current version {current!r} is not valid")
    new = _stamp(today)
    if pep440(new) <= pep440(current):
        raise VersionError(f"{new} is not greater than the current version {current}")
    return new


def _today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


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

    Matches ``## 2026.10.22b1`` and ``## v2026.10.22b1`` (optionally followed by
    more text).
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


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def _apply(version: str, root: Path) -> int:
    changed = [s.path for s in SOURCES if _write_new(s, root, version)]
    if not changed:
        print(f"ok: all sources already on {version}")
        return 0
    print(f"set {len(changed)} file(s) to {version}:")
    for path in changed:
        print(f"  {path}")
    return 0


def _set_version(version: str, root: Path) -> int:
    problem = calver_problem(version)
    if problem is not None:
        return _fail(problem)
    return _apply(version, root)


def _advance(root: Path, make: Callable[[str, dt.date], str]) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    try:
        new = make(current, _today())
    except VersionError as exc:
        return _fail(str(exc))
    return _apply(new, root)


def _check(root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    if not is_valid(current):
        return _fail(calver_problem(current) or f"{current!r} is not valid")
    print(f"ok: {len(SOURCES)} source(s) on {current}")
    return 0


def _check_increase(base: str, root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    problem = calver_problem(current) or future_problem(current, _today())
    if problem is not None:
        return _fail(f"new version: {problem}")
    if not is_valid(base):
        return _fail(f"base version {base!r} is not valid")
    try:
        if pep440(current) <= pep440(base):
            return _fail(f"version {current} is not greater than base version {base}")
        if not awesome_greater(current, base):
            return _fail(
                f"AwesomeVersion (used by HA and HACS) does not rank {current} "
                f"above {base}, so an update would not be offered"
            )
    except VersionError as exc:
        return _fail(str(exc))
    print(f"ok: {base} -> {current}")
    return 0


def _check_changelog(root: Path) -> int:
    current = synchronized_version(root)
    if current is None:
        return 1
    if changelog_section(current, root) is None:
        return _fail(
            f"CHANGELOG.md has no section (or an empty one) for {current}; "
            f"add a '## v{current}' heading with notes"
        )
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
    action.add_argument("--set", metavar="VERSION", help="Write a CalVer version.")
    action.add_argument(
        "--next-beta",
        action="store_true",
        help="Write today's next beta (beta.N+1 on the same date, else beta.1).",
    )
    action.add_argument(
        "--stable",
        action="store_true",
        help="Write today's date with no suffix (a stable release).",
    )
    action.add_argument(
        "--check-increase",
        metavar="BASE",
        help="Fail unless the version is greater than BASE (PEP 440 and AwesomeVersion).",
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
    if args.next_beta:
        return _advance(root, next_beta)
    if args.stable:
        return _advance(root, stable)
    if args.check_increase is not None:
        return _check_increase(args.check_increase, root)
    if args.check_changelog:
        return _check_changelog(root)
    return _changelog_notes(root)


if __name__ == "__main__":
    sys.exit(main())

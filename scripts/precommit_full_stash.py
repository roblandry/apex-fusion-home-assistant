#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import sys
from typing import Sequence


def _run(cmd: Sequence[str], *, env: dict[str, str] | None = None) -> int:
    proc = subprocess.run(cmd, check=False, env=env)
    return int(proc.returncode)


def _capture(cmd: Sequence[str]) -> str:
    proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, text=True)
    return proc.stdout


def _repo_root() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return proc.stdout.strip()


def _has_unstaged_tracked_changes() -> bool:
    # Exit code: 0 = no changes, 1 = changes.
    return _run(["git", "diff", "--quiet"]) != 0


def _has_untracked_files() -> bool:
    out = _capture(["git", "ls-files", "--others", "--exclude-standard"])
    return bool(out.strip())


def _unstaged_changed_files() -> list[str]:
    out = _capture(["git", "diff", "--name-only"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def main() -> int:
    stashed = False
    exit_code = 0
    root = _repo_root()
    os.chdir(root)

    env = dict(os.environ)
    # Some environments enable safe-path mode which removes the current working
    # directory from sys.path. We want imports from the repo checkout.
    env.pop("PYTHONSAFEPATH", None)
    env["PYTHONPATH"] = root + (
        (":" + env["PYTHONPATH"]) if env.get("PYTHONPATH") else ""
    )
    try:
        if _has_unstaged_tracked_changes() or _has_untracked_files():
            # Keep staged snapshot intact, stash everything else (including untracked).
            rc = _run(
                [
                    "git",
                    "stash",
                    "push",
                    "-u",
                    "--keep-index",
                    "-m",
                    "pre-commit: temp stash (full suite)",
                ]
            )
            if rc != 0:
                print("Failed to stash WIP changes; aborting.", file=sys.stderr)
                exit_code = 1
                return exit_code
            stashed = True

        # Ruff: auto-fix + format. If it changes files, fail so the user can
        # review, re-stage, and retry the commit.
        exit_code = _run([sys.executable, "-m", "ruff", "check", ".", "--fix"], env=env)
        if exit_code != 0:
            return exit_code

        exit_code = _run([sys.executable, "-m", "ruff", "format", "."], env=env)
        if exit_code != 0:
            return exit_code

        changed = _unstaged_changed_files()
        if changed:
            print("Ruff modified files; please review and re-stage:", file=sys.stderr)
            for path in changed:
                print(f"- {path}", file=sys.stderr)
            return 1

        exit_code = _run(
            [
                sys.executable,
                "-m",
                "pyright",
                "--project",
                "pyrightconfig.precommit.json",
            ],
            env=env,
        )
        if exit_code != 0:
            return exit_code

        exit_code = _run([sys.executable, "-m", "pytest", "-q"], env=env)
        if exit_code != 0:
            return exit_code

        return 0
    finally:
        if stashed:
            pop_rc = _run(["git", "stash", "pop"])
            if pop_rc != 0:
                print(
                    "WARNING: Failed to re-apply stash cleanly. Your WIP is still in git stash.",
                    file=sys.stderr,
                )
                if exit_code == 0:
                    exit_code = 1


if __name__ == "__main__":
    raise SystemExit(main())

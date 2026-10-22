from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bump-version.py"
_MANIFEST = "custom_components/apex_fusion/manifest.json"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bump_version", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bv = _load()


def _make_root(tmp_path: Path, version: str = "0.1.6", changelog: str = "") -> Path:
    manifest = tmp_path / _MANIFEST
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domain": "apex_fusion", "version": version}, indent=2) + "\n",
        encoding="utf-8",
    )
    if changelog:
        (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


def _run(root: Path, *args: str) -> int:
    return int(bv.main(["--root", str(root), *args]))


def test_repo_sources_are_in_sync() -> None:
    assert bv.synchronized_version() is not None
    assert bv.is_valid(bv.synchronized_version())


@pytest.mark.parametrize(
    "version", ["0.1.6", "1.0.0", "0.2.0b1", "0.2.0rc1", "0.1.0a3", "10.20.30rc12"]
)
def test_valid_versions(version: str) -> None:
    assert bv.is_valid(version)


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "1.2",
        "v0.2.0",
        "0.2.0-beta1",
        "0.2.0.b1",
        "0.2.0b",
        "0.2.0beta1",
        "0.2.0.dev1",
        "0.2.0b1.post1",
        "0.2.0-rc.1",
        "",
    ],
)
def test_invalid_versions(version: str) -> None:
    assert not bv.is_valid(version)


def test_prerelease_detection() -> None:
    for version in ("0.2.0a1", "0.2.0b1", "0.2.0rc1"):
        assert bv.is_prerelease(version)
    assert not bv.is_prerelease("0.2.0")
    assert not bv.is_prerelease("garbage")


def test_ordering() -> None:
    ordered = [
        "0.1.0a1",
        "0.1.0b1",
        "0.1.0rc1",
        "0.1.0rc2",
        "0.1.0",
        "0.1.6",
        "0.2.0a1",
        "0.2.0b1",
        "0.2.0b2",
        "0.2.0b10",
        "0.2.0rc1",
        "0.2.0",
        "0.2.1",
        "1.0.0",
    ]
    assert sorted(reversed(ordered), key=bv.sort_key) == ordered


def test_sort_key_rejects_invalid() -> None:
    with pytest.raises(SystemExit):
        bv.sort_key("nope")


def test_get_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--get") == 0
    assert capsys.readouterr().out.strip() == "0.1.6"
    assert _run(root, "--check") == 0


def test_check_rejects_invalid_version(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path, "banana"), "--check") == 1


def test_missing_pattern_is_fatal(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    (root / _MANIFEST).write_text("{}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _run(root, "--get")


def test_drift_is_reported(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _make_root(tmp_path)
    other = root / "other.txt"
    other.write_text('version = "9.9.9"\n', encoding="utf-8")
    extra = bv.VersionFile(
        path="other.txt",
        pattern=bv.re.compile(r'^version = "([^"]+)"', bv.re.MULTILINE),
        template='version = "{version}"',
    )
    monkeypatch.setattr(bv, "SOURCES", [*bv.SOURCES, extra])

    assert _run(root, "--check") == 1
    assert _run(root, "--get") == 1
    assert _run(root, "--bump", "patch") == 1
    assert _run(root, "--check-increase", "0.0.1") == 1
    assert _run(root, "--check-changelog") == 1
    assert _run(root, "--changelog-notes") == 1
    assert "drift" in capsys.readouterr().err

    # --set brings every source together.
    assert _run(root, "--set", "1.0.0") == 0
    assert other.read_text(encoding="utf-8") == 'version = "1.0.0"\n'
    assert _run(root, "--check") == 0


def test_set_writes_manifest_and_preserves_the_rest(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--set", "0.2.0") == 0
    data = json.loads((root / _MANIFEST).read_text(encoding="utf-8"))
    assert data == {"domain": "apex_fusion", "version": "0.2.0"}
    assert _run(root, "--set", "0.2.0") == 0  # idempotent


def test_set_rejects_invalid(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--set", "v0.2.0") == 1
    assert bv.synchronized_version(root) == "0.1.6"


@pytest.mark.parametrize(
    ("part", "expected"),
    [("patch", "0.1.7"), ("minor", "0.2.0"), ("major", "1.0.0")],
)
def test_bump(tmp_path: Path, part: str, expected: str) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--bump", part) == 0
    assert bv.synchronized_version(root) == expected


def test_bump_refuses_prerelease(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "0.2.0rc1")
    assert _run(root, "--bump", "patch") == 1


def test_check_increase(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "0.1.7")
    assert _run(root, "--check-increase", "0.1.6") == 0
    assert _run(root, "--check-increase", "0.1.7") == 1
    assert _run(root, "--check-increase", "0.2.0") == 1
    assert _run(root, "--check-increase", "garbage") == 1


def test_check_increase_rejects_invalid_current(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path, "banana"), "--check-increase", "0.1.6") == 1


def test_prerelease_to_final_is_an_increase(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "0.2.0")
    assert _run(root, "--check-increase", "0.2.0rc1") == 0


_CHANGELOG = """# Changelog

## v0.1.7

### Fixes

- one

## v0.1.6

### Fixes

- two

## 0.1.5

## v0.1.40

- not this one
"""


def test_changelog_section(tmp_path: Path) -> None:
    root = _make_root(tmp_path, changelog=_CHANGELOG)
    assert bv.changelog_section("0.1.7", root) == "### Fixes\n\n- one"
    assert bv.changelog_section("0.1.6", root) == "### Fixes\n\n- two"
    assert bv.changelog_section("0.1.5", root) is None  # empty section
    assert bv.changelog_section("0.1.4", root) is None
    assert bv.changelog_section("0.1.40", root) == "- not this one"


def test_check_changelog_and_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _make_root(tmp_path, "0.1.7", changelog=_CHANGELOG)
    assert _run(root, "--check-changelog") == 0
    capsys.readouterr()
    assert _run(root, "--changelog-notes") == 0
    assert capsys.readouterr().out.strip() == "### Fixes\n\n- one"

    missing = _make_root(tmp_path / "m", "0.9.9", changelog=_CHANGELOG)
    assert _run(missing, "--check-changelog") == 1
    capsys.readouterr()
    assert _run(missing, "--changelog-notes") == 0
    assert capsys.readouterr().out == ""


def test_no_changelog_file(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert bv.changelog_section("0.1.6", root) is None
    assert _run(root, "--check-changelog") == 1

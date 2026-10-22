from __future__ import annotations

import datetime as dt
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


def _today(monkeypatch: pytest.MonkeyPatch, year: int, month: int, day: int) -> None:
    monkeypatch.setattr(bv, "_today", lambda: dt.date(year, month, day))


def test_repo_sources_are_in_sync() -> None:
    version = bv.synchronized_version()
    assert version is not None
    assert bv.is_valid(version)


@pytest.mark.parametrize(
    "version",
    [
        "2026.10.22b1",
        "2026.10.25",
        "2026.1.5",
        "2026.12.31rc9",
        "2026.3.4a1",
        "2026.10.22.dev3",
        "2028.2.29",
        "0.1.6",  # legacy, readable as the previous version
    ],
)
def test_valid_versions(version: str) -> None:
    assert bv.is_valid(version)


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "2026.10",
        "v2026.10.22",
        "2026.10.22-beta1",
        "2026.10.22-rc.1",
        "2026.10.22.b1",
        "2026.10.22b",
        "2026.10.22beta1",
        "2026.10.22b1.post1",
        "2026.10.22b10",
        "2026.10.22rc10",
        "2026.10.22b0",
        "2026.10.22b01",
        "2026.010.22",
        "2026.10.022",
        "2026.03.5",
        "2026.2.30",
        "2027.13.1",
        "2026.10.0",
        "0.1.0b1",  # no new 0.x pre-releases
        "0.2.0-beta1",
        "",
    ],
)
def test_invalid_versions(version: str) -> None:
    assert not bv.is_valid(version)


def test_legacy_cannot_be_set_but_is_readable() -> None:
    assert bv.is_legacy("0.1.6")
    assert not bv.is_legacy("2026.10.25")
    assert not bv.is_legacy("garbage")
    assert "0.x" in bv.calver_problem("0.2.0")
    assert bv.calver_problem("2026.10.25") is None


def test_cap_message_says_to_roll_the_date() -> None:
    problem = bv.calver_problem("2026.10.22b10")
    assert problem is not None
    assert "cap" in problem
    assert "Roll the date" in problem


def test_prerelease_detection() -> None:
    for version in ("2026.10.22a1", "2026.10.22b1", "2026.10.22rc1", "2026.1.1.dev1"):
        assert bv.is_prerelease(version)
    assert not bv.is_prerelease("2026.10.22")
    assert not bv.is_prerelease("garbage")


def test_ordering() -> None:
    ordered = [
        "0.1.6",
        "2026.10.4.dev1",
        "2026.10.4a1",
        "2026.10.4b1",
        "2026.10.4b2",
        "2026.10.4b9",
        "2026.10.4rc1",
        "2026.10.4",
        "2026.10.22b1",
        "2026.10.22",
        "2026.11.1b1",
        "2027.1.1",
    ]
    assert sorted(reversed(ordered), key=bv.sort_key) == ordered


def test_sort_key_rejects_invalid() -> None:
    with pytest.raises(bv.VersionError):
        bv.sort_key("nope")


def test_get_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _make_root(tmp_path, "2026.10.22b1")
    assert _run(root, "--get") == 0
    assert capsys.readouterr().out.strip() == "2026.10.22b1"
    assert _run(root, "--check") == 0


def test_check_accepts_legacy_and_rejects_garbage(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path / "a"), "--check") == 0
    assert _run(_make_root(tmp_path / "b", "banana"), "--check") == 1
    assert _run(_make_root(tmp_path / "c", "2026.10.22b10"), "--check") == 1


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
    assert _run(root, "--next-beta") == 1
    assert _run(root, "--check-increase", "0.0.1") == 1
    assert _run(root, "--check-changelog") == 1
    assert _run(root, "--changelog-notes") == 1
    assert "drift" in capsys.readouterr().err

    # --set brings every source together.
    assert _run(root, "--set", "2026.10.25") == 0
    assert other.read_text(encoding="utf-8") == 'version = "2026.10.25"\n'
    assert _run(root, "--check") == 0


def test_set_writes_manifest_and_preserves_the_rest(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--set", "2026.10.22b1") == 0
    data = json.loads((root / _MANIFEST).read_text(encoding="utf-8"))
    assert data == {"domain": "apex_fusion", "version": "2026.10.22b1"}
    assert _run(root, "--set", "2026.10.22b1") == 0  # idempotent


@pytest.mark.parametrize(
    "version", ["v2026.10.22", "2026.10.22b10", "2026.03.05", "0.2.0"]
)
def test_set_rejects_invalid(tmp_path: Path, version: str) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--set", version) == 1
    assert bv.synchronized_version(root) == "0.1.6"


def test_next_beta_new_date() -> None:
    today = dt.date(2026, 3, 5)
    assert bv.next_beta("0.1.6", today) == "2026.3.5b1"
    assert bv.next_beta("2026.3.4b7", today) == "2026.3.5b1"
    assert bv.next_beta("2026.3.4", today) == "2026.3.5b1"
    # A two-digit day is fine when the date is new.
    assert bv.next_beta("2026.10.21b3", dt.date(2026, 10, 22)) == "2026.10.22b1"


def test_next_beta_same_date_increments() -> None:
    today = dt.date(2026, 3, 5)
    assert bv.next_beta("2026.3.5b1", today) == "2026.3.5b2"
    assert bv.next_beta("2026.3.5b8", today) == "2026.3.5b9"


def test_next_beta_cap_refuses() -> None:
    with pytest.raises(bv.VersionError, match="cap"):
        bv.next_beta("2026.3.5b9", dt.date(2026, 3, 5))


def test_next_beta_same_date_non_beta_refuses() -> None:
    for current in ("2026.3.5", "2026.3.5rc1", "2026.3.5a1"):
        with pytest.raises(bv.VersionError, match="not a beta"):
            bv.next_beta(current, dt.date(2026, 3, 5))


def test_next_beta_future_date_refuses() -> None:
    with pytest.raises(bv.VersionError, match="after today"):
        bv.next_beta("2026.3.9", dt.date(2026, 3, 5))


def test_next_beta_rejects_invalid_current() -> None:
    with pytest.raises(bv.VersionError):
        bv.next_beta("banana", dt.date(2026, 3, 5))


def test_next_beta_refuses_same_date_on_two_digit_day() -> None:
    with pytest.raises(bv.VersionError, match="later date"):
        bv.next_beta("2026.10.22b1", dt.date(2026, 10, 22))


def test_stable_new_date() -> None:
    assert bv.stable("2026.10.22b1", dt.date(2026, 10, 25)) == "2026.10.25"
    assert bv.stable("0.1.6", dt.date(2026, 10, 25)) == "2026.10.25"
    assert bv.stable("2026.10.4", dt.date(2026, 10, 5)) == "2026.10.5"


def test_stable_same_date_single_digit_day_promotes_beta() -> None:
    assert bv.stable("2026.10.4b2", dt.date(2026, 10, 4)) == "2026.10.4"


def test_stable_refuses() -> None:
    with pytest.raises(bv.VersionError, match="later date"):
        bv.stable("2026.10.22b1", dt.date(2026, 10, 22))
    with pytest.raises(bv.VersionError, match="not greater"):
        bv.stable("2026.10.4", dt.date(2026, 10, 4))
    with pytest.raises(bv.VersionError, match="not greater"):
        bv.stable("2026.10.9", dt.date(2026, 10, 4))
    with pytest.raises(bv.VersionError):
        bv.stable("banana", dt.date(2026, 10, 4))


def test_next_beta_and_stable_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _make_root(tmp_path)
    _today(monkeypatch, 2026, 10, 22)
    assert _run(root, "--next-beta") == 0
    assert bv.synchronized_version(root) == "2026.10.22b1"
    capsys.readouterr()

    assert _run(root, "--next-beta") == 1  # same date, two-digit day
    assert _run(root, "--stable") == 1
    assert "later date" in capsys.readouterr().err
    assert bv.synchronized_version(root) == "2026.10.22b1"

    _today(monkeypatch, 2026, 10, 25)
    assert _run(root, "--stable") == 0
    assert bv.synchronized_version(root) == "2026.10.25"

    _today(monkeypatch, 2026, 10, 9)  # now in the past
    assert _run(root, "--next-beta") == 1
    assert "after today" in capsys.readouterr().err


def test_next_beta_cli_uses_utc_date(tmp_path: Path) -> None:
    today = dt.datetime.now(dt.timezone.utc).date()
    root = _make_root(tmp_path)
    assert _run(root, "--next-beta") == 0
    version = bv.synchronized_version(root)
    # Allow for the clock crossing midnight UTC between the two reads.
    assert version in {f"{d.year}.{d.month}.{d.day}b1" for d in (today, bv._today())}


def test_ordering_matches_packaging() -> None:
    packaging_version = pytest.importorskip("packaging.version")
    versions = [
        "0.1.6",
        "2026.10.4.dev1",
        "2026.10.4a1",
        "2026.10.4b1",
        "2026.10.4b9",
        "2026.10.4rc1",
        "2026.10.4",
        "2026.10.22b1",
        "2026.10.22",
    ]
    for low in versions:
        for high in versions:
            assert (bv.sort_key(low) < bv.sort_key(high)) == (
                packaging_version.Version(low) < packaging_version.Version(high)
            )


def test_check_increase_ordering(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.4b2")
    assert _run(root, "--check-increase", "2026.10.4b1") == 0
    assert _run(root, "--check-increase", "0.1.6") == 0
    assert _run(root, "--check-increase", "2026.10.4b2") == 1
    assert _run(root, "--check-increase", "2026.10.5") == 1
    assert _run(root, "--check-increase", "garbage") == 1


def test_stable_promotion_is_an_increase(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.25")
    assert _run(root, "--check-increase", "2026.10.22b1") == 0


def test_check_increase_rejects_non_calver_current(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path / "a", "0.1.7"), "--check-increase", "0.1.6") == 1
    assert _run(_make_root(tmp_path / "b", "banana"), "--check-increase", "0.1.6") == 1


def test_first_transition_from_legacy(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.22b1")
    assert _run(root, "--check-increase", "0.1.6") == 0


def test_awesomeversion_gate(tmp_path: Path) -> None:
    pytest.importorskip("awesomeversion")
    # Same date on a two-digit day: PEP 440 says greater, AwesomeVersion
    # cannot rank it, so the check must fail.
    same_day = _make_root(tmp_path / "a", "2026.10.22b2")
    assert _run(same_day, "--check-increase", "2026.10.22b1") == 1
    stable_same_day = _make_root(tmp_path / "b", "2026.10.22")
    assert _run(stable_same_day, "--check-increase", "2026.10.22b1") == 1
    # A later date passes.
    later = _make_root(tmp_path / "c", "2026.10.25")
    assert _run(later, "--check-increase", "2026.10.22b1") == 0
    # Single-digit days rank fine on the same date.
    single = _make_root(tmp_path / "d", "2026.10.4b2")
    assert _run(single, "--check-increase", "2026.10.4b1") == 0
    # And the first move from the legacy version.
    first = _make_root(tmp_path / "e", "2026.10.22b1")
    assert _run(first, "--check-increase", "0.1.6") == 0


def test_awesome_greater_values() -> None:
    pytest.importorskip("awesomeversion")
    assert bv.awesome_greater("2026.10.22b1", "0.1.6") is True
    assert bv.awesome_greater("2026.10.22b2", "2026.10.22b1") is False


def test_awesomeversion_missing_is_skipped(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "awesomeversion", None)
    assert bv.awesome_greater("2026.10.25", "0.1.6") is None
    root = _make_root(tmp_path, "2026.10.25")
    assert _run(root, "--check-increase", "0.1.6") == 0
    assert "skipped" in capsys.readouterr().err


_CHANGELOG = """# Changelog

## v2026.10.25

### Fixes

- one

## v2026.10.22b1

### Fixes

- two

## 2026.10.20

## v2026.10.2

- not this one
"""


def test_changelog_section(tmp_path: Path) -> None:
    root = _make_root(tmp_path, changelog=_CHANGELOG)
    assert bv.changelog_section("2026.10.25", root) == "### Fixes\n\n- one"
    assert bv.changelog_section("2026.10.22b1", root) == "### Fixes\n\n- two"
    assert bv.changelog_section("2026.10.20", root) is None  # empty section
    assert bv.changelog_section("2026.10.1", root) is None
    assert bv.changelog_section("2026.10.2", root) == "- not this one"


def test_check_changelog_and_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _make_root(tmp_path, "2026.10.25", changelog=_CHANGELOG)
    assert _run(root, "--check-changelog") == 0
    capsys.readouterr()
    assert _run(root, "--changelog-notes") == 0
    assert capsys.readouterr().out.strip() == "### Fixes\n\n- one"

    missing = _make_root(tmp_path / "m", "2026.12.9", changelog=_CHANGELOG)
    assert _run(missing, "--check-changelog") == 1
    capsys.readouterr()
    assert _run(missing, "--changelog-notes") == 0
    assert capsys.readouterr().out == ""


def test_no_changelog_file(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert bv.changelog_section("0.1.6", root) is None
    assert _run(root, "--check-changelog") == 1

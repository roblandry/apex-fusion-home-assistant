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
_real_today = bv._today


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


@pytest.fixture(autouse=True)
def _far_future_today(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin "today" late enough that fixture versions are never future-dated."""
    _today(monkeypatch, 2030, 1, 1)


def test_repo_sources_are_in_sync() -> None:
    version = bv.synchronized_version()
    assert version is not None
    assert bv.is_valid(version)


@pytest.mark.parametrize(
    "version",
    [
        "2026.10.22-beta.1",
        "2026.10.25",
        "2026.1.5",
        "2026.12.31-rc.9",
        "2026.3.4-alpha.1",
        "2028.2.29",
        "2026.10.22-beta.9",
        "2026.10.22-alpha.10",  # the cap is for betas only
        "2026.10.22-rc.10",
        "2026.10.22-rc.99",
    ],
)
def test_valid_new_versions(version: str) -> None:
    assert bv.calver_problem(version) is None
    assert bv.is_valid(version)
    assert not bv.is_legacy(version)


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "2026.10",
        "v2026.10.22",
        "v2026.10.22-beta.1",
        "2026.10.22-beta1",
        "2026.10.22-beta",
        "2026.10.22-beta.",
        "2026.10.22-beta.0",
        "2026.10.22-beta.10",
        "2026.10.22-pre.1",
        "2026.10.22-beta.01",
        "2026.10.22-foo.1",
        "2026.10.22-beta.1.2",
        "2026.10.22b1",  # old style: previous version only
        "2026.10.22rc1",
        "2026.10.22.dev1",
        "2026.010.22",
        "2026.10.022",
        "2026.03.5",
        "2026.2.30",
        "2027.13.1",
        "2026.10.0",
        "0.1.6",  # legacy: previous version only
        "0.2.0-beta.1",
        "",
    ],
)
def test_invalid_as_new_versions(version: str) -> None:
    assert bv.calver_problem(version) is not None


@pytest.mark.parametrize(
    "version", ["0.1.6", "2026.10.22b1", "2026.10.22rc2", "2026.10.4.dev1"]
)
def test_previous_versions_stay_readable(version: str) -> None:
    assert bv.is_legacy(version)
    assert bv.is_valid(version)


@pytest.mark.parametrize("version", ["banana", "v0.1.6", "2026.10.22-beta1", ""])
def test_garbage_is_not_valid(version: str) -> None:
    assert not bv.is_valid(version)
    assert not bv.is_legacy(version)


def test_cap_message_says_to_roll_the_date() -> None:
    problem = bv.calver_problem("2026.10.22-beta.10")
    assert problem is not None
    assert "cap" in problem
    assert "Roll the date" in problem


def test_old_style_message_names_the_new_form() -> None:
    problem = bv.calver_problem("2026.10.22b1")
    assert problem is not None
    assert "-beta.1" in problem


def test_prerelease_detection() -> None:
    for version in (
        "2026.10.22-alpha.1",
        "2026.10.22-beta.1",
        "2026.10.22-rc.1",
        "2026.10.22b1",
    ):
        assert bv.is_prerelease(version)
    assert not bv.is_prerelease("2026.10.22")
    assert not bv.is_prerelease("garbage")


_ORDERED = [
    "0.1.6",
    "2026.10.4.dev1",
    "2026.10.4-alpha.1",
    "2026.10.4-beta.1",
    "2026.10.4-beta.2",
    "2026.10.4-beta.9",
    "2026.10.4-rc.1",
    "2026.10.4",
    "2026.10.22-beta.1",
    "2026.10.22-beta.2",
    "2026.10.22-rc.1",
    "2026.10.22",
    "2026.11.1-beta.1",
    "2027.1.1",
]


def test_ordering() -> None:
    # Strictly increasing under PEP 440, via packaging.
    for low, high in zip(_ORDERED, _ORDERED[1:], strict=False):
        assert bv.pep440(low) < bv.pep440(high), (low, high)
    assert bv.pep440("2026.10.22-beta.1") == bv.pep440("2026.10.22b1")


def test_beta_numbers_compare_numerically() -> None:
    assert bv.pep440("2026.10.22-beta.9") > bv.pep440("2026.10.22-beta.2")
    assert bv.pep440("2026.10.22-rc.1") > bv.pep440("2026.10.22-beta.9")
    assert bv.pep440("2026.10.22") > bv.pep440("2026.10.22-rc.9")
    assert bv.pep440("2026.10.22-beta.1") > bv.pep440("0.1.6")


def test_old_and_new_styles_order_together() -> None:
    assert bv.pep440("2026.10.22b2") < bv.pep440("2026.10.22-beta.3")
    assert bv.pep440("2026.10.22-beta.1") < bv.pep440("2026.10.22rc1")


def test_pep440_rejects_invalid() -> None:
    with pytest.raises(bv.VersionError, match="not a valid"):
        bv.pep440("nope")


def test_get_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _make_root(tmp_path, "2026.10.22-beta.1")
    assert _run(root, "--get") == 0
    assert capsys.readouterr().out.strip() == "2026.10.22-beta.1"
    assert _run(root, "--check") == 0


def test_check_accepts_previous_style_and_rejects_garbage(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path / "a"), "--check") == 0
    assert _run(_make_root(tmp_path / "b", "2026.10.22b1"), "--check") == 0
    assert _run(_make_root(tmp_path / "c", "banana"), "--check") == 1
    assert _run(_make_root(tmp_path / "d", "2026.10.22-beta.10"), "--check") == 1


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
    assert _run(root, "--stable") == 1
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
    assert _run(root, "--set", "2026.10.22-beta.1") == 0
    data = json.loads((root / _MANIFEST).read_text(encoding="utf-8"))
    assert data == {"domain": "apex_fusion", "version": "2026.10.22-beta.1"}
    assert _run(root, "--set", "2026.10.22-beta.1") == 0  # idempotent


@pytest.mark.parametrize(
    "version",
    ["v2026.10.22", "2026.10.22-beta.10", "2026.10.22b1", "2026.03.05", "0.2.0"],
)
def test_set_rejects_invalid(tmp_path: Path, version: str) -> None:
    root = _make_root(tmp_path)
    assert _run(root, "--set", version) == 1
    assert bv.synchronized_version(root) == "0.1.6"


def test_next_beta_new_date() -> None:
    today = dt.date(2026, 3, 5)
    assert bv.next_beta("0.1.6", today) == "2026.3.5-beta.1"
    assert bv.next_beta("2026.3.4-beta.7", today) == "2026.3.5-beta.1"
    assert bv.next_beta("2026.3.4", today) == "2026.3.5-beta.1"
    assert bv.next_beta("2026.3.4b3", today) == "2026.3.5-beta.1"


def test_next_beta_same_date_increments_on_any_day() -> None:
    assert bv.next_beta("2026.3.5-beta.1", dt.date(2026, 3, 5)) == "2026.3.5-beta.2"
    assert (
        bv.next_beta("2026.10.22-beta.8", dt.date(2026, 10, 22)) == "2026.10.22-beta.9"
    )


def test_next_beta_continues_an_old_style_beta() -> None:
    assert bv.next_beta("2026.3.5b1", dt.date(2026, 3, 5)) == "2026.3.5-beta.2"


def test_next_beta_cap_refuses() -> None:
    with pytest.raises(bv.VersionError, match="cap"):
        bv.next_beta("2026.3.5-beta.9", dt.date(2026, 3, 5))


def test_next_beta_same_date_non_beta_refuses() -> None:
    for current in ("2026.3.5", "2026.3.5-rc.1", "2026.3.5-alpha.1"):
        with pytest.raises(bv.VersionError, match="not a beta"):
            bv.next_beta(current, dt.date(2026, 3, 5))


def test_next_beta_future_date_refuses() -> None:
    with pytest.raises(bv.VersionError, match="after today"):
        bv.next_beta("2026.3.9", dt.date(2026, 3, 5))


def test_next_beta_rejects_invalid_current() -> None:
    with pytest.raises(bv.VersionError):
        bv.next_beta("banana", dt.date(2026, 3, 5))


def test_stable() -> None:
    assert bv.stable("2026.10.22-beta.1", dt.date(2026, 10, 25)) == "2026.10.25"
    assert bv.stable("0.1.6", dt.date(2026, 10, 25)) == "2026.10.25"
    # Same date works: the dash form ranks correctly on every day.
    assert bv.stable("2026.10.22-beta.2", dt.date(2026, 10, 22)) == "2026.10.22"


def test_stable_refuses() -> None:
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
    assert bv.synchronized_version(root) == "2026.10.22-beta.1"
    assert _run(root, "--next-beta") == 0
    assert bv.synchronized_version(root) == "2026.10.22-beta.2"
    assert _run(root, "--stable") == 0
    assert bv.synchronized_version(root) == "2026.10.22"
    capsys.readouterr()

    assert _run(root, "--stable") == 1  # already stable today
    assert _run(root, "--next-beta") == 1  # same date, not a beta
    assert "not greater" in capsys.readouterr().err

    _today(monkeypatch, 2026, 10, 9)  # now in the past
    assert _run(root, "--next-beta") == 1
    assert "after today" in capsys.readouterr().err


def test_today_is_the_utc_date() -> None:
    before = dt.datetime.now(dt.timezone.utc).date()
    value = _real_today()
    after = dt.datetime.now(dt.timezone.utc).date()
    assert before <= value <= after


def test_future_problem() -> None:
    today = dt.date(2026, 10, 22)
    assert bv.future_problem("2026.10.23", today) is not None
    assert bv.future_problem("2026.10.23-beta.1", today) is not None
    assert bv.future_problem("2027.1.1", today) is not None
    assert bv.future_problem("2026.10.22", today) is None
    assert bv.future_problem("2026.10.21-beta.3", today) is None
    assert bv.future_problem("garbage", today) is None


def test_check_increase_rejects_future_dates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _today(monkeypatch, 2026, 10, 22)
    tomorrow = _make_root(tmp_path / "a", "2026.10.23-beta.1")
    assert _run(tomorrow, "--check-increase", "0.1.6") == 1
    far = _make_root(tmp_path / "b", "2030.1.1-beta.1")
    assert _run(far, "--check-increase", "0.1.6") == 1
    today = _make_root(tmp_path / "c", "2026.10.22-beta.1")
    assert _run(today, "--check-increase", "0.1.6") == 0
    yesterday = _make_root(tmp_path / "d", "2026.10.21")
    assert _run(yesterday, "--check-increase", "0.1.6") == 0


def test_check_increase_ordering(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.4-beta.2")
    assert _run(root, "--check-increase", "2026.10.4-beta.1") == 0
    assert _run(root, "--check-increase", "0.1.6") == 0
    assert _run(root, "--check-increase", "2026.10.4-beta.2") == 1
    assert _run(root, "--check-increase", "2026.10.5") == 1
    assert _run(root, "--check-increase", "garbage") == 1


def test_stable_promotion_is_an_increase(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.25")
    assert _run(root, "--check-increase", "2026.10.22-beta.1") == 0


def test_check_increase_rejects_non_calver_current(tmp_path: Path) -> None:
    assert _run(_make_root(tmp_path / "a", "0.1.7"), "--check-increase", "0.1.6") == 1
    assert _run(_make_root(tmp_path / "b", "banana"), "--check-increase", "0.1.6") == 1
    old_style = _make_root(tmp_path / "c", "2026.10.22b2")
    assert _run(old_style, "--check-increase", "2026.10.22b1") == 1


def test_first_transition_from_legacy(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.22-beta.1")
    assert _run(root, "--check-increase", "0.1.6") == 0


def test_transition_from_old_style_previous_version(tmp_path: Path) -> None:
    root = _make_root(tmp_path, "2026.10.25-beta.1")
    assert _run(root, "--check-increase", "2026.10.22b3") == 0


def test_awesomeversion_gate(tmp_path: Path) -> None:
    # A later beta on the same two-digit day ranks correctly.
    same_day = _make_root(tmp_path / "a", "2026.10.22-beta.2")
    assert _run(same_day, "--check-increase", "2026.10.22-beta.1") == 0
    stable_same_day = _make_root(tmp_path / "b", "2026.10.22")
    assert _run(stable_same_day, "--check-increase", "2026.10.22-beta.9") == 0
    rc = _make_root(tmp_path / "c", "2026.10.22-rc.1")
    assert _run(rc, "--check-increase", "2026.10.22-beta.9") == 0
    first = _make_root(tmp_path / "d", "2026.10.22-beta.1")
    assert _run(first, "--check-increase", "0.1.6") == 0
    # Going backwards is still rejected (here by the PEP 440 ordering).
    backwards = _make_root(tmp_path / "e", "2026.10.22-beta.1")
    assert _run(backwards, "--check-increase", "2026.10.22-beta.2") == 1


def test_awesomeversion_disagreement_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PEP 440 says greater but AwesomeVersion does not (the old bN-on-a-
    # two-digit-day quirk): the gate must block it.
    monkeypatch.setattr(bv, "awesome_greater", lambda new, base: False)
    root = _make_root(tmp_path, "2026.10.22-beta.2")
    assert _run(root, "--check-increase", "2026.10.22-beta.1") == 1
    assert "AwesomeVersion" in capsys.readouterr().err


def test_awesome_greater_values() -> None:
    assert bv.awesome_greater("2026.10.22-beta.1", "0.1.6") is True
    assert bv.awesome_greater("2026.10.22-beta.2", "2026.10.22-beta.1") is True
    assert bv.awesome_greater("2026.10.22", "2026.10.22-beta.2") is True
    assert bv.awesome_greater("2026.10.22-rc.1", "2026.10.22-beta.9") is True
    assert bv.awesome_greater("2026.10.22-beta.1", "2026.10.22-beta.2") is False


@pytest.mark.parametrize(
    ("module", "pin"),
    [("awesomeversion", "25.8.0"), ("packaging", "26.3")],
)
def test_missing_dependency_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    module: str,
    pin: str,
) -> None:
    monkeypatch.setitem(sys.modules, module, None)
    if module == "packaging":
        monkeypatch.setitem(sys.modules, "packaging.version", None)
    root = _make_root(tmp_path, "2026.10.25")
    assert _run(root, "--check-increase", "0.1.6") == 1
    err = capsys.readouterr().err
    assert f"pip install {module}=={pin}" in err
    # Commands that do not order versions still work without the packages.
    assert _run(root, "--get") == 0
    assert _run(root, "--check") == 0


def test_pins_match_the_workflows() -> None:
    workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    for name in ("release-on-version-bump.yml", "version-check.yml"):
        text = (workflows / name).read_text(encoding="utf-8")
        assert f"awesomeversion=={bv.AWESOMEVERSION_PIN}" in text
        assert f"packaging=={bv.PACKAGING_PIN}" in text


_CHANGELOG = """# Changelog

## v2026.10.25

### Fixes

- one

## v2026.10.22-beta.1

### Fixes

- two

## 2026.10.20

## v2026.10.2

- not this one
"""


def test_changelog_section(tmp_path: Path) -> None:
    root = _make_root(tmp_path, changelog=_CHANGELOG)
    assert bv.changelog_section("2026.10.25", root) == "### Fixes\n\n- one"
    assert bv.changelog_section("2026.10.22-beta.1", root) == "### Fixes\n\n- two"
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

"""Module update availability is driven by the status `swstat` value."""

from __future__ import annotations

from typing import Any

import pytest

from custom_components.apex_fusion import update


def _data(
    module: dict[str, Any], *, mconf_update: bool | None = None
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "raw": {"modules": [{"abaddr": 4, "present": True, **module}]}
    }
    if mconf_update is not None:
        data["config"] = {
            "mconf": [{"abaddr": 4, "hwtype": module["hwtype"], "update": mconf_update}]
        }
    return data


def _ref(data: dict[str, Any]) -> update._UpdateRef:
    (ref,) = update._module_refs(data, "SER")
    return ref


@pytest.mark.parametrize("mconf_update", [None, True, False])
def test_old_reports_update_available(mconf_update: bool | None) -> None:
    data = _data(
        {"hwtype": "FMM", "swrev": 24, "swstat": "OLD"}, mconf_update=mconf_update
    )
    ref = _ref(data)
    assert ref.installed_fn(data) == "24"
    assert ref.latest_fn(data) == "Update available"
    assert ref.update_flag_fn(data) is True


@pytest.mark.parametrize("swstat", ["OK", "PENDING", "pending", "", "???", None])
@pytest.mark.parametrize("mconf_update", [None, True, False])
def test_other_swstat_reports_no_update(
    swstat: str | None, mconf_update: bool | None
) -> None:
    module: dict[str, Any] = {"hwtype": "FMM", "swrev": 24}
    if swstat is not None:
        module["swstat"] = swstat
    data = _data(module, mconf_update=mconf_update)
    ref = _ref(data)
    assert ref.latest_fn(data) == "24"
    assert ref.update_flag_fn(data) is None


def test_legacy_update_string_is_not_an_update_signal() -> None:
    data = _data({"hwtype": "FMM", "swrev": 24, "swstat": "UPDATE"})
    assert _ref(data).latest_fn(data) == "24"


def test_swstat_is_case_and_whitespace_tolerant() -> None:
    assert update._module_swstat_update({"hwtype": "FMM", "swstat": " old "}) is True


@pytest.mark.parametrize("hwtype", ["IOTA", "MXM", "PM3", "iota"])
@pytest.mark.parametrize("mconf_update", [None, True])
def test_module_types_the_ui_never_updates(
    hwtype: str, mconf_update: bool | None
) -> None:
    data = _data(
        {"hwtype": hwtype, "swrev": 9, "swstat": "OLD"}, mconf_update=mconf_update
    )
    ref = _ref(data)
    assert ref.latest_fn(data) == "9"
    assert ref.update_flag_fn(data) is None


def test_old_hardware_trident_is_excluded() -> None:
    module = {"hwtype": "TRI", "hwrev": 2, "software": "5.05_AB12", "swstat": "OLD"}
    assert update._module_swstat_update(module) is None

    # Same hardware on firmware 5.06 or newer is offered normally.
    assert update._module_swstat_update({**module, "software": "5.06_CD21"}) is True
    # Other hardware revisions are offered normally.
    assert update._module_swstat_update({**module, "hwrev": 3}) is True
    # Unparseable firmware cannot prove the module is old hardware on old firmware.
    assert update._module_swstat_update({**module, "software": "bogus"}) is True
    # swrev is used when software is absent.
    no_sw = {"hwtype": "TRI", "hwrev": "2", "swrev": "5.01_AB12", "swstat": "OLD"}
    assert update._module_swstat_update(no_sw) is None
    # No firmware string at all.
    assert update._module_swstat_update({"hwtype": "TRI", "hwrev": 2, "swstat": "OLD"})


def test_missing_module_is_unknown() -> None:
    assert update._module_swstat_update(None) is None
    assert update._module_swstat_update({}) is None

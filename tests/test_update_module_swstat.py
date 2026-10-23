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
    assert (
        update._module_swstat_update({"hwtype": "FMM", "swstat": " old "}, {}) is True
    )


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


@pytest.mark.parametrize("hwtype", ["IOTA", "MXM", "PM3"])
@pytest.mark.parametrize("with_mconf", [False, True])
def test_excluded_module_ignores_reported_latest(hwtype: str, with_mconf: bool) -> None:
    data = _data(
        {
            "hwtype": hwtype,
            "software": "5.04_4D18",
            "latestFirmware": "5.05_3H19",
            "swstat": "OLD",
        },
        mconf_update=False if with_mconf else None,
    )
    ref = _ref(data)
    assert ref.latest_fn(data) == "5.04_4D18"
    assert ref.update_flag_fn(data) is None


def _tri(controller: str | None, module_sw: str, hwrev: Any = 2, **extra: Any):
    data = _data(
        {
            "hwtype": "TRI",
            "hwrev": hwrev,
            "software": module_sw,
            "latestFirmware": "5.15_6A26",
            "swstat": "OLD",
            **extra,
        }
    )
    if controller is not None:
        data["meta"] = {"software": controller}
    return data


@pytest.mark.parametrize(
    ("controller", "module_sw", "offered"),
    [
        # Controller software decides, not the module's.
        ("5.15J_6A26", "5.05_3H19", True),
        ("5.05_3H19", "5.06_1B21", False),
        # Exact threshold and the full release/build ordering.
        ("5.06_CD21", "5.01_1A20", True),
        ("5.06_4D21", "5.15_6A26", False),
        ("5.06_1B21", "5.15_6A26", False),
        ("5.06_CE21", "5.06_1B21", True),
        ("5.07_4C22", "5.01_1A20", True),
        ("4.53_AB17", "5.15_6A26", False),
        # Uncomparable controller software: excluded conservatively.
        ("bogus", "5.15_6A26", False),
        (None, "5.15_6A26", False),
    ],
)
def test_old_hardware_trident_follows_controller_software(
    controller: str | None, module_sw: str, offered: bool
) -> None:
    data = _tri(controller, module_sw)
    ref = _ref(data)
    assert (ref.update_flag_fn(data) is True) is offered
    if offered:
        assert ref.latest_fn(data) == "5.15_6A26"
    else:
        # Never an update, even with a newer reported latest.
        assert ref.latest_fn(data) == module_sw


@pytest.mark.parametrize("hwrev", [3, "3", None])
def test_other_trident_hardware_is_not_excluded(hwrev: Any) -> None:
    data = _tri("4.53_AB17", "5.05_3H19", hwrev=hwrev)
    assert _ref(data).update_flag_fn(data) is True


def test_old_hardware_trident_hwrev_as_string() -> None:
    data = _tri("5.05_3H19", "5.15_6A26", hwrev="2")
    assert _ref(data).update_flag_fn(data) is None


def test_missing_module_is_unknown() -> None:
    assert update._module_swstat_update(None, {}) is None
    assert update._module_swstat_update({}, {}) is None


def test_old_with_reported_latest_equal_to_installed_uses_placeholder() -> None:
    same = _data(
        {
            "hwtype": "FMM",
            "software": "5.06_CD21",
            "latestFirmware": "5.06_CD21",
            "swstat": "OLD",
        }
    )
    ref = _ref(same)
    assert ref.latest_fn(same) == "Update available"

    # A differing reported latest is kept.
    newer = _data(
        {
            "hwtype": "FMM",
            "software": "5.06_CD21",
            "latestFirmware": "5.15_6A26",
            "swstat": "OLD",
        }
    )
    assert _ref(newer).latest_fn(newer) == "5.15_6A26"


def test_old_state_does_not_flap_as_latest_appears_and_disappears() -> None:
    def latest(module_extra: dict[str, Any]) -> str | None:
        data = _data(
            {"hwtype": "FMM", "software": "5.06_CD21", "swstat": "OLD", **module_extra}
        )
        return _ref(data).latest_fn(data)

    with_latest = latest({"latestFirmware": "5.06_CD21"})
    without = latest({})
    again = latest({"latestSw": "5.06_CD21"})
    assert with_latest == without == again == "Update available"


def test_old_without_installed_version_uses_placeholder() -> None:
    data = _data({"hwtype": "FMM", "swstat": "OLD", "latestFirmware": "5.15_6A26"})
    ref = _ref(data)
    assert ref.installed_fn(data) is None
    assert ref.latest_fn(data) == "Update available"
    assert ref.update_flag_fn(data) is True


def test_non_old_without_installed_version_stays_unknown() -> None:
    data = _data({"hwtype": "FMM", "swstat": "OK"})
    ref = _ref(data)
    assert ref.installed_fn(data) is None
    assert ref.latest_fn(data) is None


async def test_entity_states_for_old_edge_cases(hass, enable_custom_integrations):
    from tests.test_update_firmware_compare import _device_model, _entities

    data: dict[str, Any] = {
        "meta": {"serial": "SER", "hostname": "apex", "type": "AC6J"},
        "raw": {
            "modules": [
                # latest == installed under OLD -> on
                {
                    "abaddr": 1,
                    "hwtype": "FMM",
                    "present": True,
                    "software": "5.06_CD21",
                    "latestFirmware": "5.06_CD21",
                    "swstat": "OLD",
                },
                # OLD, no installed version -> on, installed placeholder
                {"abaddr": 2, "hwtype": "PM2", "present": True, "swstat": "OLD"},
                # excluded with a newer reported latest -> off
                {
                    "abaddr": 3,
                    "hwtype": "IOTA",
                    "present": True,
                    "software": "5.04_4D18",
                    "latestFirmware": "5.05_3H19",
                    "swstat": "OLD",
                },
            ]
        },
    }
    added = await _entities(hass, data)
    by = {_device_model(e): e for e in added}
    assert by["FMM"].state == "on"
    assert by["PM2"].state == "on"
    assert by["PM2"].installed_version == "Unknown"
    assert by["IOTA"].state == "off"

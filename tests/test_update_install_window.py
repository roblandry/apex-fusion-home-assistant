"""The update entity against the real install window (fake controller only).

The coordinator, its window, soak, hard cap and recorded result are all real;
only the controller is a scriptable fake (see ``test_install_window``). Nothing
here reaches a real controller.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from test_install_window import (  # noqa: F401  (fixtures)
    NEW,
    OLD,
    _advance,
    _isolated_config_dir,
    _polled,
    ctl,
)
from test_update_install import _setup_entities, _until_installing

from custom_components.apex_fusion.const import (
    DOMAIN,
    INSTALL_RESULT_SUCCESS,
    INSTALL_RESULT_TIMEOUT,
)
from custom_components.apex_fusion.coordinator import ApexNeptuneDataUpdateCoordinator
from custom_components.apex_fusion.update import ApexUpdateEntity


async def _entity(hass: Any, coord: ApexNeptuneDataUpdateCoordinator) -> Any:
    """Controller update entity on a coordinator that has polled OLD."""
    coord.update_interval = None
    assert coord.data is not None
    coord.data["meta"]["firmware_latest"] = NEW
    entities = await _setup_entities(hass, coord.entry, coord)
    ent: ApexUpdateEntity = entities[0]
    ent.hass = hass
    ent.async_write_ha_state = lambda *a, **k: None
    assert ent.state == "on"
    return ent


def _repairs_issue(hass: Any, coord: ApexNeptuneDataUpdateCoordinator) -> Any:
    return ir.async_get(hass).async_get_issue(
        DOMAIN, f"firmware_install_unconfirmed_{coord.entry.entry_id}"
    )


def _puts(ctl: Any) -> int:
    return len(ctl.calls_for("PUT", "/rest/config/nconf"))


async def test_timeout_close_after_a_late_version_change_is_a_failure(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    await _until_installing(hass, coord)
    assert coord.install_in_progress is True
    assert _puts(ctl) == 1

    ctl.mode = "refuse"
    await _advance(hass, freezer, 1150)
    # The controller only answers at 1150 s, on the new version: the soak cannot
    # finish before the 20 minute cap.
    ctl.mode = "ok"
    ctl.software = NEW
    await coord.async_refresh()
    assert coord.install_in_progress is True
    assert not task.done()
    await _advance(hass, freezer, 60)

    with pytest.raises(HomeAssistantError, match="did not report a newer firmware"):
        await task
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    assert coord.last_install_version is None
    assert _repairs_issue(hass, coord) is not None
    assert _puts(ctl) == 1  # never resent


async def test_success_needs_no_entity_data_and_no_marker_race(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    old_data = {"meta": dict(coord.data["meta"]), "raw": {}}

    real_clear = coord._async_clear_install_marker

    async def _slow_clear(generation: int) -> None:
        # The marker write yields; the waiter must not need anything after it.
        for _ in range(5):
            await asyncio.sleep(0)
        await real_clear(generation)

    with patch.object(coord, "_async_clear_install_marker", _slow_clear):
        task = asyncio.ensure_future(ent.async_install(None, False))
        await _until_installing(hass, coord)
        ctl.software = NEW
        await _advance(hass, freezer, 130)
        await coord.async_refresh()
        assert coord.install_in_progress is True
        # What the entity reads is still the old poll when the window closes.
        coord.data = old_data
        await _advance(hass, freezer, 125)
        await task

    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_SUCCESS
    assert coord.last_install_version == NEW
    assert _puts(ctl) == 1


@pytest.mark.parametrize("seen_version", ["5.14J_0001", OLD, "garbage"])
async def test_a_downgrade_is_never_success(
    hass, enable_custom_integrations, ctl, freezer, seen_version
):
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    await _until_installing(hass, coord)
    ctl.software = seen_version

    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    await _advance(hass, freezer, 200)
    await coord.async_refresh()
    await _advance(hass, freezer, 300)
    await coord.async_refresh()
    # Long past the soak: still waiting, not a success.
    assert not task.done()
    assert coord.install_in_progress is True

    await _advance(hass, freezer, 700)
    with pytest.raises(HomeAssistantError, match="did not report a newer firmware"):
        await task
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    assert coord.last_install_version is None
    assert _repairs_issue(hass, coord) is not None
    assert _puts(ctl) == 1


@pytest.mark.parametrize(
    "rollback", [OLD, "5.14J_0001", "", "garbage"], ids=["old", "older", "empty", "bad"]
)
async def test_rollback_after_a_newer_version_is_never_success(
    hass, enable_custom_integrations, ctl, freezer, rollback
):
    """NEW is seen and half soaked, then the controller reverts: no success."""
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    await _until_installing(hass, coord)

    ctl.software = NEW
    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    await _advance(hass, freezer, 60)
    await coord.async_refresh()
    assert coord.install_in_progress is True  # soak not finished yet

    ctl.software = rollback
    await coord.async_refresh()
    # Far beyond a full 120 s soak counted from the first NEW poll.
    for _ in range(3):
        await _advance(hass, freezer, 200)
        await coord.async_refresh()
        assert not task.done()
        assert coord.install_in_progress is True
        assert coord.last_install_result is None

    await _advance(hass, freezer, 700)
    with pytest.raises(HomeAssistantError, match="did not report a newer firmware"):
        await task
    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    assert coord.last_install_version is None
    assert _repairs_issue(hass, coord) is not None
    assert _puts(ctl) == 1  # never resent


async def test_newer_version_held_through_the_soak_is_success(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    await _until_installing(hass, coord)

    ctl.software = NEW
    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    assert not task.done()
    await _advance(hass, freezer, 60)
    await coord.async_refresh()
    assert not task.done()  # only half way through the soak
    await _advance(hass, freezer, 70)
    await coord.async_refresh()
    await task

    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_SUCCESS
    assert coord.last_install_version == NEW
    assert _repairs_issue(hass, coord) is None
    assert _puts(ctl) == 1


async def test_pre_send_refusal_from_the_real_request_is_surfaced_unchanged(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ent = await _entity(hass, coord)
    ctl.nconf_status = 401  # the nconf read is refused: nothing may be sent

    with pytest.raises(HomeAssistantError) as direct:
        await coord.async_request_firmware_install()
    with pytest.raises(HomeAssistantError) as via_entity:
        await ent.async_install(None, False)

    assert str(via_entity.value) == str(direct.value)
    assert coord.install_in_progress is False
    assert _puts(ctl) == 0

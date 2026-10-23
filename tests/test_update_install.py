"""Tests for installing controller firmware from the update entity.

Nothing here talks to a controller: the coordinator's install request is always a
mock, and the window is driven through the coordinator's own API.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, cast
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components.update import UpdateEntityFeature
from homeassistant.config_entries import current_entry
from homeassistant.exceptions import HomeAssistantError
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from custom_components.apex_fusion import update
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    CONF_TRANSPORT,
    CONF_USERNAME,
    DOMAIN,
    INSTALL_PHASE_RECONNECTING,
    INSTALL_PHASE_RESTARTING,
    INSTALL_PHASE_WEB_PAGES,
    INSTALL_RESULT_REJECTED,
    INSTALL_RESULT_SUCCESS,
    INSTALL_RESULT_TIMEOUT,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)
from custom_components.apex_fusion.coordinator import (
    ApexNeptuneDataUpdateCoordinator,
)
from custom_components.apex_fusion.update import (
    CONTROLLER_RELEASE_URL,
    FIRMWARE_DISCLAIMER,
    ApexUpdateEntity,
)

OLD = "5.15J_6B26"
NEW = "5.16_AC26"


@pytest.fixture(autouse=True)
def _isolated_config_dir(hass, tmp_path):
    """Real install-marker files, in a per-test directory."""
    hass.config.config_dir = str(tmp_path)
    yield


INSTALL_FEATURES = UpdateEntityFeature.INSTALL | UpdateEntityFeature.PROGRESS

DISCLAIMER_TEXT = (
    "Read Neptune's release notes and save your Apex config first. Update in "
    "person: the controller goes offline for about 5-10 minutes, and a failed "
    "update can leave it unusable. Keep power and wired Ethernet connected. "
    "Safety is not guaranteed."
)


def _data(installed: str = OLD, latest: str | None = NEW) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "serial": "ABC",
        "hostname": "apex",
        "type": "AC6J",
        "software": installed,
    }
    if latest is not None:
        meta["firmware_latest"] = latest
    return {
        "meta": meta,
        "raw": {"nstat": {"latestFirmware": latest, "updateFirmware": False}},
    }


@dataclass
class _Coordinator:
    """Stand-in exposing the public surface the entity reads."""

    data: dict[str, Any] = field(default_factory=_data)
    last_update_success: bool = True
    device_identifier: str = "TEST"
    transport: str | None = TRANSPORT_REST
    install_in_progress: bool = False
    install_phase: str | None = None
    install_percentage: int | None = None
    last_install_result: str | None = None
    request: AsyncMock = field(default_factory=AsyncMock)
    end_window: AsyncMock = field(default_factory=AsyncMock)
    listeners: list[Callable[[], None]] = field(default_factory=list)

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        self.listeners.append(update_callback)

        def _unsub() -> None:
            self.listeners.remove(update_callback)

        return _unsub

    async def async_request_firmware_install(self) -> str:
        return cast(str, await self.request())

    async def async_end_install_window(self, result: str) -> None:
        await self.end_window(result)
        self.last_install_result = result
        self.install_in_progress = False

    def close(self, result: str | None) -> None:
        """Close the window as the coordinator does: result first, then notify."""
        self.last_install_result = result
        self.install_in_progress = False
        self.notify()

    def notify(self) -> None:
        for cb in list(self.listeners):
            cb()


def _entry(hass: Any, **overrides: Any) -> MockConfigEntry:
    data: dict[str, Any] = {
        CONF_HOST: "192.0.2.10",
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "configured-password",
        CONF_TRANSPORT: TRANSPORT_REST,
    }
    data.update(overrides)
    entry = MockConfigEntry(
        domain=DOMAIN, data=data, unique_id="192.0.2.10", title="Apex (test)"
    )
    entry.add_to_hass(hass)
    return entry


async def _setup_entities(hass: Any, entry: Any, coordinator: Any) -> list[Any]:
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    added: list[Any] = []

    def _add(new_entities: Any, update_before_add: bool = False) -> None:
        added.extend(list(new_entities))

    await update.async_setup_entry(hass, entry, _add)
    return added


async def _controller(
    hass: Any, coordinator: Any | None = None, **entry_overrides: Any
) -> tuple[ApexUpdateEntity, Any]:
    coord = coordinator if coordinator is not None else _Coordinator()
    entities = await _setup_entities(hass, _entry(hass, **entry_overrides), coord)
    ent = entities[0]
    ent.hass = hass
    ent.async_write_ha_state = lambda *a, **k: None
    # Setup subscribes a module-discovery listener; drop it so tests can count
    # only the listeners the install wait adds.
    coord.listeners.clear()
    return ent, coord


# ---------------------------------------------------------------------------
# Feature gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("transport", "entry_overrides", "expected"),
    [
        (TRANSPORT_REST, {}, INSTALL_FEATURES),
        (TRANSPORT_REST, {CONF_PASSWORD: ""}, UpdateEntityFeature(0)),
        (TRANSPORT_REST, {CONF_PASSWORD: "   "}, UpdateEntityFeature(0)),
        (TRANSPORT_REST, {CONF_NO_LOGIN: True}, UpdateEntityFeature(0)),
        (TRANSPORT_LEGACY, {}, UpdateEntityFeature(0)),
        (None, {}, UpdateEntityFeature(0)),
    ],
)
async def test_install_features_only_for_rest_with_password(
    hass, enable_custom_integrations, transport, entry_overrides, expected
):
    ent, _coord = await _controller(
        hass, _Coordinator(transport=transport), **entry_overrides
    )
    assert ent.supported_features == expected
    if expected:
        assert ent.extra_state_attributes == {"install_phase": None}
    else:
        assert ent.extra_state_attributes is None


async def test_module_entities_have_no_install_feature(
    hass, enable_custom_integrations
):
    data = _data()
    data["raw"]["modules"] = [
        {
            "abaddr": 1,
            "hwtype": "FMM",
            "present": True,
            "swrev": 24,
            "swstat": "OLD",
            "latestFirmware": "25",
        },
        {"abaddr": 5, "hwtype": "TRI", "present": True, "swrev": 1, "swstat": "OK"},
    ]
    coord = _Coordinator(data=data)
    # A module update is available and the entry could install a controller
    # update; modules still must not offer INSTALL.
    entities = await _setup_entities(hass, _entry(hass), coord)
    assert len(entities) == 3
    assert entities[0].supported_features == INSTALL_FEATURES
    added_modules = entities[1:]
    for mod in added_modules:
        assert mod.supported_features == UpdateEntityFeature(0)
        assert UpdateEntityFeature.INSTALL not in mod.supported_features
        assert mod.in_progress is False
        assert mod.update_percentage is None
        assert mod.extra_state_attributes is None
        assert mod.release_url is None
        assert mod.release_summary != FIRMWARE_DISCLAIMER
        with pytest.raises(HomeAssistantError, match="Only the controller"):
            await mod.async_install(None, False)
    coord.request.assert_not_awaited()


# ---------------------------------------------------------------------------
# Disclaimer and release URL
# ---------------------------------------------------------------------------


def test_disclaimer_is_the_approved_text():
    assert FIRMWARE_DISCLAIMER == DISCLAIMER_TEXT
    assert len(FIRMWARE_DISCLAIMER) == 241
    assert len(FIRMWARE_DISCLAIMER) <= 255
    assert "—" not in FIRMWARE_DISCLAIMER


async def test_disclaimer_and_release_url_shown_when_update_available(
    hass, enable_custom_integrations
):
    ent, _coord = await _controller(hass)
    assert ent.state == "on"
    assert ent.release_summary == DISCLAIMER_TEXT
    assert ent.release_url == "https://forum.neptunesystems.com/node/334396"
    assert ent.release_url == CONTROLLER_RELEASE_URL
    assert UpdateEntityFeature.RELEASE_NOTES not in ent.supported_features
    attrs = ent.state_attributes
    assert attrs is not None
    assert attrs["release_summary"] == DISCLAIMER_TEXT
    assert attrs["release_url"] == CONTROLLER_RELEASE_URL


@pytest.mark.parametrize(
    ("transport", "entry_overrides"),
    [
        (TRANSPORT_REST, {CONF_PASSWORD: ""}),
        (TRANSPORT_REST, {CONF_NO_LOGIN: True}),
        (TRANSPORT_LEGACY, {}),
    ],
)
async def test_no_disclaimer_or_url_when_install_is_not_offered(
    hass, enable_custom_integrations, transport, entry_overrides
):
    ent, _coord = await _controller(
        hass, _Coordinator(transport=transport), **entry_overrides
    )
    assert ent.supported_features == UpdateEntityFeature(0)
    assert ent.state == "on"  # the update is still shown, just not installable
    assert ent.release_summary is None
    assert ent.release_url is None


async def test_no_disclaimer_or_url_when_up_to_date(hass, enable_custom_integrations):
    ent, _coord = await _controller(
        hass, _Coordinator(data=_data(installed=NEW, latest=NEW))
    )
    assert ent.release_summary is None
    assert ent.release_url is None


async def test_no_disclaimer_without_latest_version(hass, enable_custom_integrations):
    ent, _coord = await _controller(hass, _Coordinator(data=_data(latest=None)))
    assert ent.release_summary is None
    assert ent.release_url is None


# ---------------------------------------------------------------------------
# Progress mirrors the coordinator
# ---------------------------------------------------------------------------


async def test_progress_properties_mirror_the_coordinator(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    assert ent.in_progress is False
    assert ent.update_percentage is None

    coord.install_in_progress = True
    coord.install_phase = INSTALL_PHASE_RESTARTING
    coord.install_percentage = 17
    assert ent.in_progress is True
    assert ent.update_percentage == 17
    assert ent.extra_state_attributes == {"install_phase": INSTALL_PHASE_RESTARTING}

    # HA's wrapper clobbers _attr_in_progress when an install ends; the entity
    # must not depend on it.
    ent._attr_in_progress = False
    assert ent.in_progress is True

    coord.install_percentage = 63
    coord.install_phase = INSTALL_PHASE_WEB_PAGES
    assert ent.update_percentage == 63
    attrs = ent.state_attributes
    assert attrs is not None
    assert attrs["in_progress"] is True
    assert attrs["update_percentage"] == 63

    coord.install_in_progress = False
    coord.install_phase = None
    coord.install_percentage = None
    assert ent.in_progress is False
    assert ent.update_percentage is None


@pytest.mark.parametrize(
    ("phase", "text"),
    [
        (INSTALL_PHASE_RESTARTING, "restarting"),
        (INSTALL_PHASE_RECONNECTING, "come back"),
        (INSTALL_PHASE_WEB_PAGES, "web pages"),
    ],
)
async def test_release_summary_shows_phase_while_installing_then_reverts(
    hass, enable_custom_integrations, phase, text
):
    ent, coord = await _controller(hass)
    assert ent.release_summary == DISCLAIMER_TEXT

    coord.install_in_progress = True
    coord.install_phase = phase
    ent._handle_coordinator_update()
    assert ent.release_summary is not None
    assert text in ent.release_summary
    assert ent.release_summary.startswith("Installing")
    assert ent.release_url is None

    coord.install_in_progress = False
    coord.install_phase = None
    ent._handle_coordinator_update()
    assert ent.release_summary == DISCLAIMER_TEXT
    assert ent.release_url == CONTROLLER_RELEASE_URL


async def test_release_summary_keeps_disclaimer_if_phase_is_unknown(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    coord.install_in_progress = True
    coord.install_phase = None
    ent._handle_coordinator_update()
    assert ent.release_summary == DISCLAIMER_TEXT


async def test_entity_stays_available_during_the_window(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    assert ent.available is True

    # Polls fail while the controller reboots.
    coord.last_update_success = False
    ent._handle_coordinator_update()
    assert ent.available is False

    coord.install_in_progress = True
    ent._handle_coordinator_update()
    assert ent.available is True

    coord.install_in_progress = False
    ent._handle_coordinator_update()
    assert ent.available is False


async def test_module_entity_is_unavailable_when_polls_fail_even_if_installing(
    hass, enable_custom_integrations
):
    data = _data()
    data["raw"]["modules"] = [
        {"abaddr": 1, "hwtype": "FMM", "present": True, "swrev": 24, "swstat": "OK"}
    ]
    coord = _Coordinator(data=data, last_update_success=False, install_in_progress=True)
    (ref,) = update._module_refs(data, "abc")
    mod = ApexUpdateEntity(cast(Any, coord), cast(Any, _entry(hass)), ref=ref)
    assert mod.available is False


# ---------------------------------------------------------------------------
# async_install
# ---------------------------------------------------------------------------


def _opener(coord: _Coordinator) -> Callable[[], Any]:
    async def _open() -> str:
        coord.install_in_progress = True
        return "accepted"

    return _open


async def test_install_requests_once_and_waits_for_the_window(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    coord.request.side_effect = _opener(coord)

    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)
    coord.request.assert_awaited_once()
    assert not task.done()
    assert len(coord.listeners) == 1

    coord.close(INSTALL_RESULT_SUCCESS)
    await task

    coord.request.assert_awaited_once()
    coord.end_window.assert_not_awaited()
    assert coord.listeners == []


async def test_install_ignores_updates_while_the_window_is_open(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    coord.request.side_effect = _opener(coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)

    coord.notify()  # a progress tick, window still open
    coord.data = _data(installed=NEW, latest=NEW)  # even a new version
    coord.notify()
    await asyncio.sleep(0)
    assert not task.done()

    coord.close(INSTALL_RESULT_SUCCESS)
    coord.notify()  # a second callback after completion must be harmless
    await task


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (INSTALL_RESULT_TIMEOUT, "did not report a newer firmware"),
        (INSTALL_RESULT_REJECTED, "failed or was rejected"),
        (None, "failed or was rejected"),
    ],
)
async def test_install_fails_on_a_non_success_result(
    hass, enable_custom_integrations, result, message
):
    ent, coord = await _controller(hass)
    coord.request.side_effect = _opener(coord)
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)

    # A new version in the entity's data is not evidence of success.
    coord.data = _data(installed=NEW, latest=NEW)
    coord.close(result)
    with pytest.raises(HomeAssistantError, match=message):
        await task
    assert coord.listeners == []
    coord.end_window.assert_not_awaited()


async def test_install_window_already_closed_when_request_returns(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)

    async def _quick() -> str:
        coord.last_install_result = INSTALL_RESULT_SUCCESS
        return "accepted"

    coord.request.side_effect = _quick
    await ent.async_install(None, False)
    coord.request.assert_awaited_once()


async def _start_install(ent: Any, coord: _Coordinator) -> asyncio.Future[None]:
    async def _open_window() -> str:
        coord.install_in_progress = True
        return "accepted"

    coord.request.side_effect = _open_window
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not task.done()
    return task


async def test_success_result_wins_while_the_entity_data_is_still_old(
    hass, enable_custom_integrations
):
    """The window can close before the poll's data is published; no grace needed."""
    ent, coord = await _controller(hass)
    task = await _start_install(ent, coord)

    coord.close(INSTALL_RESULT_SUCCESS)
    assert coord.data["meta"]["software"] == OLD
    await task  # returns on the recorded result alone
    coord.request.assert_awaited_once()
    coord.end_window.assert_not_awaited()
    assert coord.listeners == []


async def test_entity_removal_cancels_the_wait_and_the_listener(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    task = await _start_install(ent, coord)
    assert len(coord.listeners) == 1

    await ent.async_will_remove_from_hass()
    with pytest.raises(HomeAssistantError, match="entity was removed"):
        await task
    assert coord.listeners == []
    assert ent._install_waiters == []
    assert ent._install_unsubs == []
    # The install belongs to the coordinator: removal does not end it.
    coord.end_window.assert_not_awaited()
    coord.request.assert_awaited_once()


async def test_removal_while_the_request_is_in_flight_creates_no_waiter(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    release = asyncio.Event()

    async def _held() -> str:
        await release.wait()
        coord.install_in_progress = True
        return "accepted"

    coord.request.side_effect = _held
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not task.done()
    assert coord.listeners == []

    await ent.async_will_remove_from_hass()
    release.set()
    async with asyncio.timeout(1):
        with pytest.raises(HomeAssistantError, match="entity was removed"):
            await task

    # Nothing was created on the removed entity, and nothing was resent.
    assert coord.listeners == []
    assert ent._install_waiters == []
    assert ent._install_unsubs == []
    coord.request.assert_awaited_once()
    # The install belongs to the coordinator: the window is left open.
    coord.end_window.assert_not_awaited()
    assert coord.install_in_progress is True


async def _remove_and_re_add(ent: Any, coord: Any) -> None:
    """What HA does to the same instance when its entity_id is renamed."""
    await ent.async_will_remove_from_hass()
    await ent.async_added_to_hass()
    # Drop the entity's own state listener so tests count only the install wait.
    coord.listeners.clear()


async def test_install_after_a_same_instance_remove_and_re_add_succeeds(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    await _remove_and_re_add(ent, coord)

    async def _quick() -> str:
        coord.last_install_result = INSTALL_RESULT_SUCCESS
        return "accepted"

    coord.request.side_effect = _quick
    await ent.async_install(None, False)

    coord.request.assert_awaited_once()
    coord.end_window.assert_not_awaited()
    assert coord.listeners == []
    assert ent._install_waiters == []
    assert ent._install_unsubs == []


async def test_removal_then_re_add_during_the_request_still_raises_removed(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    release = asyncio.Event()

    async def _held() -> str:
        await release.wait()
        coord.install_in_progress = True
        return "accepted"

    coord.request.side_effect = _held
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not task.done()

    await _remove_and_re_add(ent, coord)
    release.set()
    async with asyncio.timeout(1):
        with pytest.raises(HomeAssistantError, match="entity was removed"):
            await task

    assert coord.listeners == []
    assert ent._install_waiters == []
    assert ent._install_unsubs == []
    coord.request.assert_awaited_once()
    coord.end_window.assert_not_awaited()
    assert coord.install_in_progress is True


async def test_removal_with_nothing_pending_is_a_no_op(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    await ent.async_will_remove_from_hass()
    assert coord.listeners == []


async def test_fallback_timeout_closes_the_window_and_never_resends(
    hass, enable_custom_integrations, monkeypatch
):
    monkeypatch.setattr(update, "_INSTALL_WAIT_SECONDS", 0.01)
    ent, coord = await _controller(hass)

    async def _open_window() -> str:
        coord.install_in_progress = True
        return "accepted"

    coord.request.side_effect = _open_window
    with pytest.raises(HomeAssistantError, match="did not report a newer firmware"):
        await ent.async_install(None, False)

    coord.end_window.assert_awaited_once_with(INSTALL_RESULT_TIMEOUT)
    assert coord.install_in_progress is False
    coord.request.assert_awaited_once()
    assert coord.listeners == []


@pytest.mark.parametrize(
    "message",
    [
        "Controller rejected the request",
        "Controller rejected the stored credentials (HTTP 401); nothing was sent",
    ],
)
async def test_install_surfaces_a_pre_send_refusal_unchanged(
    hass, enable_custom_integrations, message
):
    """A request that fails before sending is reported as is, never as started."""
    ent, coord = await _controller(hass)
    err = HomeAssistantError(message)
    coord.request.side_effect = err
    with pytest.raises(HomeAssistantError) as excinfo:
        await ent.async_install(None, False)
    assert excinfo.value is err
    assert str(excinfo.value) == message
    assert excinfo.value.__cause__ is None
    coord.request.assert_awaited_once()
    # Nothing waited, and no window or "possibly started" state was assumed.
    assert coord.listeners == []
    assert coord.install_in_progress is False
    assert ent.in_progress is False


async def test_install_cancellation_removes_the_listener(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)

    async def _open_window() -> str:
        coord.install_in_progress = True
        return "accepted"

    coord.request.side_effect = _open_window
    task = asyncio.ensure_future(ent.async_install(None, False))
    for _ in range(5):
        await asyncio.sleep(0)
    assert len(coord.listeners) == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert coord.listeners == []


async def test_install_refused_when_one_is_already_in_progress(
    hass, enable_custom_integrations
):
    ent, coord = await _controller(hass)
    coord.install_in_progress = True
    with pytest.raises(HomeAssistantError, match="already in progress"):
        await ent.async_install(None, False)
    coord.request.assert_not_awaited()


@pytest.mark.parametrize(
    "data",
    [
        _data(installed=NEW, latest=NEW),
        _data(latest=None),
        {"meta": {}},
    ],
)
async def test_install_refused_when_no_update_available(
    hass, enable_custom_integrations, data
):
    ent, coord = await _controller(hass, _Coordinator(data=data))
    with pytest.raises(HomeAssistantError, match="No firmware update"):
        await ent.async_install(None, False)
    coord.request.assert_not_awaited()


async def test_install_refused_on_legacy_transport(hass, enable_custom_integrations):
    ent, coord = await _controller(hass, _Coordinator(transport=TRANSPORT_LEGACY))
    with pytest.raises(HomeAssistantError, match="REST transport"):
        await ent.async_install(None, False)
    coord.request.assert_not_awaited()


@pytest.mark.parametrize("overrides", [{CONF_PASSWORD: ""}, {CONF_NO_LOGIN: True}])
async def test_install_refused_without_a_password(
    hass, enable_custom_integrations, overrides
):
    ent, coord = await _controller(hass, **overrides)
    with pytest.raises(HomeAssistantError, match="password"):
        await ent.async_install(None, False)
    coord.request.assert_not_awaited()


# ---------------------------------------------------------------------------
# Against the real coordinator window (the request itself is mocked)
# ---------------------------------------------------------------------------


def _real_coordinator(hass: Any, entry: Any) -> ApexNeptuneDataUpdateCoordinator:
    token = current_entry.set(entry)
    try:
        return ApexNeptuneDataUpdateCoordinator(hass, entry=entry)
    finally:
        current_entry.reset(token)


async def test_install_end_to_end_with_the_real_window(
    hass, enable_custom_integrations, freezer
):
    entry = _entry(hass)
    coord = _real_coordinator(hass, entry)
    coord.async_set_updated_data(_data())
    ent, _ = await _controller_for(hass, entry, coord)
    await ent.async_added_to_hass()

    async def _request() -> str:
        await coord.async_begin_install_window(expected_version=NEW)
        return "accepted"

    with (
        patch.object(
            coord,
            "async_request_firmware_install",
            AsyncMock(side_effect=_request),
        ) as request,
        patch.object(coord, "_async_refresh_config_after_install", AsyncMock()),
    ):
        task = asyncio.ensure_future(ent.async_install(None, False))
        await _until_installing(hass, coord)
        request.assert_awaited_once()
        assert coord.install_in_progress is True
        assert ent.in_progress is True
        assert not task.done()

        # Polls fail during the reboot; the entity stays up and keeps moving.
        coord.last_update_success = False
        for seconds in (60, 60):
            freezer.tick(timedelta(seconds=seconds))
            async_fire_time_changed(hass)
            await hass.async_block_till_done()
        assert ent.available is True
        assert ent.in_progress is True
        assert ent.update_percentage == coord.install_percentage
        assert (ent.update_percentage or 0) > 0
        assert ent.release_summary is not None
        assert ent.release_summary.startswith("Installing")

        coord.async_set_updated_data(_data(installed=NEW, latest=NEW))
        await coord.async_end_install_window(INSTALL_RESULT_SUCCESS)
        await task

    assert coord.install_in_progress is False
    assert ent.in_progress is False
    assert ent.update_percentage is None
    assert ent.state == "off"
    assert ent.release_summary is None


async def test_install_end_to_end_timeout_result_raises(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    coord = _real_coordinator(hass, entry)
    coord.async_set_updated_data(_data())
    ent, _ = await _controller_for(hass, entry, coord)

    async def _request() -> str:
        await coord.async_begin_install_window(expected_version=NEW)
        return "possibly_started"

    with patch.object(
        coord, "async_request_firmware_install", AsyncMock(side_effect=_request)
    ):
        task = asyncio.ensure_future(ent.async_install(None, False))
        await _until_installing(hass, coord)
        await coord.async_end_install_window(INSTALL_RESULT_TIMEOUT)
        with pytest.raises(HomeAssistantError, match="did not report a newer firmware"):
            await task
    # The old version is still installed and the update is still offered.
    assert ent.state == "on"


async def test_real_coordinator_tick_redraws_the_entity(
    hass, enable_custom_integrations, freezer
):
    entry = _entry(hass)
    coord = _real_coordinator(hass, entry)
    coord.async_set_updated_data(_data())
    ent, _ = await _controller_for(hass, entry, coord)

    writes: list[int | None] = []
    ent.async_write_ha_state = lambda *a, **k: writes.append(ent.update_percentage)
    await ent.async_added_to_hass()
    writes.clear()

    await coord.async_begin_install_window(expected_version=NEW)
    writes.clear()
    for _ in range(3):
        freezer.tick(timedelta(seconds=5))
        async_fire_time_changed(hass)
        await hass.async_block_till_done()

    # One redraw per 5 s tick, with the percentage moving.
    assert len(writes) >= 3
    values = [w for w in writes if w is not None]
    assert values == sorted(values)
    assert values[-1] > values[0]
    await coord.async_end_install_window("rejected")


async def _until_installing(hass: Any, coord: Any) -> None:
    """Let the real marker write (an executor job) finish and the window open."""
    # Time is frozen here, so wait on a real thread rather than asyncio.sleep.
    for _ in range(200):
        if coord.install_in_progress:
            return
        await hass.async_add_executor_job(time.sleep, 0.005)
    raise AssertionError("the install window never opened")


async def _controller_for(
    hass: Any, entry: Any, coord: Any
) -> tuple[ApexUpdateEntity, Any]:
    entities = await _setup_entities(hass, entry, coord)
    ent = entities[0]
    ent.hass = hass
    ent.async_write_ha_state = lambda *a, **k: None
    return ent, coord

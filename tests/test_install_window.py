"""Tests for the firmware install window, progress model and request helper."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, cast
from unittest.mock import MagicMock, patch

import aiohttp
import pytest
from homeassistant.config_entries import ConfigEntry, current_entry
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

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
    install_progress,
)

OLD = "5.15J_6B26"
NEW = "5.16L_AC26"

# Sentinels only: they stand in for the secrets a real nconf object contains.
SENTINEL_PASSWORD = "sentinel-admin-password"
SENTINEL_EMAIL_PASSWORD = "sentinel-email-password"
SENTINEL_WIFI_PASSWORD = "sentinel-wifi-password"
SENTINEL_SSID = "sentinel-ssid"
SENTINEL_SID = "sentinel-session-id"

NCONF: dict[str, Any] = {
    "id": "network",
    "hostname": "apex-test",
    "ipaddr": "192.0.2.10",
    "httpPort": 80,
    "dhcp": True,
    "user": "admin",
    "password": SENTINEL_PASSWORD,
    "emailPassword": SENTINEL_EMAIL_PASSWORD,
    "wifiAPPassword": SENTINEL_WIFI_PASSWORD,
    "ssid": SENTINEL_SSID,
    "latestFirmware": NEW,
    "updateFirmware": False,
}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _NullTimeout:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


class _Morsel:
    def __init__(self, value: str) -> None:
        self.value = value


class _Resp:
    def __init__(
        self, status: int, body: Any = None, *, cookies: dict[str, str] | None = None
    ) -> None:
        self.status = status
        self._body = "" if body is None else json.dumps(body)
        self.headers: dict[str, str] = {}
        self.cookies = {k: _Morsel(v) for k, v in (cookies or {}).items()}
        self.request_info = cast(Any, None)
        self.history = cast(Any, ())

    async def text(self) -> str:
        return self._body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=self.request_info,
                history=self.history,
                status=self.status,
                message="err",
                headers=None,
            )

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


class _CookieJar:
    def filter_cookies(self, _url: Any) -> dict[str, _Morsel]:
        return {}

    def update_cookies(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def clear(self) -> None:
        return None


@dataclass
class _Controller:
    """A scriptable fake Apex controller that doubles as the aiohttp session."""

    # ok | refuse | timeout | 401 | 404 | 429
    mode: str = "ok"
    software: str = OLD
    put_result: Any = 200  # int status, or an exception instance
    nconf_status: int = 200
    nconf_wrapped: bool = True
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    cookie_jar: _CookieJar = field(default_factory=_CookieJar)

    def calls_for(self, method: str, path_suffix: str) -> list[dict[str, Any]]:
        return [
            kwargs
            for m, url, kwargs in self.calls
            if m == method and url.endswith(path_suffix)
        ]

    def _failure(self) -> _Resp | None:
        if self.mode == "refuse":
            raise aiohttp.ClientConnectionError("refused")
        if self.mode == "timeout":
            raise asyncio.TimeoutError
        if self.mode in ("401", "404", "429"):
            resp = _Resp(int(self.mode), {})
            if self.mode == "429":
                resp.headers["Retry-After"] = "300"
            return resp
        return None

    def get(self, url: str, **kwargs: Any) -> _Resp:
        self.calls.append(("GET", url, kwargs))
        failure = self._failure()
        if failure is not None:
            return failure
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        if url.endswith("/rest/status"):
            if SENTINEL_SID not in cookie:
                return _Resp(401, {})
            return _Resp(
                200,
                {
                    "nstat": {"ipaddr": "192.0.2.10"},
                    "system": {"serial": "TESTSERIAL", "software": self.software},
                    "inputs": [],
                    "outputs": [],
                },
            )
        if url.endswith("/rest/config/nconf"):
            if self.nconf_status != 200:
                return _Resp(self.nconf_status, {})
            return _Resp(200, {"nconf": dict(NCONF)} if self.nconf_wrapped else NCONF)
        if url.endswith("/rest/config"):
            return _Resp(200, {"mconf": [], "nconf": dict(NCONF)})
        return _Resp(404, {})  # pragma: no cover

    def post(self, url: str, **kwargs: Any) -> _Resp:
        self.calls.append(("POST", url, kwargs))
        failure = self._failure()
        if failure is not None:
            return failure
        return _Resp(200, {}, cookies={"connect.sid": SENTINEL_SID})

    def put(self, url: str, **kwargs: Any) -> _Resp:
        self.calls.append(("PUT", url, kwargs))
        if isinstance(self.put_result, BaseException):
            raise self.put_result
        return _Resp(int(self.put_result), {})


@pytest.fixture
def reauth():
    """Spy on reauth starts (HA calls this when a ConfigEntryAuthFailed escapes)."""
    with patch.object(ConfigEntry, "async_start_reauth") as spy:
        yield spy


@pytest.fixture
def ctl(monkeypatch: pytest.MonkeyPatch) -> _Controller:
    controller = _Controller()
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _hass: controller,
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_timeout.timeout",
        lambda _s: _NullTimeout(),
    )

    async def _no_sleep(_secs: float) -> None:
        return None

    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.asyncio.sleep", _no_sleep
    )
    return controller


def _make_entry(hass: Any, **overrides: Any) -> MockConfigEntry:
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


async def _make_coordinator(
    hass: Any, **overrides: Any
) -> ApexNeptuneDataUpdateCoordinator:
    entry = _make_entry(hass, **overrides)
    token = current_entry.set(cast(Any, entry))
    try:
        return ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))
    finally:
        current_entry.reset(token)


async def _polled(hass: Any, ctl: _Controller) -> ApexNeptuneDataUpdateCoordinator:
    """Coordinator that has completed one good poll on the old firmware."""
    coord = await _make_coordinator(hass)
    await coord.async_refresh()
    assert coord.last_update_success
    assert coord.data["meta"]["software"] == OLD
    ctl.calls.clear()
    return coord


async def _advance(hass: Any, freezer: Any, seconds: float) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()


# ---------------------------------------------------------------------------
# Progress curve (pure)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("elapsed", "reconnected_for", "expected"),
    [
        (0, None, (INSTALL_PHASE_RESTARTING, 0)),
        (-5, None, (INSTALL_PHASE_RESTARTING, 0)),
        (60, None, (INSTALL_PHASE_RESTARTING, 20)),
        (119.9, None, (INSTALL_PHASE_RESTARTING, 39)),
        (120, None, (INSTALL_PHASE_RECONNECTING, 40)),
        (150, None, (INSTALL_PHASE_RECONNECTING, 44)),
        (180, None, (INSTALL_PHASE_RECONNECTING, 49)),
        (900, None, (INSTALL_PHASE_RECONNECTING, 49)),
        (130, 0, (INSTALL_PHASE_WEB_PAGES, 50)),
        (190, 60, (INSTALL_PHASE_WEB_PAGES, 74)),
        (250, 120, (INSTALL_PHASE_WEB_PAGES, 99)),
        (2000, 1500, (INSTALL_PHASE_WEB_PAGES, 99)),
        (130, -3, (INSTALL_PHASE_WEB_PAGES, 50)),
    ],
)
def test_install_progress_curve(elapsed, reconnected_for, expected):
    assert (
        install_progress(elapsed=elapsed, reconnected_for=reconnected_for) == expected
    )


def test_install_progress_is_monotonic_and_never_reaches_100():
    previous = -1
    for second in range(0, 400):
        reconnected = None if second < 200 else second - 200
        _phase, pct = install_progress(elapsed=second, reconnected_for=reconnected)
        assert pct >= previous
        assert pct < 100
        previous = pct


# ---------------------------------------------------------------------------
# Window lifecycle and phases
# ---------------------------------------------------------------------------


async def test_idle_coordinator_reports_no_install(
    hass, enable_custom_integrations, ctl
):
    coord = await _make_coordinator(hass)
    assert coord.install_in_progress is False
    assert coord.install_phase is None
    assert coord.install_percentage is None
    # Ending a window that is not open is a no-op.
    await coord.async_end_install_window(INSTALL_RESULT_SUCCESS)


async def test_begin_requires_known_version_and_single_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _make_coordinator(hass)
    with pytest.raises(HomeAssistantError, match="version is unknown"):
        await coord.async_begin_install_window()

    coord.data = {"meta": "not-a-dict"}
    with pytest.raises(HomeAssistantError, match="version is unknown"):
        await coord.async_begin_install_window()

    coord.data = {"meta": {"software": OLD}}
    await coord.async_begin_install_window()
    with pytest.raises(HomeAssistantError, match="already in progress"):
        await coord.async_begin_install_window()
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_phases_and_percentages_follow_fake_time(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    assert coord.install_in_progress is True
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RESTARTING,
        0,
    )

    await _advance(hass, freezer, 60)
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RESTARTING,
        20,
    )

    # Controller is gone: polls fail but never reauth.
    ctl.mode = "refuse"
    await _advance(hass, freezer, 60)
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RECONNECTING,
        40,
    )
    await coord.async_refresh()
    assert not coord.last_update_success

    await _advance(hass, freezer, 30)
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RECONNECTING,
        44,
    )
    await _advance(hass, freezer, 300)
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RECONNECTING,
        49,
    )

    # Controller answers again, still on the old version (web pages loading).
    ctl.mode = "ok"
    coord._rest_sid = "pre-reboot-session"
    await coord.async_refresh()
    assert coord.last_update_success
    assert coord.install_in_progress is True
    assert coord._rest_sid is None
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_WEB_PAGES,
        50,
    )

    await _advance(hass, freezer, 60)
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_WEB_PAGES,
        74,
    )
    await _advance(hass, freezer, 600)
    # Capped at 99 however long it takes, and the window is still open.
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_WEB_PAGES,
        99,
    )

    # A verified version change is the only way to finish.
    ctl.software = NEW
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.install_in_progress is False
    assert coord.install_phase is None
    assert coord.install_percentage is None
    assert coord.data["meta"]["software"] == NEW
    # The config was refreshed afterwards.
    assert ctl.calls_for("GET", "/rest/config")


async def test_good_poll_before_restart_period_does_not_reconnect(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    await _advance(hass, freezer, 30)
    await coord.async_refresh()
    assert coord.last_update_success
    assert coord.install_in_progress is True
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RESTARTING,
        10,
    )


async def test_success_only_when_version_changes(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()

    for _ in range(3):
        await _advance(hass, freezer, 100)
        await coord.async_refresh()
        assert coord.install_in_progress is True

    ctl.software = NEW
    await coord.async_refresh()
    assert coord.install_in_progress is False
    await hass.async_block_till_done()
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None


async def test_unexpected_version_still_closes_window_with_warning(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window(expected_version=NEW)
    ctl.software = "5.99Z_0000"
    with caplog.at_level(logging.WARNING):
        await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.install_in_progress is False
    assert "not the expected" in caplog.text


async def test_post_install_config_refresh_failure_is_logged_not_raised(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.software = NEW
    await coord.async_refresh()
    ctl.mode = "refuse"
    with caplog.at_level(logging.WARNING):
        await coord._async_refresh_config_after_install()
    assert "Could not refresh controller config" in caplog.text


async def test_end_window_success_refreshes_config(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    await coord.async_end_install_window(INSTALL_RESULT_SUCCESS)
    assert coord.install_in_progress is False
    assert ctl.calls_for("GET", "/rest/config")


# ---------------------------------------------------------------------------
# Reboot-safe error handling
# ---------------------------------------------------------------------------


async def test_auth_rejection_in_window_is_updatefailed_and_never_reauth(
    hass, enable_custom_integrations, ctl, reauth
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()

    ctl.mode = "401"
    with pytest.raises(UpdateFailed, match="installing firmware"):
        await coord._async_update_data()
    await coord.async_refresh()
    await hass.async_block_till_done()

    assert not coord.last_update_success
    reauth.assert_not_called()
    # One attempt, one login per poll: the retries are capped while the window
    # is open (two polls above).
    assert len(ctl.calls_for("POST", "/rest/login")) == 2


async def test_not_found_in_window_is_updatefailed_without_redetect_hint(
    hass, enable_custom_integrations, ctl, reauth
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "404"
    with pytest.raises(UpdateFailed, match="installing firmware"):
        await coord._async_update_data()
    reauth.assert_not_called()


async def test_auth_failure_outside_window_still_starts_reauth(
    hass, enable_custom_integrations, ctl, reauth
):
    """Control: the same 401 outside the window keeps its normal behaviour."""
    coord = await _polled(hass, ctl)
    ctl.mode = "401"
    with pytest.raises(ConfigEntryAuthFailed):
        await coord._async_update_data()
    await coord.async_refresh()
    await hass.async_block_till_done()
    reauth.assert_called_once()
    # Full retry budget outside the window: 3 attempts x 4 logins, twice.
    assert len(ctl.calls_for("POST", "/rest/login")) == 24


async def test_not_found_outside_window_keeps_redetect_hint(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.mode = "404"
    with pytest.raises(UpdateFailed, match="re-detect"):
        await coord._async_update_data()


async def test_config_entry_auth_failed_from_inner_is_mapped_in_window(
    hass, enable_custom_integrations, ctl, monkeypatch
):
    coord = await _polled(hass, ctl)

    async def _boom() -> dict[str, Any]:
        raise ConfigEntryAuthFailed("nope")

    monkeypatch.setattr(coord, "_async_update_rest_inner", _boom)
    with pytest.raises(ConfigEntryAuthFailed):
        await coord._async_update_rest()

    await coord.async_begin_install_window()
    with pytest.raises(UpdateFailed, match="installing firmware"):
        await coord._async_update_rest()


@pytest.mark.parametrize("mode", ["refuse", "timeout", "401", "404", "429"])
async def test_no_transport_change_during_window(
    hass, enable_custom_integrations, ctl, monkeypatch, mode
):
    """The #33 transport pin: no failure during the window switches transport."""
    coord = await _polled(hass, ctl)
    entry = coord.entry
    data_before = dict(entry.data)
    update_entry = MagicMock()
    monkeypatch.setattr(hass.config_entries, "async_update_entry", update_entry)

    await coord.async_begin_install_window()
    ctl.mode = mode
    for _ in range(3):
        await coord.async_refresh()
        assert not coord.last_update_success

    assert coord.transport == TRANSPORT_REST
    assert dict(entry.data) == data_before
    update_entry.assert_not_called()
    # Every poll stayed on the REST endpoints; nothing touched the CGI ones.
    assert all("/cgi-bin/" not in url for _m, url, _k in ctl.calls)


async def test_rest_backoff_is_capped_only_during_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    coord._disable_rest(seconds=300, reason="test")
    outside = coord._rest_disabled_until
    coord._rest_disabled_until = 0.0

    await coord.async_begin_install_window()
    import time

    before = time.monotonic()
    coord._disable_rest(seconds=300, reason="test")
    assert coord._rest_disabled_until - before <= 31
    assert outside - before > 200


async def test_rate_limited_poll_in_window_backs_off_briefly(
    hass, enable_custom_integrations, ctl
):
    import time

    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "429"
    await coord.async_refresh()
    assert not coord.last_update_success
    assert coord._rest_disabled_until - time.monotonic() <= 31


async def test_control_login_is_single_attempt_in_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "401"
    with pytest.raises(HomeAssistantError, match="REST login rejected"):
        await coord._async_rest_login(session=cast(Any, ctl))
    assert len(ctl.calls_for("POST", "/rest/login")) == 1


async def test_other_rest_writes_are_blocked_during_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    with pytest.raises(HomeAssistantError, match="firmware install is in progress"):
        await coord.async_rest_put_json(path="/rest/config/mconf/1", payload={"a": 1})
    assert ctl.calls_for("PUT", "/rest/config/mconf/1") == []

    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    await coord.async_rest_put_json(path="/rest/config/mconf/1", payload={"a": 1})
    assert len(ctl.calls_for("PUT", "/rest/config/mconf/1")) == 1


# ---------------------------------------------------------------------------
# Hard cap, warning, timers
# ---------------------------------------------------------------------------


async def test_hard_cap_raises_repair_issue_closes_window_and_never_retries(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "refuse"

    await _advance(hass, freezer, 1199)
    assert coord.install_in_progress is True
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None

    await _advance(hass, freezer, 2)
    assert coord.install_in_progress is False
    assert coord.install_phase is None
    assert coord.install_percentage is None

    issue = ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id)
    assert issue is not None
    assert issue.translation_key == "firmware_install_unconfirmed"
    assert issue.severity == ir.IssueSeverity.ERROR
    assert issue.is_fixable is False
    # Nothing was ever sent: in particular no second install request.
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord._install_unsubs == []

    # Beginning a new window clears the stale issue.
    ctl.mode = "ok"
    await coord.async_refresh()
    await coord.async_begin_install_window()
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_hard_cap_timer_is_a_noop_after_the_window_closed(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord._async_install_hard_cap(None)
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None


async def test_ui_fail_point_only_logs_a_warning(
    hass, enable_custom_integrations, ctl, freezer, caplog
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "refuse"
    with caplog.at_level(logging.WARNING):
        await _advance(hass, freezer, 185)
    assert "would declare failure" in caplog.text
    assert coord.install_in_progress is True
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []


async def test_ui_fail_point_is_silent_once_reconnected(
    hass, enable_custom_integrations, ctl, freezer, caplog
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    with caplog.at_level(logging.WARNING):
        await _advance(hass, freezer, 60)
    assert "would declare failure" not in caplog.text


async def test_progress_tick_notifies_listeners(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    listener = MagicMock()
    coord.async_add_listener(listener)
    await coord.async_begin_install_window()
    listener.reset_mock()
    await _advance(hass, freezer, 5)
    assert listener.call_count >= 1


async def test_timers_cancelled_when_window_ends(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    # Silence the regular poll schedule so only install timers could notify.
    coord.update_interval = None
    listener = MagicMock()
    coord.async_add_listener(listener)
    await coord.async_begin_install_window()
    assert len(coord._install_unsubs) == 3

    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    assert coord._install_unsubs == []
    listener.reset_mock()
    await _advance(hass, freezer, 2000)
    listener.assert_not_called()
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None


async def test_timers_cancelled_on_entry_unload(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    listener = MagicMock()
    coord.async_add_listener(listener)
    await coord.async_begin_install_window()
    assert len(coord._install_unsubs) == 3

    # What HA runs when the entry unloads.
    await coord.entry._async_process_on_unload(hass)
    assert coord._install_unsubs == []
    assert coord.install_in_progress is False

    listener.reset_mock()
    await _advance(hass, freezer, 2000)
    listener.assert_not_called()
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None


# ---------------------------------------------------------------------------
# One-shot install request
# ---------------------------------------------------------------------------


async def test_install_request_body_strips_secrets_and_sends_once(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
    with caplog.at_level(logging.DEBUG):
        outcome = await coord.async_request_firmware_install()
    assert outcome == "accepted"

    # Fresh GET of nconf first, then exactly one PUT.
    assert len(ctl.calls_for("GET", "/rest/config/nconf")) == 1
    puts = ctl.calls_for("PUT", "/rest/config/nconf")
    assert len(puts) == 1
    body = puts[0]["json"]
    assert body["updateFirmware"] is True
    for stripped in ("password", "emailPassword", "wifiAPPassword", "ssid"):
        assert stripped not in body
    # Everything else the controller returned is passed through unchanged.
    expected = {
        k: v
        for k, v in NCONF.items()
        if k not in ("password", "emailPassword", "wifiAPPassword", "ssid")
    }
    expected["updateFirmware"] = True
    assert body == expected

    headers = puts[0]["headers"]
    assert headers["accept-version"] == "1"
    assert "csrf-token" not in headers
    assert headers["Cookie"] == f"connect.sid={SENTINEL_SID}"

    # The window is open, restarting, and the clock started when the PUT returned.
    assert coord.install_in_progress is True
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_RESTARTING,
        0,
    )

    # Secrets and nconf contents are never logged or kept.
    for secret in (
        SENTINEL_PASSWORD,
        SENTINEL_EMAIL_PASSWORD,
        SENTINEL_WIFI_PASSWORD,
        SENTINEL_SSID,
        SENTINEL_SID,
        "configured-password",
    ):
        assert secret not in caplog.text
        assert secret not in repr(vars(coord))
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_install_request_accepts_unwrapped_nconf_payload(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.nconf_wrapped = False
    await coord.async_request_firmware_install()
    body = ctl.calls_for("PUT", "/rest/config/nconf")[0]["json"]
    assert body["updateFirmware"] is True
    assert "password" not in body
    assert body["hostname"] == "apex-test"
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_install_request_clock_starts_when_put_returns(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    original_put = ctl.put

    def _slow_put(url: str, **kwargs: Any) -> _Resp:
        freezer.tick(timedelta(seconds=9))
        return original_put(url, **kwargs)

    ctl.put = _slow_put  # type: ignore[method-assign]
    await coord.async_request_firmware_install()
    assert coord.install_percentage == 0
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


@pytest.mark.parametrize(
    "put_result",
    [
        asyncio.TimeoutError(),
        aiohttp.ServerDisconnectedError(),
        aiohttp.ClientConnectionResetError("reset"),
        500,
        502,
        302,
    ],
)
async def test_ambiguous_put_result_opens_window_and_is_never_resent(
    hass, enable_custom_integrations, ctl, put_result, caplog
):
    coord = await _polled(hass, ctl)
    ctl.put_result = put_result
    with caplog.at_level(logging.WARNING):
        outcome = await coord.async_request_firmware_install()
    assert outcome == "possibly_started"
    assert "not resending" in caplog.text
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1
    assert coord.install_in_progress is True

    # Polls and a later window end never trigger a second PUT either.
    ctl.mode = "refuse"
    await coord.async_refresh()
    await coord.async_end_install_window(INSTALL_RESULT_TIMEOUT)
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "rejected the firmware install session"),
        (403, "rejected the firmware install session"),
        (404, "does not support"),
        (405, "does not support"),
        (400, "rejected the firmware install request"),
        (429, "rejected the firmware install request"),
    ],
)
async def test_definite_rejection_closes_window_without_retry(
    hass, enable_custom_integrations, ctl, status, message
):
    coord = await _polled(hass, ctl)
    ctl.put_result = status
    with pytest.raises(HomeAssistantError, match=message):
        await coord.async_request_firmware_install()
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1
    assert coord.install_in_progress is False
    assert coord._install_unsubs == []
    # Rejection is not a timeout: no Repairs issue.
    assert ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id) is None


async def test_install_request_preconditions(hass, enable_custom_integrations, ctl):
    legacy = await _make_coordinator(hass, **{CONF_TRANSPORT: TRANSPORT_LEGACY})
    with pytest.raises(HomeAssistantError, match="REST transport"):
        await legacy.async_request_firmware_install()

    no_password = await _make_coordinator(hass, **{CONF_PASSWORD: ""})
    with pytest.raises(HomeAssistantError, match="password"):
        await no_password.async_request_firmware_install()

    no_login = await _make_coordinator(hass, **{CONF_NO_LOGIN: True})
    with pytest.raises(HomeAssistantError, match="password"):
        await no_login.async_request_firmware_install()

    assert ctl.calls == []

    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    with pytest.raises(HomeAssistantError, match="already in progress"):
        await coord.async_request_firmware_install()
    assert ctl.calls == []
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_install_request_without_nconf_endpoint_sends_nothing(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.nconf_status = 404
    with pytest.raises(HomeAssistantError, match="network config"):
        await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


async def test_install_request_with_unknown_version_sends_nothing(
    hass, enable_custom_integrations, ctl
):
    coord = await _make_coordinator(hass)
    with pytest.raises(HomeAssistantError, match="version is unknown"):
        await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []


async def test_install_request_without_session_cookie_still_sends_once(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    original_get = ctl.get

    def _get_clearing_sid(url: str, **kwargs: Any) -> _Resp:
        resp = original_get(url, **kwargs)
        if url.endswith("/rest/config/nconf"):
            coord._rest_sid = None
        return resp

    ctl.get = _get_clearing_sid  # type: ignore[method-assign]
    await coord.async_request_firmware_install()
    puts = ctl.calls_for("PUT", "/rest/config/nconf")
    assert len(puts) == 1
    assert "Cookie" not in puts[0]["headers"]
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_cached_latest_firmware_is_the_expected_version(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    assert coord._cached_latest_firmware() == NEW
    coord._cached_nconf = None
    assert coord._cached_latest_firmware() is None

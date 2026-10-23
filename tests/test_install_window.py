"""Tests for the firmware install window, progress model and request helper."""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import os
import socket
import stat
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, AsyncGenerator, cast
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

from custom_components.apex_fusion import async_remove_entry
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
    _parse_install_marker,
    _SingleConnectionConnector,
    install_progress,
    redact_nconf_for_install,
)
from custom_components.apex_fusion.firmware import firmware_is_newer

# The module-level fixture below replaces asyncio.sleep globally (login retries
# would otherwise sleep); tests that need to yield to the loop use this one.
_real_sleep = asyncio.sleep

# Resolved at runtime: the HA test harness only allows IPv4 loopback sockets.
_LOOPBACK = socket.gethostbyname("localhost")

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
    "emailTo": "owner@example.invalid",
    "password": SENTINEL_PASSWORD,
    "emailPassword": SENTINEL_EMAIL_PASSWORD,
    "wifiAPPassword": SENTINEL_WIFI_PASSWORD,
    "ssid": SENTINEL_SSID,
    "latestFirmware": NEW,
    "updateFirmware": False,
}
SECRET_VALUES = (
    SENTINEL_PASSWORD,
    SENTINEL_EMAIL_PASSWORD,
    SENTINEL_WIFI_PASSWORD,
    SENTINEL_SSID,
    SENTINEL_SID,
    "configured-password",
)


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
        self,
        status: int,
        body: Any = None,
        *,
        cookies: dict[str, str] | None = None,
        raw: str | None = None,
    ) -> None:
        self.status = status
        self._body = (
            raw if raw is not None else ("" if body is None else json.dumps(body))
        )
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
    nconf_body: str | None = None
    nconf: dict[str, Any] = field(default_factory=lambda: dict(NCONF))
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
            if self.nconf_body is not None:
                return _Resp(200, raw=self.nconf_body)
            return _Resp(
                200, {"nconf": self.nconf} if self.nconf_wrapped else self.nconf
            )
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


def _patch_common(monkeypatch: pytest.MonkeyPatch, controller: _Controller) -> None:
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


@pytest.fixture
def ctl(monkeypatch: pytest.MonkeyPatch) -> _Controller:
    """Fake controller serving the shared session and the one-shot sessions."""
    controller = _Controller()
    _patch_common(monkeypatch, controller)

    @asynccontextmanager
    async def _fake_one_shot() -> AsyncGenerator[Any]:
        yield controller

    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator._one_shot_session", _fake_one_shot
    )
    return controller


@pytest.fixture
def ctl_wire(monkeypatch: pytest.MonkeyPatch) -> _Controller:
    """Fake shared session (login/poll) but the REAL one-shot sessions."""
    controller = _Controller()
    _patch_common(monkeypatch, controller)
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


def _coordinator_for(hass: Any, entry: Any) -> ApexNeptuneDataUpdateCoordinator:
    token = current_entry.set(entry)
    try:
        return ApexNeptuneDataUpdateCoordinator(hass, entry=entry)
    finally:
        current_entry.reset(token)


async def _make_coordinator(
    hass: Any, **overrides: Any
) -> ApexNeptuneDataUpdateCoordinator:
    return _coordinator_for(hass, _make_entry(hass, **overrides))


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
    await hass.async_block_till_done(wait_background_tasks=True)


async def _spin(times: int = 10) -> None:
    for _ in range(times):
        await _real_sleep(0)


def _marker_key(coord: ApexNeptuneDataUpdateCoordinator) -> str:
    return f"{DOMAIN}.install_{coord.entry.entry_id}"


def _issue(hass: Any, coord: ApexNeptuneDataUpdateCoordinator) -> Any:
    return ir.async_get(hass).async_get_issue(DOMAIN, coord._install_issue_id)


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
# Redaction rule (finding 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "PASSWORD",
        "emailpassword",
        "emailPassword",
        "wifiAPPassword",
        "adminPwd",
        "apiToken",
        "secret",
        "clientSecret",
        "apiKey",
        "wifiKey",
        "Key",
        "emailAuth",
        "authHeader",
        "credentials",
        "ssid",
        "SSID",
        "wifiSsid",
    ],
)
def test_redaction_drops_secret_like_keys_at_top_level(key):
    assert redact_nconf_for_install({key: "x", "hostname": "h"}) == {"hostname": "h"}


def test_redaction_is_recursive_through_dicts_and_lists():
    value: dict[str, Any] = {
        "hostname": "apex-test",
        "user": "admin",
        "network": {"password": "p", "host": "h", "inner": {"Token": "t", "ok": 1}},
        "wifi": {"Key": "k", "mode": "ap"},
        "peers": [{"secret": "s", "name": "n"}, 3, "plain"],
    }
    assert redact_nconf_for_install(value) == {
        "hostname": "apex-test",
        "user": "admin",
        "network": {"host": "h", "inner": {"ok": 1}},
        "wifi": {"mode": "ap"},
        "peers": [{"name": "n"}, 3, "plain"],
    }
    # The input is not mutated.
    assert value["network"]["password"] == "p"


def test_redaction_keeps_known_non_secret_ui_fields():
    ui_fields = {
        "id": "network",
        "dhcp": True,
        "hostname": "h",
        "ipaddr": "192.0.2.10",
        "netmask": "255.255.255.0",
        "gateway": "192.0.2.1",
        "dns": "192.0.2.1",
        "httpPort": 80,
        "emailEnable": False,
        "smtpPort": 25,
        "smtpServer": "mail.example.invalid",
        "emailFrom": "a@example.invalid",
        "emailTo": "b@example.invalid",
        "reEmail": 0,
        "emailUser": "u",
        "wifiAPLock": False,
        "wifiAP": False,
        "wifiEnable": False,
        "updateFirmware": False,
        "user": "admin",
        "fusionEnable": True,
        "latestFirmware": NEW,
    }
    assert redact_nconf_for_install(ui_fields) == ui_fields


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

    # A verified version change after the soak finishes it on that poll.
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

    for _ in range(4):
        await _advance(hass, freezer, 100)
        await coord.async_refresh()
        assert coord.install_in_progress is True

    ctl.software = NEW
    await coord.async_refresh()
    assert coord.install_in_progress is False
    await hass.async_block_till_done()
    assert _issue(hass, coord) is None


async def test_version_at_reconnect_keeps_window_open_through_web_pages_soak(
    hass, enable_custom_integrations, ctl, freezer
):
    """The version may flip at reconnect; writes stay blocked for the soak."""
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    listener = MagicMock()
    coord.async_add_listener(listener)
    await coord.async_begin_install_window(expected_version=NEW)

    ctl.mode = "refuse"
    await _advance(hass, freezer, 130)
    ctl.mode = "ok"
    ctl.software = NEW
    await coord.async_refresh()

    # Version already changed, but the window (and write block) stays open.
    assert coord.install_in_progress is True
    assert (coord.install_phase, coord.install_percentage) == (
        INSTALL_PHASE_WEB_PAGES,
        50,
    )
    with pytest.raises(HomeAssistantError, match="firmware install is in progress"):
        await coord.async_rest_put_json(path="/rest/config/mconf/1", payload={})

    await _advance(hass, freezer, 60)
    assert coord.install_in_progress is True
    assert coord.install_percentage == 74
    assert 100 not in [c.args for c in listener.call_args_list]

    # The timer (no further poll) finishes it once the soak has elapsed.
    await _advance(hass, freezer, 61)
    assert coord.install_in_progress is False
    assert coord.install_percentage is None
    assert ctl.calls_for("GET", "/rest/config")
    # Writes work again, and the persisted marker is gone.
    await coord.async_rest_put_json(path="/rest/config/mconf/1", payload={})
    assert _marker_key(coord) not in _storage(hass)


async def test_version_before_restart_period_waits_for_reconnect_and_soak(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    await coord.async_begin_install_window()

    # Version reported early (before the 120 s restart period): recorded only.
    await _advance(hass, freezer, 30)
    ctl.software = NEW
    await coord.async_refresh()
    assert coord.install_in_progress is True
    assert coord._install_reconnected_at is None
    assert coord.install_phase == INSTALL_PHASE_RESTARTING

    await _advance(hass, freezer, 100)
    await coord.async_refresh()
    assert coord._install_reconnected_at is not None
    assert coord.install_in_progress is True

    await _advance(hass, freezer, 125)
    assert coord.install_in_progress is False


async def test_unexpected_version_is_flagged_and_still_waits_for_soak(
    hass, enable_custom_integrations, ctl, freezer, caplog
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    await coord.async_begin_install_window(expected_version=NEW)
    ctl.software = "5.99Z_0000"
    await _advance(hass, freezer, 130)
    with caplog.at_level(logging.WARNING):
        await coord.async_refresh()
    assert "not the expected" in caplog.text
    assert coord.install_in_progress is True
    await _advance(hass, freezer, 125)
    assert coord.install_in_progress is False


async def test_post_install_config_refresh_failure_is_logged_not_raised(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
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
    before = time.monotonic()
    coord._disable_rest(seconds=300, reason="test")
    assert coord._rest_disabled_until - before <= 31
    assert outside - before > 200


async def test_rate_limited_poll_in_window_backs_off_briefly(
    hass, enable_custom_integrations, ctl
):
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


# ---------------------------------------------------------------------------
# Write blocking and serialization (findings 3 and 4)
# ---------------------------------------------------------------------------


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


async def test_control_write_context_is_blocked_during_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    async with coord.async_control_write():
        pass
    await coord.async_begin_install_window()
    with pytest.raises(HomeAssistantError, match="firmware install is in progress"):
        async with coord.async_control_write():
            raise AssertionError("must not run")  # pragma: no cover
    # The lock was released by the failed entry.
    assert not coord._write_lock.locked()


async def test_write_suspended_at_login_serializes_with_install_open(
    hass, enable_custom_integrations, ctl, monkeypatch
):
    """A write that is mid-login when the install opens can never send during it."""
    coord = await _polled(hass, ctl)
    entered = asyncio.Event()
    release = asyncio.Event()
    real_login = coord._async_rest_login

    async def _slow_login(*, session: Any) -> str:
        entered.set()
        await release.wait()
        return await real_login(session=session)

    monkeypatch.setattr(coord, "_async_rest_login", _slow_login)

    write1 = asyncio.create_task(
        coord.async_rest_put_json(path="/rest/config/mconf/1", payload={"n": 1})
    )
    await entered.wait()
    begin = asyncio.create_task(coord.async_begin_install_window())
    write2 = asyncio.create_task(
        coord.async_rest_put_json(path="/rest/config/mconf/2", payload={"n": 2})
    )
    await _spin()

    # The install cannot open under an in-flight write, and nothing was sent yet.
    assert coord.install_in_progress is False
    assert not begin.done()
    assert ctl.calls_for("PUT", "/rest/config/mconf/1") == []

    release.set()
    await write1
    await begin
    assert coord.install_in_progress is True
    # Queued behind the install open: refused at send time, nothing on the wire.
    with pytest.raises(HomeAssistantError, match="firmware install is in progress"):
        await write2
    assert len(ctl.calls_for("PUT", "/rest/config/mconf/1")) == 1
    assert ctl.calls_for("PUT", "/rest/config/mconf/2") == []
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_send_time_guard_catches_window_opened_without_the_lock(
    hass, enable_custom_integrations, ctl, monkeypatch
):
    """Defence in depth: the guard right before the PUT is independent."""
    coord = await _polled(hass, ctl)
    real_login = coord._async_rest_login

    async def _login_then_open(*, session: Any) -> str:
        sid = await real_login(session=session)
        coord._install_active = True  # bypasses the lock on purpose
        return sid

    monkeypatch.setattr(coord, "_async_rest_login", _login_then_open)
    with pytest.raises(HomeAssistantError, match="firmware install is in progress"):
        await coord.async_rest_put_json(path="/rest/config/mconf/1", payload={})
    assert ctl.calls_for("PUT", "/rest/config/mconf/1") == []
    coord._install_active = False


# ---------------------------------------------------------------------------
# Hard cap, warning, timers
# ---------------------------------------------------------------------------


async def test_hard_cap_raises_repair_issue_closes_window_and_never_retries(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    assert _marker_key(coord) in _storage(hass)
    ctl.mode = "refuse"

    await _advance(hass, freezer, 1199)
    assert coord.install_in_progress is True
    assert _issue(hass, coord) is None

    await _advance(hass, freezer, 2)
    assert coord.install_in_progress is False
    assert coord.install_phase is None
    assert coord.install_percentage is None

    issue = _issue(hass, coord)
    assert issue is not None
    assert issue.translation_key == "firmware_install_unconfirmed"
    assert issue.severity == ir.IssueSeverity.ERROR
    assert issue.is_fixable is False
    # Nothing was ever sent: in particular no second install request.
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord._install_unsubs == []
    assert _marker_key(coord) not in _storage(hass)

    # Beginning a new window clears the stale issue.
    ctl.mode = "ok"
    await coord.async_refresh()
    await coord.async_begin_install_window()
    assert _issue(hass, coord) is None
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_hard_cap_timer_is_a_noop_after_the_window_closed(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord._async_install_hard_cap(None)
    assert _issue(hass, coord) is None


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
    assert _issue(hass, coord) is None
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
    assert _issue(hass, coord) is None


async def test_timers_cancelled_on_entry_unload(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
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
    assert _issue(hass, coord) is None


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

    # One fresh GET of nconf, then exactly one PUT.
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
    for secret in SECRET_VALUES:
        assert secret not in caplog.text
        assert secret not in repr(vars(coord))
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_install_request_redacts_variant_and_nested_secret_keys(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.nconf = {
        "hostname": "apex-test",
        "user": "admin",
        "Password": SENTINEL_PASSWORD,
        "emailpassword": SENTINEL_EMAIL_PASSWORD,
        "network": {"password": SENTINEL_PASSWORD, "gateway": "192.0.2.1"},
        "wifi": {"Key": SENTINEL_WIFI_PASSWORD, "mode": "ap"},
        "SSID": SENTINEL_SSID,
    }
    await coord.async_request_firmware_install()
    body = ctl.calls_for("PUT", "/rest/config/nconf")[0]["json"]
    assert body == {
        "hostname": "apex-test",
        "user": "admin",
        "network": {"gateway": "192.0.2.1"},
        "wifi": {"mode": "ap"},
        "updateFirmware": True,
    }
    assert not any(secret in json.dumps(body) for secret in SECRET_VALUES)
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
        aiohttp.ClientConnectionError("single-use connection already used"),
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


async def test_connect_failure_means_nothing_was_sent_and_closes_window(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.put_result = aiohttp.ClientConnectorError(MagicMock(), OSError("refused"))
    with pytest.raises(HomeAssistantError, match="not sent"):
        await coord.async_request_firmware_install()
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1
    assert coord.install_in_progress is False
    assert _marker_key(coord) not in _storage(hass)
    # Not a timeout: no Repairs issue.
    assert _issue(hass, coord) is None


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
    assert _marker_key(coord) not in _storage(hass)
    # Rejection is not a timeout: no Repairs issue.
    assert _issue(hass, coord) is None


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

    coord._rest_disabled_until = time.monotonic() + 100
    with pytest.raises(HomeAssistantError, match="temporarily disabled"):
        await coord.async_request_firmware_install()
    assert ctl.calls == []


async def test_install_request_with_unknown_version_sends_nothing(
    hass, enable_custom_integrations, ctl
):
    coord = await _make_coordinator(hass)
    with pytest.raises(HomeAssistantError, match="version is unknown"):
        await coord.async_request_firmware_install()
    assert ctl.calls == []


async def test_install_request_login_not_found_sends_nothing(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    coord._rest_sid = None
    ctl.mode = "404"
    with pytest.raises(HomeAssistantError, match="REST login"):
        await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


# --- nconf read: one bounded request (finding 9) ---------------------------


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "rejected the session"),
        (403, "rejected the session"),
        (404, "does not expose its network config"),
        (500, r"HTTP 500\); nothing was sent"),
    ],
)
async def test_nconf_read_is_a_single_request_and_failure_sends_nothing(
    hass, enable_custom_integrations, ctl, status, message
):
    coord = await _polled(hass, ctl)
    ctl.nconf_status = status
    with pytest.raises(HomeAssistantError, match=message):
        await coord.async_request_firmware_install()
    # No relogin-and-retry: one GET, no second login, no PUT, no window.
    assert len(ctl.calls_for("GET", "/rest/config/nconf")) == 1
    assert ctl.calls_for("POST", "/rest/login") == []
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False
    assert _marker_key(coord) not in _storage(hass)
    if status in (401, 403):
        assert coord._rest_sid is None


@pytest.mark.parametrize(
    ("body", "message"),
    [("not json", "not valid JSON"), ("[1, 2]", "not a JSON object")],
)
async def test_nconf_read_rejects_unusable_bodies(
    hass, enable_custom_integrations, ctl, body, message
):
    coord = await _polled(hass, ctl)
    ctl.nconf_body = body
    with pytest.raises(HomeAssistantError, match=message):
        await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


async def test_nconf_read_empty_body_is_treated_as_empty_object(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    ctl.nconf_body = ""
    await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf")[0]["json"] == {
        "updateFirmware": True
    }
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


@pytest.mark.parametrize("mode", ["refuse", "timeout"])
async def test_nconf_read_transport_error_sends_nothing(
    hass, enable_custom_integrations, ctl, mode
):
    coord = await _polled(hass, ctl)
    ctl.mode = "ok"
    original_get = ctl.get

    def _get(url: str, **kwargs: Any) -> _Resp:
        if url.endswith("/rest/config/nconf"):
            ctl.mode = mode
        return original_get(url, **kwargs)

    ctl.get = _get  # type: ignore[method-assign]
    with pytest.raises(HomeAssistantError, match="Could not read"):
        await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


# ---------------------------------------------------------------------------
# Persistence across reload / restart (findings 6 and 8)
# ---------------------------------------------------------------------------


class _MarkerFiles:
    """Dict-like view of the install-marker files in this test's config dir."""

    def __init__(self, hass: Any) -> None:
        self._hass = hass

    def _path(self, key: str) -> str:
        return cast(str, self._hass.config.path(".storage", key))

    def __contains__(self, key: object) -> bool:
        return os.path.exists(self._path(cast(str, key)))

    def get(self, key: str, default: Any = None) -> Any:
        return self[key] if key in self else default

    def __getitem__(self, key: str) -> Any:
        with open(self._path(key), encoding="utf-8") as handle:
            return json.load(handle)

    def __setitem__(self, key: str, value: Any) -> None:
        os.makedirs(os.path.dirname(self._path(key)), exist_ok=True)
        with open(self._path(key), "w", encoding="utf-8") as handle:
            handle.write(value if isinstance(value, str) else json.dumps(value))


def _storage(hass: Any) -> _MarkerFiles:
    return _MarkerFiles(hass)


@pytest.fixture(autouse=True)
def _isolated_config_dir(hass, tmp_path):
    """Real marker files, in a per-test directory."""
    hass.config.config_dir = str(tmp_path)
    yield


def _marker_envelope(coord: ApexNeptuneDataUpdateCoordinator, **data: Any) -> Any:
    return {
        "version": 1,
        "minor_version": 1,
        "key": _marker_key(coord),
        "data": {
            "entry_id": coord.entry.entry_id,
            "attempt_id": "0000000000000000",
            "started_at": 1.0,
            "expires_at": 1201.0,
            "from_version": OLD,
            "expected_version": NEW,
            **data,
        },
    }


async def test_marker_is_persisted_before_the_put_is_sent(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    seen: dict[str, Any] = {}
    original_put = ctl.put

    def _put(url: str, **kwargs: Any) -> _Resp:
        seen.update(_storage(hass).get(_marker_key(coord), {}))
        return original_put(url, **kwargs)

    ctl.put = _put  # type: ignore[method-assign]
    await coord.async_request_firmware_install()

    marker = seen["data"]
    assert marker["entry_id"] == coord.entry.entry_id
    assert marker["from_version"] == OLD
    assert marker["expires_at"] - marker["started_at"] == 1200
    for secret in SECRET_VALUES:
        assert secret not in json.dumps(seen)
    # Owner-only file under .storage, written by the atomic writer.
    mode = os.stat(hass.config.path(".storage", _marker_key(coord))).st_mode
    assert mode & 0o077 == 0
    await coord.async_end_install_window(INSTALL_RESULT_SUCCESS)
    assert _marker_key(coord) not in _storage(hass)


async def test_marker_is_written_with_the_atomic_fsynced_writer(
    hass, enable_custom_integrations, ctl
):
    from homeassistant.util.file import write_utf8_file_atomic

    coord = await _polled(hass, ctl)
    with patch(
        "custom_components.apex_fusion.coordinator.write_utf8_file_atomic",
        wraps=write_utf8_file_atomic,
    ) as writer:
        await coord.async_begin_install_window()
    writer.assert_called_once()
    assert writer.call_args.kwargs == {"private": True}
    assert writer.call_args.args[0] == hass.config.path(".storage", _marker_key(coord))
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_marker_writer_failure_aborts_before_anything_is_sent(
    hass, enable_custom_integrations, ctl
):
    from homeassistant.util.file import WriteError

    coord = await _polled(hass, ctl)
    with patch(
        "custom_components.apex_fusion.coordinator.write_utf8_file_atomic",
        side_effect=WriteError("disk full"),
    ):
        with pytest.raises(HomeAssistantError, match="not starting the update"):
            await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False
    assert _marker_key(coord) not in _storage(hass)


@pytest.mark.parametrize("failing", ["file", "directory"])
async def test_real_file_fsync_failure_fails_closed_with_zero_puts(
    hass, enable_custom_integrations, ctl, failing
):
    """No mock of the store: the real atomic writer hits a real fsync error.

    The directory case fails *after* the rename, so the file is already in
    place with the new content; the attempt must still be refused and the file
    removed.
    """
    import atomicwrites

    coord = await _polled(hass, ctl)
    real_fsync = atomicwrites._proper_fsync

    def _fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode) == (failing == "directory"):
            raise OSError(errno.EIO, "fsync failed")
        real_fsync(fd)

    with patch.object(atomicwrites, "_proper_fsync", _fsync):
        with pytest.raises(HomeAssistantError, match="not starting the update"):
            await coord.async_request_firmware_install()

    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False
    assert _marker_key(coord) not in _storage(hass)
    # Nothing left behind in .storage (no temp file either).
    leftovers = os.listdir(hass.config.path(".storage"))
    assert [name for name in leftovers if "install" in name] == []


async def test_real_file_write_succeeds_when_fsync_works(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_request_firmware_install()
    stored = _storage(hass)[_marker_key(coord)]
    assert stored["data"]["from_version"] == OLD
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_no_install_while_home_assistant_is_stopping(
    hass, enable_custom_integrations, ctl
):
    from homeassistant.core import CoreState

    coord = await _polled(hass, ctl)
    hass.set_state(CoreState.stopping)
    try:
        with patch(
            "custom_components.apex_fusion.coordinator.write_utf8_file_atomic"
        ) as writer:
            with pytest.raises(HomeAssistantError, match="not starting the update"):
                await coord.async_request_firmware_install()
            with pytest.raises(HomeAssistantError, match="not starting the update"):
                await coord.async_begin_install_window()
    finally:
        hass.set_state(CoreState.running)
    writer.assert_not_called()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


async def test_read_back_error_fails_closed_and_cleans_up(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    with patch(
        "custom_components.apex_fusion.coordinator.json.load",
        side_effect=ValueError("unreadable"),
    ):
        with pytest.raises(HomeAssistantError, match="not starting the update"):
            await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    # The marker that was written for an install that never started is removed.
    assert _marker_key(coord) not in _storage(hass)


async def test_unused_marker_cleanup_failure_is_logged_as_a_warning(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
    with caplog.at_level(logging.WARNING):
        with (
            patch(
                "custom_components.apex_fusion.coordinator.json.load",
                side_effect=ValueError("unreadable"),
            ),
            patch(
                "custom_components.apex_fusion.coordinator._remove_install_marker_file",
                side_effect=OSError("ro"),
            ),
        ):
            with pytest.raises(HomeAssistantError, match="not starting the update"):
                await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("unused install marker" in r.getMessage() for r in warnings)


async def test_marker_carries_a_unique_attempt_id(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    freezer.move_to("2026-10-23 18:00:00")
    ids = []
    for _ in range(2):
        await coord.async_begin_install_window()
        ids.append(_storage(hass)[_marker_key(coord)]["data"]["attempt_id"])
        await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    assert ids[0] != ids[1]
    assert all(len(i) == 16 for i in ids)


async def test_equal_time_older_marker_does_not_confirm_a_write_that_did_nothing(
    hass, enable_custom_integrations, ctl, freezer
):
    """Fixed clock, an older marker with identical times already on disk."""
    from homeassistant.util import dt as dt_util

    coord = await _polled(hass, ctl)
    freezer.move_to("2026-10-23 18:00:00")
    started_at = dt_util.utcnow().timestamp()
    _storage(hass)[_marker_key(coord)] = _marker_envelope(
        coord, started_at=started_at, expires_at=started_at + 1200
    )

    with patch("custom_components.apex_fusion.coordinator.write_utf8_file_atomic"):
        with pytest.raises(HomeAssistantError, match="not starting the update"):
            await coord.async_request_firmware_install()
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []
    assert coord.install_in_progress is False


async def test_marker_remove_failure_is_logged_not_raised(
    hass, enable_custom_integrations, ctl, caplog
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    with caplog.at_level(logging.WARNING):
        with patch(
            "custom_components.apex_fusion.coordinator._remove_install_marker_file",
            side_effect=OSError("ro"),
        ):
            await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    assert "Could not remove the firmware install marker" in caplog.text
    assert coord.install_in_progress is False


async def test_reload_mid_install_resumes_window_and_refuses_second_request(
    hass, enable_custom_integrations, ctl, freezer, caplog
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_request_firmware_install()
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1

    # Entry reload / HA restart: the old coordinator goes away mid-install.
    freezer.tick(timedelta(seconds=130))
    await coord.async_shutdown()
    assert coord.install_in_progress is False
    assert _marker_key(coord) in _storage(hass)

    fresh = _coordinator_for(hass, entry)
    fresh.update_interval = None
    with caplog.at_level(logging.WARNING):
        await fresh.async_restore_install_window()
    assert "Resuming a firmware install" in caplog.text
    assert fresh.install_in_progress is True
    # The window resumed 130 s in: reconnecting phase, not a fresh restart.
    assert (fresh.install_phase, fresh.install_percentage) == (
        INSTALL_PHASE_RECONNECTING,
        41,
    )

    # A second install request is refused and nothing goes on the wire.
    ctl.calls.clear()
    with pytest.raises(HomeAssistantError, match="already in progress"):
        await fresh.async_request_firmware_install()
    assert ctl.calls == []

    # A boot-time 401 still maps to UpdateFailed, never reauth.
    ctl.mode = "401"
    with pytest.raises(UpdateFailed, match="installing firmware"):
        await fresh._async_update_data()

    # The resumed window keeps the original hard cap.
    ctl.mode = "refuse"
    await _advance(hass, freezer, 1100)
    assert fresh.install_in_progress is False
    assert _issue(hass, fresh) is not None
    assert _marker_key(fresh) not in _storage(hass)


async def test_resumed_window_completes_on_version_change_after_soak(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_request_firmware_install()
    await coord.async_shutdown()
    freezer.tick(timedelta(seconds=300))

    fresh = _coordinator_for(hass, entry)
    fresh.update_interval = None
    await fresh.async_restore_install_window()
    ctl.software = NEW
    await fresh.async_refresh()
    assert fresh.install_in_progress is True
    await _advance(hass, freezer, 125)
    assert fresh.install_in_progress is False
    assert _marker_key(fresh) not in _storage(hass)


async def test_restore_with_no_marker_clears_stale_issue(
    hass, enable_custom_integrations, ctl, freezer
):
    """timeout -> unload -> setup: the stale Repairs issue is removed."""
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    ctl.mode = "refuse"
    await _advance(hass, freezer, 1201)
    assert _issue(hass, coord) is not None

    await coord.async_shutdown()
    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    assert _issue(hass, fresh) is None
    assert fresh.install_in_progress is False


async def test_restore_keeps_issue_while_an_attempt_is_live(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    ir.async_create_issue(
        hass,
        DOMAIN,
        coord._install_issue_id,
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key="firmware_install_unconfirmed",
    )
    await coord.async_shutdown()
    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    assert fresh.install_in_progress is True
    assert _issue(hass, fresh) is not None
    await fresh.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_expired_marker_with_unchanged_version_raises_repair_issue(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    await coord.async_shutdown()
    freezer.tick(timedelta(minutes=25))

    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    assert fresh.install_in_progress is False
    assert _marker_key(fresh) in _storage(hass)

    await fresh.async_refresh()
    assert _issue(hass, fresh) is not None
    assert _marker_key(fresh) not in _storage(hass)
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []


async def test_expired_marker_with_new_version_resolves_quietly(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    await coord.async_shutdown()
    freezer.tick(timedelta(minutes=25))
    ctl.software = NEW

    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    await fresh.async_refresh()
    assert _issue(hass, fresh) is None
    assert _marker_key(fresh) not in _storage(hass)
    assert fresh.install_in_progress is False


async def test_expired_marker_waits_for_a_poll_that_reports_a_version(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    await coord.async_shutdown()
    freezer.tick(timedelta(minutes=25))

    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    await fresh._async_resolve_expired_install("")
    assert fresh._install_unresolved is not None
    assert _issue(hass, fresh) is None


@pytest.mark.parametrize(
    "content",
    [
        json.dumps({"data": {"started_at": "yesterday"}}),
        "this is not json",
        "[1, 2, 3]",
    ],
)
async def test_invalid_marker_is_discarded(
    hass, enable_custom_integrations, ctl, content
):
    coord = await _make_coordinator(hass)
    _storage(hass)[_marker_key(coord)] = content
    await coord.async_restore_install_window()
    assert coord.install_in_progress is False
    assert _marker_key(coord) not in _storage(hass)


def test_parse_install_marker():
    good = {
        "started_at": 100,
        "expires_at": 1300.5,
        "from_version": OLD,
        "expected_version": NEW,
    }
    assert _parse_install_marker(good) == (100.0, 1300.5, OLD, NEW)
    assert _parse_install_marker({**good, "expected_version": None}) == (
        100.0,
        1300.5,
        OLD,
        None,
    )
    assert _parse_install_marker("nope") is None
    assert _parse_install_marker({**good, "from_version": ""}) is None
    assert _parse_install_marker({**good, "expires_at": "x"}) is None


async def test_remove_entry_deletes_marker_and_issue(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ir.async_create_issue(
        hass,
        DOMAIN,
        coord._install_issue_id,
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key="firmware_install_unconfirmed",
    )
    assert _marker_key(coord) in _storage(hass)
    await async_remove_entry(hass, coord.entry)
    assert _marker_key(coord) not in _storage(hass)
    assert _issue(hass, coord) is None
    await coord.async_shutdown()


# ---------------------------------------------------------------------------
# Interleavings (findings 7 and the marker race)
# ---------------------------------------------------------------------------


async def test_window_closed_while_put_is_in_flight_does_not_rearm_timers(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    listener = MagicMock()
    coord.async_add_listener(listener)

    class _ClosingResp(_Resp):
        async def __aenter__(self) -> _Resp:
            await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
            return self

    ctl.put = lambda url, **kw: (  # type: ignore[method-assign]
        ctl.calls.append(("PUT", url, kw)) or _ClosingResp(200, {})
    )
    outcome = await coord.async_request_firmware_install()
    assert outcome == "accepted"
    assert coord.install_in_progress is False
    assert coord._install_unsubs == []

    listener.reset_mock()
    await _advance(hass, freezer, 2000)
    listener.assert_not_called()


async def test_stale_close_does_not_delete_a_newer_attempts_marker(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    await coord._marker_lock.acquire()
    closing = asyncio.create_task(
        coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    )
    await _spin()
    # A newer attempt takes over before the old close gets to the store.
    coord._install_generation += 1
    coord._marker_lock.release()
    await closing
    assert _marker_key(coord) in _storage(hass)


# ---------------------------------------------------------------------------
# Wire level (findings 1 and 9): real aiohttp against a real socket
# ---------------------------------------------------------------------------


class _WireServer:
    """Tiny HTTP/1.1 server that records what really arrives on the socket."""

    def __init__(self, *, get_mode: str = "ok", put_mode: str = "drop") -> None:
        self.get_mode = get_mode
        self.put_mode = put_mode
        self.connections = 0
        self.requests: list[tuple[str, str, bytes]] = []
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    def count(self, method: str) -> int:
        return sum(1 for m, _p, _b in self.requests if m == method)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, _LOOPBACK, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connections += 1
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, path, _ver = lines[0].split(" ")
                length = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1])
                body = await reader.readexactly(length) if length else b""
                self.requests.append((method, path, body))

                mode = self.get_mode if method == "GET" else self.put_mode
                if mode == "drop":
                    writer.close()  # processed, but the answer never arrives
                    return
                if mode == "reset":
                    writer.transport.abort()
                    return
                if mode == "401":
                    payload, status = b"{}", "401 Unauthorized"
                else:
                    payload, status = json.dumps({"nconf": NCONF}).encode(), "200 OK"
                writer.write(
                    f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                    + payload
                )
                await writer.drain()
                writer.close()
                return
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()


@pytest.fixture
async def wire(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> AsyncGenerator[_WireServer]:
    server = _WireServer()
    await server.start()
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.build_base_url",
        lambda _host: f"http://{_LOOPBACK}:{server.port}",
    )
    yield server
    await server.stop()


@pytest.mark.parametrize("put_mode", ["drop", "reset"])
async def test_wire_server_disconnect_after_receipt_puts_exactly_one_request(
    hass, enable_custom_integrations, ctl_wire, wire, put_mode
):
    """aiohttp's own transparent PUT retry must not reach the wire."""
    wire.put_mode = put_mode
    coord = await _polled(hass, ctl_wire)

    outcome = await coord.async_request_firmware_install()

    assert outcome == "possibly_started"
    assert coord.install_in_progress is True
    assert wire.count("PUT") == 1
    assert wire.count("GET") == 1
    # One connection for the nconf read, one for the PUT, none for a retry.
    assert wire.connections == 2
    put_body = json.loads(next(b for m, _p, b in wire.requests if m == "PUT"))
    assert put_body["updateFirmware"] is True
    assert "password" not in put_body
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_wire_successful_put_is_one_request(
    hass, enable_custom_integrations, ctl_wire, wire
):
    wire.put_mode = "ok"
    coord = await _polled(hass, ctl_wire)
    assert await coord.async_request_firmware_install() == "accepted"
    assert wire.count("PUT") == 1
    assert wire.connections == 2
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_wire_nconf_read_disconnect_is_not_retried(
    hass, enable_custom_integrations, ctl_wire, wire
):
    wire.get_mode = "drop"
    coord = await _polled(hass, ctl_wire)
    with pytest.raises(HomeAssistantError, match="Could not read"):
        await coord.async_request_firmware_install()
    assert wire.count("GET") == 1
    assert wire.count("PUT") == 0
    assert wire.connections == 1
    assert coord.install_in_progress is False


async def test_wire_nconf_read_401_is_not_retried(
    hass, enable_custom_integrations, ctl_wire, wire
):
    wire.get_mode = "401"
    coord = await _polled(hass, ctl_wire)
    with pytest.raises(HomeAssistantError, match="rejected the session"):
        await coord.async_request_firmware_install()
    assert wire.count("GET") == 1
    assert wire.count("PUT") == 0
    assert ctl_wire.calls_for("POST", "/rest/login") == []


async def test_wire_nconf_read_connect_failure_sends_nothing(
    hass, enable_custom_integrations, ctl_wire, wire
):
    coord = await _polled(hass, ctl_wire)
    await wire.stop()  # nothing listens on the port any more
    with pytest.raises(HomeAssistantError, match="Could not read"):
        await coord.async_request_firmware_install()
    assert wire.requests == []
    assert coord.install_in_progress is False


async def test_single_connection_connector_refuses_a_second_connection(socket_enabled):
    server = _WireServer(get_mode="ok")
    await server.start()
    connector = _SingleConnectionConnector()
    session = aiohttp.ClientSession(connector=connector)
    try:
        async with session.get(f"http://{_LOOPBACK}:{server.port}/a") as resp:
            assert resp.status == 200
        with pytest.raises(aiohttp.ClientConnectionError, match="single-use"):
            async with session.get(f"http://{_LOOPBACK}:{server.port}/b"):
                raise AssertionError("must not connect")  # pragma: no cover
        assert server.connections == 1
    finally:
        await session.close()
        await server.stop()


async def test_one_shot_session_helper_yields_a_working_session(socket_enabled):
    from custom_components.apex_fusion.coordinator import _one_shot_session

    server = _WireServer(get_mode="ok")
    await server.start()
    try:
        async with _one_shot_session() as session:
            async with session.get(f"http://{_LOOPBACK}:{server.port}/x") as resp:
                assert resp.status == 200
            assert not session.closed
        assert session.closed
    finally:
        await server.stop()


async def test_failed_connect_does_not_use_up_the_single_connection(socket_enabled):
    connector = _SingleConnectionConnector()
    session = aiohttp.ClientSession(connector=connector)
    server = _WireServer()
    await server.start()
    port = server.port
    await server.stop()  # nothing listens here any more
    try:
        with pytest.raises(aiohttp.ClientConnectorError):
            async with session.get(f"http://{_LOOPBACK}:{port}/x"):
                raise AssertionError("must not connect")  # pragma: no cover
        assert connector._connections_made == 0
    finally:
        await session.close()


async def test_rejection_after_the_window_already_closed_still_raises(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)

    class _ClosingResp(_Resp):
        async def __aenter__(self) -> _Resp:
            await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
            return self

    ctl.put = lambda url, **kw: (  # type: ignore[method-assign]
        ctl.calls.append(("PUT", url, kw)) or _ClosingResp(404, {})
    )
    with pytest.raises(HomeAssistantError, match="does not support"):
        await coord.async_request_firmware_install()
    assert coord.install_in_progress is False
    assert len(ctl.calls_for("PUT", "/rest/config/nconf")) == 1


# ---------------------------------------------------------------------------
# Recorded close result and downgrade handling (PR C requirements)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "installed", "expected"),
    [
        ("5.16L_AC26", "5.15J_6B26", True),
        ("5.15J_6B26", "5.16L_AC26", False),  # rollback
        ("5.14J_0001", "5.15J_6B26", False),  # rollback
        ("5.15J_6B26", "5.15J_6B26", False),  # unchanged
        ("5.16L_AC26", "5.16J_AC26", False),  # family letter ignored
        ("5.16L_BC27", "5.16J_AC26", True),  # same release line, other build
        ("6.00_0001", "5.99J_ZZ99", True),
        ("garbage", "5.15J_6B26", False),  # unparseable is never newer
        ("5.16L_AC26", "garbage", False),
        ("5.16L_AC26", None, False),
        (None, "5.15J_6B26", False),
    ],
)
def test_firmware_is_newer(candidate, installed, expected):
    assert firmware_is_newer(candidate, installed) is expected


async def test_last_install_result_is_none_before_any_attempt(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    assert coord.last_install_result is None
    assert coord.last_install_version is None
    await coord.async_begin_install_window()
    assert coord.last_install_result is None
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)


async def test_success_result_is_set_before_listeners_run(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    seen: list[tuple[bool, str | None, str | None]] = []

    def _listener() -> None:
        seen.append(
            (
                coord.install_in_progress,
                coord.last_install_result,
                coord.last_install_version,
            )
        )

    coord.async_add_listener(_listener)
    await coord.async_begin_install_window(expected_version=NEW)
    ctl.software = NEW
    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    await _advance(hass, freezer, 125)

    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_SUCCESS
    assert coord.last_install_version == NEW
    # Every notification that saw the window closed already saw the result.
    closed = [entry for entry in seen if entry[0] is False]
    assert closed
    assert all(r == (False, INSTALL_RESULT_SUCCESS, NEW) for r in closed)
    # And while it was open there was no result yet.
    assert all(r[1] is None for r in seen if r[0] is True)


async def test_late_version_change_that_misses_the_soak_is_a_timeout(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    await coord.async_begin_install_window()
    ctl.mode = "refuse"
    await _advance(hass, freezer, 1150)
    # The controller only answers at 1150 s, on the new version: the soak cannot
    # finish before the 20 minute cap.
    ctl.mode = "ok"
    ctl.software = NEW
    await coord.async_refresh()
    assert coord.install_in_progress is True
    await _advance(hass, freezer, 60)

    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    assert coord.last_install_version is None
    assert _issue(hass, coord) is not None


async def test_result_is_retained_after_close_and_reset_by_the_next_attempt(
    hass, enable_custom_integrations, ctl
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    await coord.async_end_install_window(INSTALL_RESULT_TIMEOUT)
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    # Nothing but the next attempt clears it.
    await coord.async_refresh()
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT

    await coord.async_begin_install_window()
    assert coord.last_install_result is None
    assert coord.last_install_version is None
    await coord.async_end_install_window(INSTALL_RESULT_REJECTED)
    assert coord.last_install_result == INSTALL_RESULT_REJECTED


@pytest.mark.parametrize("status", [400, 404])
async def test_rejected_request_records_a_rejected_result(
    hass, enable_custom_integrations, ctl, status
):
    coord = await _polled(hass, ctl)
    ctl.put_result = status
    with pytest.raises(HomeAssistantError):
        await coord.async_request_firmware_install()
    assert coord.last_install_result == INSTALL_RESULT_REJECTED
    assert coord.last_install_version is None


async def test_hard_cap_without_any_version_change_records_a_timeout(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    await coord.async_begin_install_window()
    ctl.mode = "refuse"
    await _advance(hass, freezer, 1201)
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT


@pytest.mark.parametrize("seen_version", ["5.14J_0001", "5.15J_6B26", "garbage"])
async def test_downgrade_or_unparseable_version_is_never_success(
    hass, enable_custom_integrations, ctl, freezer, caplog, seen_version
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    await coord.async_begin_install_window(expected_version=NEW)
    ctl.software = seen_version

    await _advance(hass, freezer, 130)
    with caplog.at_level(logging.WARNING):
        await coord.async_refresh()
        await _advance(hass, freezer, 200)
        await coord.async_refresh()
        await _advance(hass, freezer, 300)
        await coord.async_refresh()
    # Long past the soak, still waiting; no success.
    assert coord.install_in_progress is True
    assert coord.last_install_result is None
    assert coord._install_version_changed is False
    warned = [r for r in caplog.records if "not newer" in r.getMessage()]
    assert len(warned) == (0 if seen_version == OLD else 1)

    await _advance(hass, freezer, 700)
    assert coord.install_in_progress is False
    assert coord.last_install_result == INSTALL_RESULT_TIMEOUT
    assert coord.last_install_version is None
    assert _issue(hass, coord) is not None
    assert ctl.calls_for("PUT", "/rest/config/nconf") == []


async def test_rollback_then_newer_version_still_succeeds(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    coord.update_interval = None
    await coord.async_begin_install_window()
    ctl.software = "5.14J_0001"
    await _advance(hass, freezer, 130)
    await coord.async_refresh()
    assert coord._install_version_changed is False

    ctl.software = NEW
    await coord.async_refresh()
    assert coord._install_version_changed is True
    await _advance(hass, freezer, 125)
    assert coord.last_install_result == INSTALL_RESULT_SUCCESS
    assert coord.last_install_version == NEW


async def test_expired_marker_result_is_recorded(
    hass, enable_custom_integrations, ctl, freezer
):
    coord = await _polled(hass, ctl)
    entry = coord.entry
    await coord.async_begin_install_window()
    await coord.async_shutdown()
    freezer.tick(timedelta(minutes=25))
    ctl.software = NEW
    fresh = _coordinator_for(hass, entry)
    await fresh.async_restore_install_window()
    await fresh.async_refresh()
    assert fresh.last_install_result == INSTALL_RESULT_SUCCESS
    assert fresh.last_install_version == NEW

    # A rolled-back version at an expired marker is not success.
    await fresh.async_begin_install_window()
    await fresh.async_shutdown()
    freezer.tick(timedelta(minutes=25))
    ctl.software = "5.14J_0001"
    again = _coordinator_for(hass, entry)
    await again.async_restore_install_window()
    await again.async_refresh()
    assert again.last_install_result == INSTALL_RESULT_TIMEOUT
    assert again.last_install_version is None
    assert _issue(hass, again) is not None

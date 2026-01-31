"""Tests for coordinator update logic (REST + fallbacks)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import patch

import aiohttp
import pytest
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
)
from custom_components.apex_fusion.coordinator import ApexNeptuneDataUpdateCoordinator


class _NullTimeout:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


@dataclass
class _Resp:
    status: int
    body: str
    cookies: dict[str, Any] | None = None
    headers: Any = None

    def __post_init__(self):
        self.headers = self.headers or {"Content-Type": "application/json"}
        self.cookies = self.cookies or {}
        # Minimal attributes used by ClientResponseError construction.
        self.request_info = cast(Any, None)
        self.history = cast(Any, ())

    async def text(self) -> str:
        return self.body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=self.request_info,
                history=self.history,
                status=self.status,
                message="err",
                headers=self.headers,
            )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _CookieMorsel:
    def __init__(self, value: str):
        self.value = value


class _CookieJar:
    def __init__(self):
        self._cookies: dict[str, str] = {}

    def filter_cookies(self, _url):
        return {k: _CookieMorsel(v) for k, v in self._cookies.items()}

    def update_cookies(self, cookies: dict[str, str], response_url=None):
        self._cookies.update(cookies)


class _Session:
    def __init__(self):
        self.cookie_jar = _CookieJar()
        self._post_queue: list[_Resp | Exception] = []
        self._get_queue: list[_Resp | Exception] = []

    def queue_post(self, item: _Resp | Exception) -> None:
        self._post_queue.append(item)

    def queue_get(self, item: _Resp | Exception) -> None:
        self._get_queue.append(item)

    def post(self, *_args, **_kwargs):
        item = self._post_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        # Simulate aiohttp response cookies mapping.
        item.cookies = {k: _CookieMorsel(v) for k, v in (item.cookies or {}).items()}
        return item

    def get(self, *_args, **_kwargs):
        item = self._get_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


async def _make_coordinator(
    hass, *, host: str, username: str = "admin", password: str = "pw"
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: host, CONF_USERNAME: username, CONF_PASSWORD: password},
        unique_id=host,
        title=f"Apex ({host})",
    )
    entry.add_to_hass(hass)
    return ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))


async def test_rest_success_with_mconf_and_cookie(hass, enable_custom_integrations):
    session = _Session()
    # Coordinator probes /rest/status without a login first.
    session.queue_get(_Resp(401, "{}"))

    # Login sets cookie.
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))

    # Status payload (with cookie).
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    # mconf payload with MXM.
    session.queue_get(
        _Resp(
            200,
            '{"mconf": [{"hwtype": "MXM", "extra": {"status": "Nero 5(x) - Rev 1 Ser #: S1 - OK"}}]}',
        )
    )

    # nconf payload (contains secrets in real life; ensure we sanitize what we store).
    session.queue_get(
        _Resp(
            200,
            '{"nconf": {"latestFirmware": "5.12_CA25", "updateFirmware": false, "password": "pw"}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"
    assert "mxm_devices" in data

    config = data.get("config")
    assert isinstance(config, dict)
    assert config.get("nconf") == {
        "latestFirmware": "5.12_CA25",
        "updateFirmware": False,
    }


async def test_rest_trident_waste_size_from_mconf_and_nconf_404(
    hass, enable_custom_integrations
):
    session = _Session()
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "modules": [{"abaddr": 4, "hwtype": "TRI", "present": true, "swrev": 23, "extra": {"levels": [1,2,3,4,5]}}], "inputs": [], "outputs": []}',
        )
    )
    session.queue_get(
        _Resp(
            200,
            '{"mconf": [{"abaddr": 4, "hwtype": "TRI", "extra": {"wasteSize": 450.0}, "update": false, "updateStat": 0}]}',
        )
    )
    # nconf missing -> coordinator should ignore.
    session.queue_get(_Resp(404, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    trident = data.get("trident")
    assert isinstance(trident, dict)
    assert trident.get("waste_size_ml") == 450.0


async def test_rest_trident_mconf_tri_without_extra_does_not_set_waste_size(
    hass, enable_custom_integrations
):
    session = _Session()
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "modules": [{"abaddr": 4, "hwtype": "TRI", "present": true, "swrev": 23, "extra": {"levels": [1,2,3,4,5]}}], "inputs": [], "outputs": []}',
        )
    )
    # TRI module present but no extra in sanitized mconf -> should hit continue branch.
    session.queue_get(_Resp(200, '{"mconf": [{"abaddr": 4, "hwtype": "TRI"}]}'))
    session.queue_get(_Resp(404, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    trident = data.get("trident")
    assert isinstance(trident, dict)
    assert trident.get("waste_size_ml") is None


async def test_rest_nconf_bad_json_and_unexpected_error_are_handled(
    hass, enable_custom_integrations
):
    # First run: bad JSON -> JSONDecodeError path.
    session = _Session()
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )
    session.queue_get(_Resp(200, '{"mconf": []}'))
    session.queue_get(_Resp(200, "not-json"))

    coord = await _make_coordinator(hass, host="1.2.3.4")
    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"

    # Second run: unexpected error from session.get -> generic Exception path.
    session2 = _Session()
    session2.queue_get(_Resp(401, "{}"))
    session2.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session2.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )
    session2.queue_get(_Resp(200, '{"mconf": []}'))
    session2.queue_get(RuntimeError("boom"))

    coord2 = await _make_coordinator(hass, host="1.2.3.4")
    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session2,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data2 = await coord2._async_update_data()

    assert data2["meta"]["source"] == "rest"


async def test_rest_nconf_permission_error_is_handled(hass, enable_custom_integrations):
    session = _Session()
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {"ipaddr": "1.2.3.4"}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )
    session.queue_get(_Resp(200, '{"mconf": []}'))
    session.queue_get(_Resp(403, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_login_unauthorized_raises_auth_failed(
    hass, enable_custom_integrations
):
    session = _Session()
    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))
    # Login rejected.
    session.queue_post(_Resp(401, "{}"))
    # REST rejected -> coordinator falls back to legacy JSON, which rejects auth.
    session.queue_get(_Resp(401, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()


async def test_rest_status_unauthorized_falls_back_to_legacy_json(
    hass, enable_custom_integrations
):
    session = _Session()
    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    # REST status unauthorized -> fall back to legacy.
    session.queue_get(_Resp(401, "{}"))
    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_transient_error_retries_then_falls_back_to_legacy_json(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # First REST login attempt: transient status triggers ClientResponseError.
    session.queue_post(_Resp(503, "{}"))
    # Second REST login attempt: REST not supported -> fallback.
    session.queue_post(_Resp(404, "{}"))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    async def _no_sleep(_secs: float):
        return None

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
        patch("custom_components.apex_fusion.coordinator.asyncio.sleep", new=_no_sleep),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_legacy_json_404_falls_back_to_xml(hass, enable_custom_integrations):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(404, "{}"))

    # REST not supported.
    session.queue_post(_Resp(404, "{}"))

    # legacy json 404
    session.queue_get(_Resp(404, "{}"))

    # xml success
    session.queue_get(
        _Resp(
            200,
            """<status software='1.0' hardware='Apex'><hostname>apex</hostname><serial>ABC</serial><timezone>UTC</timezone><date>now</date><probes></probes><outlets></outlets></status>""",
            headers={"Content-Type": "application/xml"},
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "xml"


async def test_legacy_json_unauthorized_raises_auth_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(404, "{}"))

    # REST not supported.
    session.queue_post(_Resp(404, "{}"))

    # legacy json 401
    session.queue_get(_Resp(401, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()


async def test_legacy_xml_parse_error_raises_update_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(404, "{}"))

    # REST not supported.
    session.queue_post(_Resp(404, "{}"))

    # legacy json 404
    session.queue_get(_Resp(404, "{}"))

    # xml invalid
    session.queue_get(_Resp(200, "<bad", headers={"Content-Type": "application/xml"}))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()


async def test_rest_status_payload_not_dict_raises_update_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(_Resp(200, "[]"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()


async def test_rest_mconf_optional_errors_are_ignored(hass, enable_custom_integrations):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )
    # mconf 404 should be ignored
    session.queue_get(_Resp(404, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_exhausts_retries_and_raises_update_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # Three attempts: raise ClientError each time.
    session.queue_post(aiohttp.ClientError("boom"))
    session.queue_post(aiohttp.ClientError("boom"))
    session.queue_post(aiohttp.ClientError("boom"))

    # After REST fails, legacy JSON also fails to force final XML.
    session.queue_get(aiohttp.ClientError("boom"))
    session.queue_get(aiohttp.ClientError("boom"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    async def _no_sleep(_secs: float):
        return None

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
        patch("custom_components.apex_fusion.coordinator.asyncio.sleep", new=_no_sleep),
    ):
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()


async def test_rest_disabled_until_skips_rest_and_falls_back_to_legacy_json(
    hass, enable_custom_integrations
):
    session = _Session()

    # REST is disabled; coordinator should skip REST entirely.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")
    coord._rest_disabled_until = time.monotonic() + 60

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_cached_sid_skips_login_and_succeeds(
    hass, enable_custom_integrations
):
    session = _Session()
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")
    coord._rest_sid = "abc"

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_login_uses_sid_from_json_body(hass, enable_custom_integrations):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))
    # login returns connect.sid in JSON body
    session.queue_post(_Resp(200, '{"connect.sid": "abc"}'))
    # status with cookie
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_rate_limited_on_no_login_probe_falls_back_to_legacy_json(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login REST status probe returns 429 with Retry-After
    session.queue_get(_Resp(429, "{}", headers={"Retry-After": "3"}))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_rate_limited_on_login_sets_backoff_and_falls_back(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # login 429 with invalid Retry-After -> default backoff
    session.queue_post(_Resp(429, "{}", headers={"Retry-After": "bogus"}))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"
    assert coord._rest_disabled_until > time.monotonic()


async def test_coordinator_device_identifier_and_serial_cache(
    hass, enable_custom_integrations
):
    coord = await _make_coordinator(hass, host="1.2.3.4")

    # Default: stable non-IP fallback.
    assert coord.device_identifier.startswith("entry:")

    # Cached serial takes priority.
    coord._cached_serial = "SER123"
    assert coord.device_identifier == "SER123"

    # meta non-dict is normalized, and cached serial is injected when missing.
    data = coord._apply_serial_cache({"meta": "nope"})
    assert isinstance(data["meta"], dict)
    assert data["meta"]["serial"] == "SER123"


async def test_rest_cached_status_path_is_used(hass, enable_custom_integrations):
    session = _Session()
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")
    coord._rest_sid = "abc"
    coord._rest_status_path = "/rest/status"

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_rate_limited_without_retry_after_uses_default_backoff(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login REST status probe returns 429 with no Retry-After header
    session.queue_get(_Resp(429, "{}", headers={"Content-Type": "application/json"}))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"
    # No-login rate limiting currently falls back to legacy without disabling REST.
    assert coord._rest_disabled_until == 0.0


async def test_rest_rate_limited_with_blank_retry_after(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login REST status probe returns 429 with blank Retry-After
    session.queue_get(
        _Resp(
            429,
            "{}",
            headers={"Content-Type": "application/json", "Retry-After": "  "},
        )
    )

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_status_transient_error_falls_back_to_legacy(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe returns transient HTTP error (e.g. 503)
    session.queue_get(_Resp(503, "{}"))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_login_cookie_jar_sid_is_used(hass, enable_custom_integrations):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # Simulate cookie jar already having connect.sid.
    session.cookie_jar.update_cookies({"connect.sid": "jar_sid"})

    # Login response has no cookies, but cookie jar does.
    session.queue_post(_Resp(200, "{}"))

    # Status success.
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_login_body_invalid_json_falls_back_to_legacy(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # Login response body isn't JSON; no cookies either.
    session.queue_post(_Resp(200, "{no"))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_cached_sid_status_404_triggers_not_supported_and_fallback(
    hass, enable_custom_integrations
):
    session = _Session()

    # Cached SID attempt: status 404 => not supported.
    session.queue_get(_Resp(404, "{}"))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")
    coord._rest_sid = "abc"

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_no_login_success_returns_without_login(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login REST status probe succeeds
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_cached_sid_unauthorized_clears_sid_then_no_login_succeeds(
    hass, enable_custom_integrations
):
    session = _Session()

    # Cached SID attempt: status 401 -> unauthorized, should clear cached SID.
    session.queue_get(_Resp(401, "{}"))

    # Then no-login status probe succeeds.
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")
    coord._rest_sid = "abc"

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"
    assert coord._rest_sid is None


async def test_rest_non_transient_http_error_falls_back(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # Login returns non-transient error (400)
    session.queue_post(_Resp(400, "{}"))

    # Legacy CGI JSON success.
    session.queue_get(
        _Resp(
            200,
            '{"istat": {"hostname": "apex", "hardware": "Apex", "date": "now", "inputs": [], "outputs": []}}',
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "cgi_json"


async def test_rest_username_candidate_then_admin_is_tried(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))

    # First login candidate rejected; second succeeds.
    session.queue_post(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))

    # Status success.
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    # mconf 401 should be ignored (permission error).
    session.queue_get(_Resp(401, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4", username="user")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_rest_status_404_after_login_raises_update_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))

    # REST status 404 after login => triggers FileNotFoundError continue path
    session.queue_get(_Resp(404, "{}"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()


async def test_rest_mconf_invalid_json_is_logged_and_ignored(
    hass, enable_custom_integrations
):
    session = _Session()

    # no-login status probe first
    session.queue_get(_Resp(401, "{}"))
    session.queue_post(_Resp(200, "{}", cookies={"connect.sid": "abc"}))

    # Status payload (with cookie).
    session.queue_get(
        _Resp(
            200,
            '{"nstat": {}, "system": {"serial": "ABC"}, "inputs": [], "outputs": []}',
        )
    )

    # mconf invalid JSON should be ignored.
    session.queue_get(_Resp(200, "{no"))

    coord = await _make_coordinator(hass, host="1.2.3.4")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "rest"


async def test_legacy_json_invalid_body_logs_and_falls_back_to_xml(
    hass, enable_custom_integrations
):
    session = _Session()

    # no password: skip REST
    # legacy json 200 but invalid json
    session.queue_get(_Resp(200, "{no"))

    # xml success
    session.queue_get(
        _Resp(
            200,
            """<status software='1.0' hardware='Apex'><hostname>apex</hostname><serial>ABC</serial><timezone>UTC</timezone><date>now</date><probes></probes><outlets></outlets></status>""",
            headers={"Content-Type": "application/xml"},
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4", password="")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        data = await coord._async_update_data()

    assert data["meta"]["source"] == "xml"


async def test_legacy_xml_unauthorized_logs_and_raises_auth_failed(
    hass, enable_custom_integrations
):
    session = _Session()

    # no password: skip REST
    # legacy json 404 -> fall back to xml
    session.queue_get(_Resp(404, "{}"))
    # xml unauthorized
    session.queue_get(
        _Resp(401, "<status></status>", headers={"Content-Type": "application/xml"})
    )

    coord = await _make_coordinator(hass, host="1.2.3.4", password="")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()


async def test_legacy_xml_update_failed_reraises(hass, enable_custom_integrations):
    session = _Session()

    # no password: skip REST
    # legacy json 404 -> fall back to xml
    session.queue_get(_Resp(404, "{}"))
    session.queue_get(
        _Resp(
            200,
            """<status software='1.0' hardware='Apex'><hostname>apex</hostname><serial>ABC</serial><timezone>UTC</timezone><date>now</date><probes></probes><outlets></outlets></status>""",
            headers={"Content-Type": "application/xml"},
        )
    )

    coord = await _make_coordinator(hass, host="1.2.3.4", password="")

    with (
        patch(
            "custom_components.apex_fusion.coordinator.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.coordinator.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
        patch(
            "custom_components.apex_fusion.coordinator.parse_status_xml",
            side_effect=UpdateFailed("boom"),
        ),
    ):
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()

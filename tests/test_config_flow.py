"""Tests for the Apex Fusion config flow."""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, patch

from aiohttp import ClientSession
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.config_flow import InvalidAuth, _async_validate_input
from custom_components.apex_fusion.const import CONF_HOST, CONF_NO_LOGIN, DOMAIN


def test_normalize_host_variants():
    from custom_components.apex_fusion.config_flow import _normalize_host

    assert _normalize_host("") == ""
    assert _normalize_host(" 1.2.3.4 ") == "1.2.3.4"
    assert _normalize_host("http://1.2.3.4") == "1.2.3.4"
    assert _normalize_host("https://1.2.3.4/foo") == "1.2.3.4"


def test_config_flow_cookie_helpers_cover_exception_and_noop():
    from custom_components.apex_fusion import config_flow

    class _BadJar:
        def filter_cookies(self, *_args, **_kwargs):
            raise RuntimeError("boom")

        def update_cookies(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    class _Sess:
        cookie_jar = _BadJar()

    sess = cast(ClientSession, _Sess())
    assert config_flow._session_has_connect_sid(sess, "http://x") is False
    # Empty sid is a no-op.
    config_flow._set_connect_sid_cookie(sess, base_url="http://x", sid="")


def test_extract_serial_helpers_cover_branches():
    from custom_components.apex_fusion.config_flow import (
        _coerce_serial,
        _extract_hostname_from_status_obj,
        _extract_serial_from_status_obj,
    )

    assert _coerce_serial("  ABC ") == "ABC"
    assert _coerce_serial(123) == "123"
    assert _coerce_serial(None) is None

    assert _extract_serial_from_status_obj({"serial": "  S1  "}) == "S1"
    assert _extract_serial_from_status_obj({"system": {"serial": 999}}) == "999"
    assert _extract_serial_from_status_obj({"istat": {"serialNO": 888}}) == "888"

    nested = {"data": {"system": {"serial": "NEST"}}}
    assert _extract_serial_from_status_obj(nested) == "NEST"

    assert _extract_serial_from_status_obj({"data": "nope"}) is None
    assert _extract_serial_from_status_obj({"status": {}}) is None

    assert _extract_hostname_from_status_obj({"hostname": "  200XL  "}) == "200XL"
    assert _extract_hostname_from_status_obj({"system": {"hostname": "SYS"}}) == "SYS"
    assert _extract_hostname_from_status_obj({"nstat": {"hostname": "NST"}}) == "NST"
    assert _extract_hostname_from_status_obj({"istat": {"hostname": "IST"}}) == "IST"
    assert (
        _extract_hostname_from_status_obj({"data": {"system": {"hostname": "NEST"}}})
        == "NEST"
    )
    assert _extract_hostname_from_status_obj({"data": "nope"}) is None


async def test_rest_validation_uses_hostname_from_config_when_missing_in_status(
    hass, aioclient_mock
):
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=200,
        text="{}",
    )
    aioclient_mock.get(
        f"http://{host}/rest/config",
        status=200,
        text='{"nconf": {"hostname": "200XL"}}',
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )

    assert info["title"] == "200XL (1.2.3.4)"


async def test_user_flow_creates_entry(hass, enable_custom_integrations):
    """User flow creates a config entry when validation succeeds.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """
    with patch(
        "custom_components.apex_fusion.config_flow._async_validate_input",
        new=AsyncMock(return_value={"title": "Apex (1.2.3.4)", "unique_id": "1.2.3.4"}),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "user"},
            data={
                CONF_HOST: "1.2.3.4",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["title"] == "Apex (1.2.3.4)"
    assert result["data"][CONF_HOST] == "1.2.3.4"


async def test_reauth_flow_is_supported_and_updates_entry(
    hass, enable_custom_integrations
):
    """Reauth flow exists and updates stored credentials.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Apex (1.2.3.4)",
        data={
            CONF_HOST: "1.2.3.4",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "old",
        },
        unique_id="1.2.3.4",
    )
    entry.add_to_hass(hass)

    # Start reauth flow.
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "reauth", "entry_id": entry.entry_id},
        data={"entry_id": entry.entry_id},
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    with patch(
        "custom_components.apex_fusion.config_flow._async_validate_input",
        new=AsyncMock(return_value={"title": "Apex (1.2.3.4)", "unique_id": "1.2.3.4"}),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "new",
            },
        )

    assert result2["type"] == FlowResultType.ABORT
    assert result2["reason"] == "reauth_successful"

    updated = hass.config_entries.async_get_entry(entry.entry_id)
    assert updated is not None
    assert updated.data[CONF_PASSWORD] == "new"


async def test_reconfigure_flow_is_supported_and_updates_entry(
    hass, enable_custom_integrations
):
    """Reconfigure flow exists and updates stored host/credentials.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Apex (1.2.3.4)",
        data={
            CONF_HOST: "1.2.3.4",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "old",
        },
        unique_id="1.2.3.4",
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "reconfigure", "entry_id": entry.entry_id},
        data=None,
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reconfigure_confirm"

    with patch(
        "custom_components.apex_fusion.config_flow._async_validate_input",
        new=AsyncMock(
            return_value={"title": "Apex (apex.local)", "unique_id": "1.2.3.4"}
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_HOST: "apex.local",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "new",
            },
        )

    assert result2["type"] == FlowResultType.ABORT
    assert result2["reason"] == "reconfigure_successful"

    updated = hass.config_entries.async_get_entry(entry.entry_id)
    assert updated is not None
    assert updated.data[CONF_HOST] == "apex.local"
    assert updated.data[CONF_PASSWORD] == "new"


async def test_rest_validation_accepts_cookie_from_set_cookie(hass, aioclient_mock):
    """REST validation sends connect.sid from Set-Cookie.

    Args:
        hass: Home Assistant fixture.
        aioclient_mock: Aiohttp client mock fixture.

    Returns:
        None.
    """
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=200,
        text="{}",
    )

    await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )

    get_calls = [
        call
        for call in aioclient_mock.mock_calls
        if str(call[0]).lower() == "get"
        and str(call[1]) == f"http://{host}/rest/status"
    ]
    assert get_calls
    _method, _url, _data, headers = get_calls[-1]
    assert (headers or {}).get("Cookie") == "connect.sid=abc"


async def test_rest_validation_accepts_cookie_from_json_body(hass, aioclient_mock):
    """REST validation sends connect.sid from JSON body.

    Args:
        hass: Home Assistant fixture.
        aioclient_mock: Aiohttp client mock fixture.

    Returns:
        None.
    """
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text='{"connect.sid": "abc"}',
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=200,
        text="{}",
    )

    await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )

    get_calls = [
        call
        for call in aioclient_mock.mock_calls
        if str(call[0]).lower() == "get"
        and str(call[1]) == f"http://{host}/rest/status"
    ]
    assert get_calls
    _method, _url, _data, headers = get_calls[-1]
    assert (headers or {}).get("Cookie") == "connect.sid=abc"


async def test_rest_validation_401_raises_invalid_auth(hass, aioclient_mock):
    """REST validation raises InvalidAuth when login is unauthorized.

    Args:
        hass: Home Assistant fixture.
        aioclient_mock: Aiohttp client mock fixture.

    Returns:
        None.

    Raises:
        AssertionError: If InvalidAuth is not raised.
    """
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=401,
        text="{}",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_rest_validation_includes_admin_candidate_when_username_not_admin(
    hass, aioclient_mock
):
    """Cover adding the implicit admin login candidate.

    The config flow always appends "admin" as a fallback login user when the
    provided username isn't already "admin".
    """

    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=401,
        text="{}",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "not-admin",
                CONF_PASSWORD: "pw",
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_rest_validation_reraises_invalid_auth_from_rest_block(
    hass, aioclient_mock
):
    """Cover the defensive InvalidAuth re-raise inside REST validation.

    Args:
        hass: Home Assistant fixture.
        aioclient_mock: Aiohttp client mock fixture.

    Returns:
        None.

    Raises:
        AssertionError: If InvalidAuth is not raised.
    """

    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=200,
        text="{}",
    )

    def _boom(*_args, **_kwargs):
        raise InvalidAuth

    with patch(
        "custom_components.apex_fusion.config_flow._session_has_connect_sid",
        new=_boom,
    ):
        try:
            await _async_validate_input(
                hass,
                {
                    CONF_HOST: host,
                    CONF_USERNAME: "admin",
                    CONF_PASSWORD: "pw",
                },
            )
        except InvalidAuth:
            pass
        else:
            raise AssertionError("Expected InvalidAuth")


async def test_xml_validation_success_when_no_password(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=404,
        text="",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "",  # no REST
        },
    )

    assert info["unique_id"] == host


async def test_cgi_json_unauthorized_raises_invalid_auth(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=401,
        text="{}",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "",
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_cgi_json_invalid_json_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=200,
        text="not-json",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "",
        },
    )

    assert info["unique_id"] == host


async def test_xml_validation_unauthorized_raises_invalid_auth(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=404,
        text="",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=401,
        text="<status></status>",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "",  # no REST
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_xml_validation_parse_error_raises_cannot_connect(hass, aioclient_mock):
    from custom_components.apex_fusion.config_flow import CannotConnect

    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=404,
        text="",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<bad",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "",
            },
        )
    except CannotConnect:
        pass
    else:
        raise AssertionError("Expected CannotConnect")


async def test_rest_login_rejected_for_all_candidates_raises_invalid_auth(
    hass, aioclient_mock
):
    """Cover the logged_in=False path when all REST login candidates reject.

    Args:
        hass: Home Assistant fixture.
        aioclient_mock: Aiohttp client mock fixture.

    Returns:
        None.
    """

    host = "1.2.3.4"
    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=401,
        text="{}",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_no_login_ignores_credentials_and_uses_xml(hass, aioclient_mock):
    host = "1.2.3.4"
    # In no-login mode we should not attempt REST at all.
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=404,
        text="",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status><serial>S1</serial><hostname>Tank</hostname></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_NO_LOGIN: True,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "wrong",
        },
    )

    assert info["unique_id"] == "S1"
    assert info["title"] == "Tank (1.2.3.4)"


async def test_cgi_json_validation_success_when_no_password(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.json",
        status=200,
        text='{"system": {"serial": "SER", "hostname": "200XL"}}',
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "",
        },
    )

    assert info["unique_id"] == "SER"
    assert info["title"] == "200XL (1.2.3.4)"


async def test_rest_status_404_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    # Correct REST status endpoint returns 404 -> treated as not supported.
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=404,
        text="",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )
    assert info["unique_id"] == host


async def test_rest_status_invalid_json_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"

    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=200,
        text="not-json",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )
    assert info["unique_id"] == host


async def test_rest_404_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=404,
        text="{}",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )
    assert info["unique_id"] == host


async def test_rest_transient_failure_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=503,
        text="{}",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )
    assert info["unique_id"] == host


async def test_rest_status_unauthorized_raises_invalid_auth(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=401,
        text="{}",
    )

    try:
        await _async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )
    except InvalidAuth:
        pass
    else:
        raise AssertionError("Expected InvalidAuth")


async def test_rest_status_transient_falls_back_to_xml(hass, aioclient_mock):
    host = "1.2.3.4"
    aioclient_mock.post(
        f"http://{host}/rest/login",
        status=200,
        text="{}",
        cookies={"connect.sid": "abc"},
    )
    aioclient_mock.get(
        f"http://{host}/rest/status",
        status=503,
        text="{}",
    )
    aioclient_mock.get(
        f"http://{host}/cgi-bin/status.xml",
        status=200,
        text="<status></status>",
    )

    info = await _async_validate_input(
        hass,
        {
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "pw",
        },
    )
    assert info["unique_id"] == host


async def test_rest_retries_on_client_error_then_succeeds(
    hass, enable_custom_integrations
):
    """Cover the retry/sleep path in REST validation.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """

    import aiohttp

    from custom_components.apex_fusion import config_flow

    class _NullTimeout:
        async def __aenter__(self):
            return None

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Resp:
        def __init__(
            self, status: int, body: str, cookies: dict[str, str] | None = None
        ):
            self.status = status
            self._body = body
            self.headers = {"Content-Type": "application/json"}

            class _M:
                def __init__(self, v: str):
                    self.value = v

            self.cookies = {}
            for k, v in (cookies or {}).items():
                self.cookies[k] = _M(v)

        async def text(self) -> str:
            return self._body

        def raise_for_status(self) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Jar:
        def filter_cookies(self, *_args, **_kwargs):
            return {}

        def update_cookies(self, *_args, **_kwargs):
            return None

    class _Sess:
        def __init__(self):
            self.cookie_jar = _Jar()
            self._attempt = 0

        def post(self, *_args, **_kwargs):
            self._attempt += 1
            if self._attempt == 1:
                raise aiohttp.ClientError("boom")
            return _Resp(200, "{}", cookies={"connect.sid": "abc"})

        def get(self, *_args, **_kwargs):
            return _Resp(200, "{}")

    async def _no_sleep(_secs: float):
        return None

    host = "1.2.3.4"
    session = _Sess()
    with (
        patch(
            "custom_components.apex_fusion.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.config_flow.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
        patch("custom_components.apex_fusion.config_flow.asyncio.sleep", new=_no_sleep),
    ):
        info = await config_flow._async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )

    assert info["unique_id"] == host


async def test_rest_login_body_invalid_json_is_ignored(
    hass, enable_custom_integrations
):
    """Cover the login_body JSONDecodeError branch when no cookie is set.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """

    from custom_components.apex_fusion import config_flow

    class _NullTimeout:
        async def __aenter__(self):
            return None

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Resp:
        def __init__(self, status: int, body: str):
            self.status = status
            self._body = body
            self.headers = {"Content-Type": "application/json"}
            self.cookies = {}

        async def text(self) -> str:
            return self._body

        def raise_for_status(self) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Jar:
        def filter_cookies(self, *_args, **_kwargs):
            return {}

        def update_cookies(self, *_args, **_kwargs):
            return None

    class _Sess:
        def __init__(self):
            self.cookie_jar = _Jar()

        def post(self, *_args, **_kwargs):
            return _Resp(200, "not-json")

        def get(self, *_args, **_kwargs):
            return _Resp(200, "{}")

    host = "1.2.3.4"
    session = _Sess()
    with (
        patch(
            "custom_components.apex_fusion.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.config_flow.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
    ):
        info = await config_flow._async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )

    assert info["unique_id"] == host


async def test_rest_exhausts_retry_loop_then_falls_back_to_xml(
    hass, enable_custom_integrations
):
    """Cover raising CannotConnect after exhausting REST retry attempts.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """

    import aiohttp

    from custom_components.apex_fusion import config_flow

    class _NullTimeout:
        async def __aenter__(self):
            return None

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Resp:
        def __init__(self, status: int, body: str):
            self.status = status
            self._body = body
            self.headers = {"Content-Type": "application/xml"}
            self.cookies = {}

        async def text(self) -> str:
            return self._body

        def raise_for_status(self) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Jar:
        def filter_cookies(self, *_args, **_kwargs):
            return {}

        def update_cookies(self, *_args, **_kwargs):
            return None

    class _Sess:
        def __init__(self):
            self.cookie_jar = _Jar()
            self._calls = 0

        def post(self, *_args, **_kwargs):
            self._calls += 1
            raise aiohttp.ClientError("boom")

        def get(self, *_args, **_kwargs):
            # Called for XML fallback.
            return _Resp(200, "<status></status>")

    async def _no_sleep(_secs: float):
        return None

    host = "1.2.3.4"
    session = _Sess()
    with (
        patch(
            "custom_components.apex_fusion.config_flow.async_get_clientsession",
            return_value=session,
        ),
        patch(
            "custom_components.apex_fusion.config_flow.async_timeout.timeout",
            return_value=_NullTimeout(),
        ),
        patch("custom_components.apex_fusion.config_flow.asyncio.sleep", new=_no_sleep),
    ):
        info = await config_flow._async_validate_input(
            hass,
            {
                CONF_HOST: host,
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pw",
            },
        )

    assert session._calls >= 2
    assert info["unique_id"] == host


async def test_flow_user_step_maps_errors(hass, enable_custom_integrations):
    from custom_components.apex_fusion.config_flow import CannotConnect

    with patch(
        "custom_components.apex_fusion.config_flow._async_validate_input",
        new=AsyncMock(side_effect=CannotConnect),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "user"},
            data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        )

    assert result["type"] == FlowResultType.FORM
    assert result["errors"]["base"] == "cannot_connect"


async def test_reauth_confirm_aborts_when_missing_context(
    hass, enable_custom_integrations
):
    from custom_components.apex_fusion.config_flow import ConfigFlow

    flow = ConfigFlow()
    flow.hass = hass

    result = await flow.async_step_reauth_confirm()
    assert result.get("type") == FlowResultType.ABORT
    assert result.get("reason") == "unknown"


async def test_reauth_confirm_aborts_when_entry_missing(
    hass, enable_custom_integrations
):
    from custom_components.apex_fusion.config_flow import ConfigFlow

    flow = ConfigFlow()
    flow.hass = hass
    flow._apex_reauth_entry_id = "missing"

    result = await flow.async_step_reauth_confirm()
    assert result.get("type") == FlowResultType.ABORT
    assert result.get("reason") == "unknown"

"""Config flow for Apex Fusion (Local)."""

from __future__ import annotations

import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from http import HTTPStatus
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp
import async_timeout
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from yarl import URL

from .const import (
    CONF_HOST,
    DEFAULT_PASSWORD,
    DEFAULT_STATUS_PATH,
    DEFAULT_USERNAME,
    DOMAIN,
    LOGGER_NAME,
)
from .coordinator import build_base_url, build_status_url

_LOGGER = logging.getLogger(LOGGER_NAME)


_TRANSIENT_HTTP_STATUSES: set[int] = {
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.TOO_MANY_REQUESTS,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
}


def _is_transient_http_status(status: int) -> bool:
    return status in _TRANSIENT_HTTP_STATUSES


def _session_has_connect_sid(session: aiohttp.ClientSession, base_url: str) -> bool:
    try:
        cookies = session.cookie_jar.filter_cookies(URL(base_url))
        return "connect.sid" in cookies
    except Exception:
        return False


def _set_connect_sid_cookie(
    session: aiohttp.ClientSession, *, base_url: str, sid: str
) -> None:
    if not sid:
        return
    session.cookie_jar.update_cookies({"connect.sid": sid}, response_url=URL(base_url))


STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_USERNAME, default=DEFAULT_USERNAME): str,
        vol.Optional(CONF_PASSWORD, default=DEFAULT_PASSWORD): str,
    }
)


STEP_REAUTH_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_USERNAME, default=DEFAULT_USERNAME): str,
        vol.Optional(CONF_PASSWORD, default=DEFAULT_PASSWORD): str,
    }
)


def _step_reconfigure_schema(existing: dict[str, Any]) -> vol.Schema:
    """Build the reconfigure schema with sensible defaults."""
    host_default = _normalize_host(str(existing.get(CONF_HOST, "")))
    username_default = str(
        existing.get(CONF_USERNAME, DEFAULT_USERNAME) or DEFAULT_USERNAME
    )

    # Password has no default so leaving it blank won't overwrite an existing one.
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=host_default): str,
            vol.Optional(CONF_USERNAME, default=username_default): str,
            vol.Optional(CONF_PASSWORD): str,
        }
    )


def _extract_hostname_from_status_obj(status_obj: dict[str, Any]) -> str | None:
    """Best-effort hostname extraction from various REST status JSON shapes."""

    def _coerce(v: Any) -> str | None:
        if isinstance(v, str) and v.strip():
            return v.strip()
        return None

    def _maybe_from_dict(d: dict[str, Any]) -> str | None:
        for k in ("hostname", "hostName", "host_name"):
            s = _coerce(d.get(k))
            if s:
                return s

        system_any: Any = d.get("system")
        if isinstance(system_any, dict):
            s = _coerce(cast(dict[str, Any], system_any).get("hostname"))
            if s:
                return s

        nstat_any: Any = d.get("nstat")
        if isinstance(nstat_any, dict):
            s = _coerce(cast(dict[str, Any], nstat_any).get("hostname"))
            if s:
                return s

        istat_any: Any = d.get("istat")
        if isinstance(istat_any, dict):
            s = _coerce(cast(dict[str, Any], istat_any).get("hostname"))
            if s:
                return s

        return None

    s = _maybe_from_dict(status_obj)
    if s:
        return s

    for container_key in ("data", "status", "result", "systat"):
        container_any: Any = status_obj.get(container_key)
        if isinstance(container_any, dict):
            s = _maybe_from_dict(cast(dict[str, Any], container_any))
            if s:
                return s

    return None


def _normalize_host(host: str) -> str:
    """Normalize a host field to a hostname/IP.

    Users sometimes paste URLs (e.g., http://10.0.0.5). This integration stores
    only the host portion and assumes http.

    Args:
        host: Raw host input.

    Returns:
        Hostname/IP without scheme/path.
    """
    raw = (host or "").strip()
    if not raw:
        return raw

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        return (parsed.hostname or parsed.netloc or raw).strip()

    # If someone typed a bare URL-ish value without scheme, keep as-is.
    return raw


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


def _coerce_serial(candidate: Any) -> str | None:
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()
    if isinstance(candidate, int):
        return str(candidate)
    return None


def _extract_serial_from_status_obj(status_obj: dict[str, Any]) -> str | None:
    """Best-effort serial extraction from various status JSON shapes."""

    def _maybe_from_dict(d: dict[str, Any]) -> str | None:
        for k in ("serial", "serialNo", "serialNO", "serial_number"):
            s = _coerce_serial(d.get(k))
            if s:
                return s
        system_any: Any = d.get("system")
        if isinstance(system_any, dict):
            s = _coerce_serial(cast(dict[str, Any], system_any).get("serial"))
            if s:
                return s
        istat_any: Any = d.get("istat")
        if isinstance(istat_any, dict):
            istat = cast(dict[str, Any], istat_any)
            for k in ("serial", "serialNo", "serialNO", "serial_number"):
                s = _coerce_serial(istat.get(k))
                if s:
                    return s
        return None

    # Direct fields.
    s = _maybe_from_dict(status_obj)
    if s:
        return s

    # Common nesting patterns.
    for container_key in ("data", "status", "result", "systat"):
        container_any: Any = status_obj.get(container_key)
        if isinstance(container_any, dict):
            s = _maybe_from_dict(cast(dict[str, Any], container_any))
            if s:
                return s

    return None


async def _async_validate_input(
    hass: HomeAssistant, data: dict[str, Any]
) -> dict[str, str]:
    """Validate user input.

    Tries REST first (if a password is provided), then falls back to
    legacy status.xml.

    Args:
        hass: Home Assistant instance.
        data: User-provided config data.

    Returns:
        A dict containing a display title and unique_id.

    Raises:
        CannotConnect: If the device cannot be reached.
        InvalidAuth: If authentication fails.
    """
    host = _normalize_host(str(data[CONF_HOST]))
    username = str(data.get(CONF_USERNAME, DEFAULT_USERNAME) or DEFAULT_USERNAME)
    password = str(data.get(CONF_PASSWORD, DEFAULT_PASSWORD) or "")
    status_path = DEFAULT_STATUS_PATH

    _LOGGER.debug(
        "Validating Apex connection host=%s user=%s has_password=%s",
        host,
        username,
        bool(password),
    )

    base_url = build_base_url(host)
    url = build_status_url(host, status_path)
    session = async_get_clientsession(hass)

    auth: aiohttp.BasicAuth | None = None
    if password:
        auth = aiohttp.BasicAuth(username or "admin", password)

    # Prefer REST if present; fall back to XML.
    rest_invalid_auth = False

    if password:
        try:
            login_url = f"{base_url}/rest/login"
            accept_headers = {"Accept": "*/*", "Content-Type": "application/json"}

            max_attempts = 2
            for attempt in range(1, max_attempts + 1):
                _LOGGER.debug(
                    "REST validation attempt %s/%s host=%s user=%s",
                    attempt,
                    max_attempts,
                    host,
                    username,
                )

                try:
                    login_cookie_sid = ""
                    login_body = ""

                    # Try the provided username first.
                    # If that fails, fall back to the default "admin" account
                    # (common on Apex controllers) to keep setup easy.
                    login_candidates: list[str] = []
                    if username:
                        login_candidates.append(username)
                    if "admin" not in login_candidates:
                        login_candidates.append("admin")

                    logged_in = False
                    for login_user in login_candidates:
                        async with async_timeout.timeout(10):
                            async with session.post(
                                login_url,
                                json={
                                    "login": login_user,
                                    "password": password,
                                    "remember_me": False,
                                },
                                headers=accept_headers,
                            ) as resp:
                                _LOGGER.debug(
                                    "REST login HTTP %s content_type=%s",
                                    resp.status,
                                    resp.headers.get("Content-Type"),
                                )
                                if resp.status == 404:
                                    raise KeyError("rest_not_supported")
                                if resp.status in (401, 403):
                                    _LOGGER.debug(
                                        "REST login rejected for user=%s; trying next candidate",
                                        login_user,
                                    )
                                    continue
                                if _is_transient_http_status(resp.status):
                                    raise CannotConnect
                                resp.raise_for_status()
                                login_body = await resp.text()

                                morsel = resp.cookies.get("connect.sid")
                                if morsel is not None and morsel.value:
                                    login_cookie_sid = morsel.value
                                logged_in = True
                                break

                    if not logged_in:
                        # Some devices/users may not permit REST login but still
                        # allow legacy status.xml BasicAuth access.
                        rest_invalid_auth = True
                        raise CannotConnect

                    sid_set = False
                    sid_value = ""
                    if login_cookie_sid:
                        _set_connect_sid_cookie(
                            session, base_url=base_url, sid=login_cookie_sid
                        )
                        sid_set = True
                        sid_value = login_cookie_sid

                    sid_set = sid_set or _session_has_connect_sid(session, base_url)
                    if not sid_set and login_body:
                        try:
                            login_any: Any = json.loads(login_body)
                            if isinstance(login_any, dict):
                                sid_any: Any = cast(dict[str, Any], login_any).get(
                                    "connect.sid"
                                )
                                if isinstance(sid_any, str) and sid_any:
                                    _set_connect_sid_cookie(
                                        session, base_url=base_url, sid=sid_any
                                    )
                                    sid_set = True
                                    sid_value = sid_any
                        except json.JSONDecodeError:
                            pass

                    _LOGGER.debug(
                        "REST login session established=%s (will_send_cookie_header=%s)",
                        sid_set,
                        bool(sid_value),
                    )

                    request_headers = dict(accept_headers)
                    if sid_value:
                        request_headers["Cookie"] = f"connect.sid={sid_value}"

                    status_urls = [
                        f"{base_url}/rest/status",
                    ]

                    status_text = ""
                    status_ok = False
                    for status_url in status_urls:
                        async with async_timeout.timeout(10):
                            async with session.get(
                                status_url, headers=request_headers
                            ) as resp:
                                _LOGGER.debug(
                                    "REST status HTTP %s content_type=%s has_connect_sid=%s",
                                    resp.status,
                                    resp.headers.get("Content-Type"),
                                    _session_has_connect_sid(session, base_url),
                                )
                                if resp.status == 404:
                                    continue
                                if resp.status in (401, 403):
                                    rest_invalid_auth = True
                                    raise CannotConnect
                                if _is_transient_http_status(resp.status):
                                    raise CannotConnect
                                resp.raise_for_status()
                                status_text = await resp.text()
                                status_ok = True
                                break

                    if not status_ok:
                        raise KeyError("rest_not_supported")

                    # Ensure it's JSON.
                    status_any: Any = json.loads(status_text) if status_text else {}
                    status_obj: dict[str, Any] = (
                        cast(dict[str, Any], status_any)
                        if isinstance(status_any, dict)
                        else {}
                    )
                    serial = _extract_serial_from_status_obj(status_obj)

                    # Prefer the controller-reported hostname for tank naming.
                    hostname = _extract_hostname_from_status_obj(status_obj)
                    if not hostname:
                        try:
                            async with async_timeout.timeout(10):
                                async with session.get(
                                    f"{base_url}/rest/config", headers=request_headers
                                ) as resp:
                                    if resp.status == 200:
                                        config_text = await resp.text()
                                        config_any: Any = (
                                            json.loads(config_text)
                                            if config_text
                                            else {}
                                        )
                                        if isinstance(config_any, dict):
                                            nconf_any: Any = cast(
                                                dict[str, Any], config_any
                                            ).get("nconf")
                                            if isinstance(nconf_any, dict):
                                                hostname = (
                                                    str(
                                                        cast(
                                                            dict[str, Any], nconf_any
                                                        ).get("hostname")
                                                        or ""
                                                    ).strip()
                                                    or None
                                                )
                        except Exception:  # noqa: BLE001
                            hostname = hostname
                    title = f"{hostname} ({host})" if hostname else f"Apex ({host})"
                    return {"title": title, "unique_id": serial or host}

                except (asyncio.TimeoutError, aiohttp.ClientError) as err:
                    _LOGGER.debug("Transient REST validation error: %s", err)
                    if attempt < max_attempts:
                        await asyncio.sleep(0.5 * attempt)

            raise CannotConnect

        except KeyError:
            # No REST, try XML.
            _LOGGER.debug("REST not supported; falling back to status.xml")
            pass
        except InvalidAuth:
            # Reserved for legacy XML auth failures below.
            raise
        except (CannotConnect, json.JSONDecodeError) as err:
            # REST flaky? Try XML before failing.
            _LOGGER.debug("REST validation failed; trying status.xml: %s", err)

    try:
        _LOGGER.debug("Trying legacy XML validation: %s", url)
        async with async_timeout.timeout(10):
            async with session.get(url, auth=auth) as resp:
                _LOGGER.debug("XML status HTTP %s", resp.status)
                if resp.status in (401, 403):
                    raise InvalidAuth
                resp.raise_for_status()
                body = await resp.text()

        root = ET.fromstring(body)
        serial = (root.findtext("./serial") or "").strip() or None
        hostname = (root.findtext("./hostname") or "").strip() or None

    except InvalidAuth:
        if rest_invalid_auth:
            _LOGGER.debug(
                "REST login rejected and legacy XML auth failed host=%s user=%s",
                host,
                username,
            )
        raise
    except (asyncio.TimeoutError, aiohttp.ClientError, ET.ParseError) as err:
        raise CannotConnect from err

    title = f"{hostname} ({host})" if hostname else f"Apex ({host})"
    return {"title": title, "unique_id": serial or host}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Apex Fusion."""

    VERSION = 1
    reconfigure_supported = True

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step.

        Args:
            user_input: User-provided input, if any.

        Returns:
            A Home Assistant flow result.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            normalized_input = dict(user_input)

            normalized_input[CONF_HOST] = _normalize_host(
                str(normalized_input.get(CONF_HOST, ""))
            )

            try:
                info = await _async_validate_input(self.hass, normalized_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(info["unique_id"])

                # If this controller is already configured, treat running the flow
                # again as a "re-login": update credentials/host and reload.
                existing = next(
                    (
                        e
                        for e in self._async_current_entries()
                        if str(e.unique_id or "") == info["unique_id"]
                    ),
                    None,
                )
                if existing is not None:
                    merged = dict(existing.data)
                    merged.update(normalized_input)

                    self.hass.config_entries.async_update_entry(
                        existing, data=merged, title=info["title"]
                    )
                    self.hass.config_entries.async_schedule_reload(existing.entry_id)
                    return self.async_abort(reason="already_configured")

                return self.async_create_entry(
                    title=info["title"],
                    data=normalized_input,
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_reauth(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        """Handle config entry re-authentication.

        Args:
            user_input: Context from Home Assistant, including `entry_id`.

        Returns:
            A Home Assistant flow result.
        """
        # NOTE: Home Assistant reserves `_reauth_entry_id` on ConfigFlow.
        self._apex_reauth_entry_id = str(user_input.get("entry_id") or "") or None
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Prompt for updated credentials.

        Args:
            user_input: Updated credentials, if submitted.

        Returns:
            A Home Assistant flow result.
        """
        entry_id = getattr(self, "_apex_reauth_entry_id", None)
        if not entry_id:
            return self.async_abort(reason="unknown")

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None:
            return self.async_abort(reason="unknown")

        errors: dict[str, str] = {}

        if user_input is not None:
            merged: dict[str, Any] = dict(entry.data)
            merged.update(user_input)
            try:
                await _async_validate_input(self.hass, merged)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected exception during reauth")
                errors["base"] = "unknown"
            else:
                self.hass.config_entries.async_update_entry(entry, data=merged)
                self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_SCHEMA,
            errors=errors,
            description_placeholders={CONF_HOST: str(entry.data.get(CONF_HOST, ""))},
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle config entry reconfiguration.

        Home Assistant will show a "Reconfigure" button for integrations that
        support it.
        """

        # Home Assistant may call this step with `user_input=None`.
        entry_id = None
        if isinstance(user_input, dict):
            entry_id = user_input.get("entry_id")
        if not entry_id:
            entry_id = (self.context or {}).get("entry_id")

        self._apex_reconfigure_entry_id = str(entry_id or "") or None
        return await self.async_step_reconfigure_confirm()

    async def async_step_reconfigure_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Prompt for updated host/credentials and reload the entry."""

        entry_id = getattr(self, "_apex_reconfigure_entry_id", None)
        if not entry_id:
            return self.async_abort(reason="unknown")

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None:
            return self.async_abort(reason="unknown")

        errors: dict[str, str] = {}

        if user_input is not None:
            merged: dict[str, Any] = dict(entry.data)
            merged.update(user_input)

            # If the user leaves password empty/omitted, keep the existing one.
            # The HA frontend commonly submits empty strings for optional fields.
            pw_any: Any = user_input.get(CONF_PASSWORD)
            if CONF_PASSWORD not in user_input or (
                isinstance(pw_any, str) and not pw_any.strip()
            ):
                merged[CONF_PASSWORD] = entry.data.get(CONF_PASSWORD, DEFAULT_PASSWORD)

            try:
                info = await _async_validate_input(self.hass, merged)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected exception during reconfigure")
                errors["base"] = "unknown"
            else:
                # Prevent accidentally repointing an existing entry that already
                # has a stable unique_id (serial) to a different controller.
                old_host = _normalize_host(str(entry.data.get(CONF_HOST, "")))
                entry_uid = str(entry.unique_id or "")
                if (
                    entry_uid
                    and entry_uid != old_host
                    and info["unique_id"] != entry_uid
                ):
                    return self.async_abort(reason="different_device")

                # If we learned a better unique_id (serial), apply it unless it
                # would collide with an existing entry.
                if info["unique_id"] and info["unique_id"] != entry.unique_id:
                    if any(
                        e.entry_id != entry.entry_id
                        and str(e.unique_id or "") == info["unique_id"]
                        for e in self.hass.config_entries.async_entries(DOMAIN)
                    ):
                        return self.async_abort(reason="already_configured")
                    self.hass.config_entries.async_update_entry(
                        entry, unique_id=info["unique_id"]
                    )

                self.hass.config_entries.async_update_entry(
                    entry, data=merged, title=info["title"]
                )
                self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure_confirm",
            data_schema=_step_reconfigure_schema(dict(entry.data)),
            errors=errors,
            description_placeholders={CONF_HOST: str(entry.data.get(CONF_HOST, ""))},
        )

"""The Apex Fusion (Local) integration.

This integration communicates with Neptune Apex controllers over the local
network.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import (
    CONF_HOST,
    CONF_LAST_CONTROL_ENABLED,
    CONF_LAST_SOURCE,
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    DOMAIN,
    LOGGER_NAME,
    PLATFORMS,
)
from .coordinator import ApexNeptuneDataUpdateCoordinator

_LOGGER = logging.getLogger(LOGGER_NAME)

_DOMAIN_LOADED_PLATFORMS_KEY = "_loaded_platforms"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Apex Fusion from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.

    Returns:
        True if setup succeeds.
    """
    # If config-flow validation established a REST session cookie, reuse it for
    # the coordinator's first refresh to avoid back-to-back logins.
    host = str(entry.data.get(CONF_HOST, "") or "")
    rest_sid: str | None = None
    try:
        domain_data_any: Any = hass.data.get(DOMAIN)
        domain_data = (
            cast(dict[str, Any], domain_data_any)
            if isinstance(domain_data_any, dict)
            else {}
        )
        sid_cache_any: Any = domain_data.get("_rest_sid_by_host")
        sid_cache = (
            cast(dict[str, Any], sid_cache_any)
            if isinstance(sid_cache_any, dict)
            else {}
        )
        rest_sid_any: Any = sid_cache.pop(host, None)
        if isinstance(rest_sid_any, str) and rest_sid_any:
            rest_sid = rest_sid_any
    except Exception:  # noqa: BLE001
        rest_sid = None

    coordinator = ApexNeptuneDataUpdateCoordinator(
        hass,
        entry=entry,
        rest_sid_seed=rest_sid,
    )
    await coordinator.async_config_entry_first_refresh()

    # Detect REST-vs-legacy mode based on the first successful refresh.
    data: dict[str, Any] = coordinator.data or {}
    meta_any: Any = data.get("meta")
    meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
    source = str(meta.get("source") or "").strip().lower() or None

    prev_source = (
        str(entry.data.get(CONF_LAST_SOURCE, "") or "").strip().lower() or None
    )

    read_only = (
        bool(entry.data.get(CONF_NO_LOGIN, False))
        or not str(entry.data.get(CONF_PASSWORD, "") or "").strip()
    )

    rest_active = source == "rest"
    control_enabled = rest_active and not read_only
    prev_control_any: Any = entry.data.get(CONF_LAST_CONTROL_ENABLED)
    prev_control_enabled = (
        prev_control_any if isinstance(prev_control_any, bool) else None
    )

    async def _async_purge_registry_entries() -> None:
        """Remove stale entities/devices for this config entry.

        This is intentionally blunt: when swapping between REST and legacy data
        sources, entity unique_ids (and device grouping) can change significantly.
        Removing registry entries avoids confusing duplicates.
        """

        try:
            from homeassistant.helpers import (
                device_registry as dr,
                entity_registry as er,
            )

            ent_reg = er.async_get(hass)
            reg_entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
            for reg_entry in reg_entries:
                ent_reg.async_remove(reg_entry.entity_id)

            dev_reg = dr.async_get(hass)
            dev_entries = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
            for dev_entry in dev_entries:
                dev_reg.async_remove_device(dev_entry.id)
        except Exception:  # noqa: BLE001
            _LOGGER.exception(
                "Failed to purge entity/device registry for entry_id=%s", entry.entry_id
            )

    purge_reason: str | None = None
    if prev_source and source and prev_source != source:
        purge_reason = f"source {prev_source} -> {source}"
    elif prev_control_enabled is not None and prev_control_enabled != control_enabled:
        purge_reason = f"control {prev_control_enabled} -> {control_enabled}"

    if purge_reason:
        _LOGGER.info(
            "Apex setup mode changed for entry_id=%s (%s); purging stale registry entries",
            entry.entry_id,
            purge_reason,
        )
        await _async_purge_registry_entries()

    if source and (source != prev_source or prev_control_enabled != control_enabled):
        new_data = dict(entry.data)
        if source != prev_source:
            new_data[CONF_LAST_SOURCE] = source
        new_data[CONF_LAST_CONTROL_ENABLED] = control_enabled
        hass.config_entries.async_update_entry(entry, data=new_data)

    # Prefer the controller-reported hostname as the tank name.
    host = str(entry.data.get(CONF_HOST, ""))
    hostname = str(meta.get("hostname") or "").strip() or None
    if not hostname:
        config_any: Any = data.get("config")
        if isinstance(config_any, dict):
            nconf_any: Any = cast(dict[str, Any], config_any).get("nconf")
            if isinstance(nconf_any, dict):
                hostname = (
                    str(cast(dict[str, Any], nconf_any).get("hostname") or "").strip()
                    or None
                )

    desired_title = (
        f"{hostname} ({host})"
        if hostname
        else str(entry.title or "").strip() or f"Apex ({host})"
    )
    if desired_title and str(entry.title or "") != desired_title:
        hass.config_entries.async_update_entry(entry, title=desired_title)

    # Prefer controller serial as a stable, non-IP unique_id.
    # This prevents duplicate entries (and entity collisions) when the same
    # controller is added under different hostnames/IPs.
    serial: str | None = str(meta.get("serial") or "").strip() or None

    if serial and entry.unique_id != serial:
        other_entries = hass.config_entries.async_entries(DOMAIN)
        if any(
            e.entry_id != entry.entry_id and str(e.unique_id or "") == serial
            for e in other_entries
        ):
            _LOGGER.warning(
                "Duplicate Apex config entries detected for serial=%s; remove extra entries to avoid inconsistent entities",
                serial,
            )
        else:
            hass.config_entries.async_update_entry(entry, unique_id=serial)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    # Forward only the platforms that make sense for this entry.
    platforms: list[Platform] = [
        Platform.SENSOR,
        Platform.BINARY_SENSOR,
    ]

    # Firmware + network metadata are only available when REST parsing is active.
    if rest_active:
        platforms.append(Platform.UPDATE)

    # Control entities only exist when login is enabled and REST is active.
    if control_enabled:
        platforms.extend(
            [
                Platform.SELECT,
                Platform.SWITCH,
                Platform.BUTTON,
                Platform.NUMBER,
            ]
        )

    await hass.config_entries.async_forward_entry_setups(entry, platforms)

    # Track which platforms were actually forwarded so unload can avoid
    # attempting to unload platforms that were never set up.
    hass.data.setdefault(DOMAIN, {}).setdefault(_DOMAIN_LOADED_PLATFORMS_KEY, {})[
        entry.entry_id
    ] = list(platforms)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.

    Returns:
        True if the entry was unloaded.
    """
    domain_data_any: Any = hass.data.get(DOMAIN)
    domain_data: dict[str, Any] = (
        cast(dict[str, Any], domain_data_any)
        if isinstance(domain_data_any, dict)
        else {}
    )

    def _coerce_platforms(value: Any) -> list[Platform]:
        platforms: list[Platform] = []
        if not isinstance(value, (list, set, tuple)):
            return platforms
        for item in cast(Any, value):
            if isinstance(item, Platform):
                platforms.append(item)
            elif isinstance(item, str):
                try:
                    platforms.append(Platform(item))
                except ValueError:
                    continue
        return platforms

    # Prefer Home Assistant's internal bookkeeping when available.
    platforms_to_unload: list[Platform] = []
    entry_platforms_any: Any = getattr(entry, "platforms", None)
    platforms_to_unload = _coerce_platforms(entry_platforms_any)

    # Fall back to what we recorded during setup.
    if not platforms_to_unload:
        stored_map_any: Any = domain_data.get(_DOMAIN_LOADED_PLATFORMS_KEY)
        stored_map: dict[str, Any] = (
            cast(dict[str, Any], stored_map_any)
            if isinstance(stored_map_any, dict)
            else {}
        )
        stored_any: Any = stored_map.get(entry.entry_id)
        if isinstance(stored_any, list) and stored_any:
            platforms_to_unload = cast(list[Platform], stored_any)

    # Last resort: unload all known platforms.
    if not platforms_to_unload:
        platforms_to_unload = list(PLATFORMS)

    try:
        unload_ok = await hass.config_entries.async_unload_platforms(
            entry, platforms_to_unload
        )
    except ValueError:
        # Guard against mismatches between what we think was loaded and what HA
        # actually loaded (can happen across upgrades/reloads).
        fallback = _coerce_platforms(entry_platforms_any)
        if not fallback:
            raise
        unload_ok = await hass.config_entries.async_unload_platforms(entry, fallback)

    if unload_ok:
        # Remove coordinator.
        domain_data.pop(entry.entry_id, None)
        # Remove platform bookkeeping.
        stored_map_any = domain_data.get(_DOMAIN_LOADED_PLATFORMS_KEY)
        if isinstance(stored_map_any, dict):
            cast(dict[str, Any], stored_map_any).pop(entry.entry_id, None)

    return unload_ok

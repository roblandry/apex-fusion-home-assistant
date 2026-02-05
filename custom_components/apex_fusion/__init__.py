"""The Apex Fusion (Local) integration.

This integration communicates with Neptune Apex controllers over the local
network, using REST when available and falling back to legacy status.xml.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_HOST, DOMAIN, LOGGER_NAME, PLATFORMS
from .coordinator import ApexNeptuneDataUpdateCoordinator

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Apex Fusion from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.

    Returns:
        True if setup succeeds.
    """
    coordinator = ApexNeptuneDataUpdateCoordinator(hass, entry=entry)
    await coordinator.async_config_entry_first_refresh()

    # Prefer the controller-reported hostname as the tank name.
    host = str(entry.data.get(CONF_HOST, ""))
    data: dict[str, Any] = coordinator.data or {}
    meta_any: Any = data.get("meta")
    meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
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

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.

    Returns:
        True if the entry was unloaded.
    """
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return unload_ok

"""Config entry migration for the Apex Fusion (Local) integration.

Version 2 pins each entry to one transport and gives every controller a stable
identity (its serial). Earlier releases chose the transport on every poll, so a
controller that went offline could come back as a second, "APEX 1.0" device with
host-based unique ids. This module converts those entries in place:

- the transport (and legacy format) are taken from the old bookkeeping;
- host/``entry:``-based unique ids and device identifiers are rewritten to the
  serial-based ones, keeping entity ids, history and customizations;
- when the serial-based entity already exists, it is kept and the duplicate is
  removed;
- orphan devices are removed only once they hold no entities.

Everything is computed as a plan first (logged as a summary) and then applied,
and re-running it is a no-op.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .const import (
    CONF_HOST,
    CONF_LAST_SOURCE,
    CONF_LEGACY_FORMAT,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    LEGACY_FORMAT_CGI_JSON,
    LEGACY_FORMAT_XML,
    LOGGER_NAME,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)
from .coordinator import transport_from_entry_data

_LOGGER = logging.getLogger(LOGGER_NAME)

CONFIG_ENTRY_VERSION = 2

# Removed bookkeeping keys written by earlier releases.
_OBSOLETE_DATA_KEYS = (CONF_LAST_SOURCE, "last_control_enabled")

# Platforms that only exist when the REST transport was active (update and the
# control platforms are never forwarded for legacy entries).
_REST_ONLY_ENTITY_DOMAINS = frozenset(
    {"update", "select", "switch", "button", "number"}
)

# Model string the legacy parsers gave the duplicate controller device.
_LEGACY_MODEL = "APEX 1.0"


@dataclass
class MigrationPlan:
    """What the migration will change for one config entry."""

    transport: str | None
    serial: str | None
    uid_rewrites: dict[str, str] = field(default_factory=lambda: {})
    twin_entities: list[str] = field(default_factory=lambda: [])
    orphan_entities: list[str] = field(default_factory=lambda: [])
    device_renames: dict[str, set[tuple[str, str]]] = field(default_factory=lambda: {})
    device_removals: list[str] = field(default_factory=lambda: [])

    def summary(self) -> str:
        """Return a one-line description of the plan."""
        return (
            f"transport={self.transport} serial={self.serial}: "
            f"unique_ids rewritten={len(self.uid_rewrites)}, "
            f"duplicate entities removed={len(self.twin_entities)}, "
            f"orphan entities removed={len(self.orphan_entities)}, "
            f"devices renamed={len(self.device_renames)}, "
            f"orphan devices removed={len(self.device_removals)}"
        )


def _host_token(host: str) -> str:
    return host.strip().replace(":", "_").lower()


def _legacy_uid_prefixes(entry: ConfigEntry) -> list[str]:
    """Return the unique-id prefixes that were not based on the serial."""
    prefixes: list[str] = []
    host = _host_token(str(entry.data.get(CONF_HOST, "")))
    if host:
        prefixes.append(f"{host}_")
    entry_token = entry.entry_id.lower()
    prefixes.append(f"entry:{entry_token}_")
    prefixes.append(f"entry_{entry_token}_")
    return prefixes


def _canonical_device_identifier(
    entry: ConfigEntry, identifier: str, serial: str
) -> str:
    """Map a host/``entry:`` based device identifier onto the serial-based one."""
    host = str(entry.data.get(CONF_HOST, "")).strip().lower()
    entry_prefix = f"entry:{entry.entry_id}"
    if identifier == entry_prefix:
        return serial
    if identifier.startswith(f"{entry_prefix}_"):
        return f"{serial}{identifier[len(entry_prefix) :]}"
    if host and identifier.lower() == host:
        return serial
    if host and identifier.lower().startswith(f"{host}_module_"):
        return f"{serial}{identifier[len(host) :]}"
    return identifier


def _resolve_serial(entry: ConfigEntry, devices: list[dr.DeviceEntry]) -> str | None:
    """Work out the controller serial for an existing entry."""
    host = str(entry.data.get(CONF_HOST, "")).strip().lower()
    unique_id = str(entry.unique_id or "").strip()
    if unique_id and unique_id.lower() != host:
        return unique_id
    for device in devices:
        for domain, identifier in device.identifiers:
            if (
                domain == DOMAIN
                and "_module_" not in identifier
                and _canonical_device_identifier(entry, identifier, "x") == identifier
            ):
                return identifier
    # A controller that never reported a serial keeps its original unique_id.
    return unique_id or None


def _migrated_data(
    entry: ConfigEntry, entities: list[er.RegistryEntry], serial: str | None
) -> dict[str, Any]:
    """Return the entry data with the transport/identity fields filled in."""
    data: dict[str, Any] = dict(entry.data)
    transport = transport_from_entry_data(data)
    if transport != TRANSPORT_REST and any(
        e.domain in _REST_ONLY_ENTITY_DOMAINS for e in entities
    ):
        # Only the REST transport ever created these entities, so a last_source
        # of cgi_json/xml just means the final poll before the upgrade happened
        # to fall through during an outage.
        transport = TRANSPORT_REST
    if transport is not None:
        data[CONF_TRANSPORT] = transport
    last = str(data.get(CONF_LAST_SOURCE) or "").strip().lower()
    if transport == TRANSPORT_LEGACY and last in (
        LEGACY_FORMAT_CGI_JSON,
        LEGACY_FORMAT_XML,
    ):
        data[CONF_LEGACY_FORMAT] = last
    if serial and not data.get(CONF_SERIAL):
        data[CONF_SERIAL] = serial
    for key in _OBSOLETE_DATA_KEYS:
        data.pop(key, None)
    return data


def build_plan(
    hass: HomeAssistant, entry: ConfigEntry, *, transport: str | None
) -> MigrationPlan:
    """Compute the registry changes for an entry without applying them.

    Args:
        hass: Home Assistant instance.
        entry: The config entry being migrated.
        transport: The transport the entry will be pinned to.

    Returns:
        The plan (empty when the serial cannot be determined).
    """
    ent_reg = er.async_get(hass)
    dev_reg = dr.async_get(hass)
    entities = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)

    serial = _resolve_serial(entry, devices)
    plan = MigrationPlan(transport=transport, serial=serial)
    if not serial:
        return plan

    serial_token = serial.replace(":", "_").lower()
    removed: set[str] = set()

    # --- Entities: host/entry-prefixed unique ids -> serial-prefixed ones. ---
    prefixes = _legacy_uid_prefixes(entry)
    claimed: set[tuple[str, str]] = set()
    for reg_entry in entities:
        prefix = next((p for p in prefixes if reg_entry.unique_id.startswith(p)), None)
        if prefix is None or prefix == f"{serial_token}_":
            continue
        new_uid = f"{serial_token}_{reg_entry.unique_id[len(prefix) :]}"
        existing_id = ent_reg.async_get_entity_id(
            reg_entry.domain, reg_entry.platform, new_uid
        )
        if existing_id is not None and existing_id != reg_entry.entity_id:
            existing = ent_reg.async_get(existing_id)
            if existing is not None and existing.config_entry_id == entry.entry_id:
                # The serial-based (REST) entity already exists: keep it.
                plan.twin_entities.append(reg_entry.entity_id)
                removed.add(reg_entry.entity_id)
            continue
        if (reg_entry.domain, new_uid) in claimed:
            plan.twin_entities.append(reg_entry.entity_id)
            removed.add(reg_entry.entity_id)
            continue
        claimed.add((reg_entry.domain, new_uid))
        plan.uid_rewrites[reg_entry.entity_id] = new_uid

    # --- Devices: rename in place, or drop duplicates that hold nothing. ---
    canonical_ids = {(DOMAIN, serial)}
    canonical_exists = any(
        canonical_ids & set(device.identifiers) for device in devices
    )
    claimed_identifiers: set[tuple[str, str]] = set()
    for device in devices:
        own = {i for i in device.identifiers if i[0] == DOMAIN}
        mapped = {
            (DOMAIN, _canonical_device_identifier(entry, ident, serial))
            for _, ident in own
        }
        is_canonical = bool(canonical_ids & own)
        duplicate = False
        if mapped != own:
            for ident in mapped - own:
                other = dev_reg.async_get_device(identifiers={ident})
                if (other is not None and other.id != device.id) or (
                    ident in claimed_identifiers
                ):
                    duplicate = True
            if not duplicate:
                claimed_identifiers |= mapped
                plan.device_renames[device.id] = (set(device.identifiers) - own) | (
                    mapped
                )
        elif (
            canonical_exists
            and not is_canonical
            and str(device.model or "") == _LEGACY_MODEL
        ):
            duplicate = True
        if not duplicate:
            continue

        for reg_entry in er.async_entries_for_device(
            ent_reg, device.id, include_disabled_entities=True
        ):
            if reg_entry.config_entry_id != entry.entry_id:
                continue
            if reg_entry.entity_id in removed:
                continue
            if transport == TRANSPORT_REST:
                # Nothing on a duplicate device is provided on REST any more.
                plan.orphan_entities.append(reg_entry.entity_id)
                plan.uid_rewrites.pop(reg_entry.entity_id, None)
                removed.add(reg_entry.entity_id)
        leftover = [
            e
            for e in er.async_entries_for_device(
                ent_reg, device.id, include_disabled_entities=True
            )
            if e.entity_id not in removed
        ]
        if not leftover:
            plan.device_removals.append(device.id)
    return plan


async def apply_plan(
    hass: HomeAssistant, entry: ConfigEntry, plan: MigrationPlan
) -> None:
    """Apply a migration plan to the registries."""
    ent_reg = er.async_get(hass)
    dev_reg = dr.async_get(hass)

    for entity_id in (*plan.twin_entities, *plan.orphan_entities):
        if ent_reg.async_get(entity_id) is not None:
            ent_reg.async_remove(entity_id)

    def _rewrite(reg_entry: er.RegistryEntry) -> dict[str, Any] | None:
        new_uid = plan.uid_rewrites.get(reg_entry.entity_id)
        if new_uid is None or new_uid == reg_entry.unique_id:
            return None
        return {"new_unique_id": new_uid}

    await er.async_migrate_entries(hass, entry.entry_id, _rewrite)

    for device_id in plan.device_removals:
        if dev_reg.async_get(device_id) is not None:
            dev_reg.async_remove_device(device_id)
    for device_id, identifiers in plan.device_renames.items():
        if dev_reg.async_get(device_id) is not None:
            dev_reg.async_update_device(device_id, new_identifiers=identifiers)


async def migrate_v1_to_v2(
    hass: HomeAssistant, entry: ConfigEntry, *, dry_run: bool = False
) -> MigrationPlan:
    """Migrate a version 1 entry to version 2.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.
        dry_run: Only compute and log the plan; change nothing.

    Returns:
        The plan that was (or, for a dry run, would be) applied.
    """
    ent_reg = er.async_get(hass)
    entities = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    serial = _resolve_serial(entry, devices)
    data = _migrated_data(entry, entities, serial)
    plan = build_plan(hass, entry, transport=data.get(CONF_TRANSPORT))

    _LOGGER.info(
        "Apex entry %s migration%s: %s",
        entry.entry_id,
        " (dry run)" if dry_run else "",
        plan.summary(),
    )
    for entity_id, new_uid in plan.uid_rewrites.items():
        _LOGGER.debug("Apex migration: %s unique_id -> %s", entity_id, new_uid)
    for entity_id in plan.twin_entities:
        _LOGGER.debug("Apex migration: removing duplicate entity %s", entity_id)
    for entity_id in plan.orphan_entities:
        _LOGGER.debug("Apex migration: removing orphan entity %s", entity_id)
    if dry_run:
        return plan

    await apply_plan(hass, entry, plan)
    hass.config_entries.async_update_entry(entry, data=data, version=2)
    return plan

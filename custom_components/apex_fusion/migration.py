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
import re
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
    candidates = sorted(
        identifier
        for device in devices
        for domain, identifier in device.identifiers
        if domain == DOMAIN
        and "_module_" not in identifier
        and _canonical_device_identifier(entry, identifier, "x") == identifier
    )
    # Never pin the old ``AC6:<token>`` form when a current one exists.
    current = [c for c in candidates if _CURRENT_IDENTIFIER.match(c)]
    if current or candidates:
        return (current or candidates)[0]
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


# The old duplicate controller device: literal ``AC6`` prefix, model ``1.0``.
_LEGACY_PREFIX = "AC6"
_LEGACY_ORPHAN_MODEL = "1.0"
_CURRENT_IDENTIFIER = re.compile(r"^AC6[A-Z]:(?P<token>[^:]+)$")


def _live_token(live_identifier: str) -> str | None:
    """Return the serial token of a current-form (``AC6J:``/``AC6L:``) identifier."""
    match = _CURRENT_IDENTIFIER.match(live_identifier)
    return match.group("token") if match else None


def is_legacy_orphan_signature(device: dr.DeviceEntry, entry_id: str) -> str | None:
    """Return the serial token if the device has the exact old-orphan signature.

    The signature is: one identifier, ``(DOMAIN, "AC6:<token>")``, model ``1.0``,
    no ``via_device`` and held by this config entry alone.
    """
    if (
        device.via_device_id is not None
        or device.config_entries != {entry_id}
        or str(device.model or "") != _LEGACY_ORPHAN_MODEL
        or len(device.identifiers) != 1
    ):
        return None
    domain, identifier = next(iter(device.identifiers))
    prefix, sep, token = identifier.partition(":")
    if domain != DOMAIN or not sep or prefix != _LEGACY_PREFIX or not token:
        return None
    return token


def find_orphan_controller_device(
    hass: HomeAssistant, entry: ConfigEntry, live_identifier: str
) -> dr.DeviceEntry | None:
    """Return the one positively identified old controller device, if any.

    Requires a verified current-form live identifier that is the entry's
    persisted identity, a registered live device, and exactly one other
    top-level controller-like device sharing the serial token, which must have
    the exact old-orphan signature. Anything else returns ``None``.
    """
    token = _live_token(live_identifier)
    if token is None or str(entry.data.get(CONF_SERIAL) or "") != live_identifier:
        return None
    dev_reg = dr.async_get(hass)
    live = dev_reg.async_get_device(identifiers={(DOMAIN, live_identifier)})
    if live is None or entry.entry_id not in live.config_entries:
        return None
    sharing: list[dr.DeviceEntry] = []
    for device in dr.async_entries_for_config_entry(dev_reg, entry.entry_id):
        if device.id == live.id or device.via_device_id is not None:
            continue
        for domain, identifier in device.identifiers:
            if (
                domain == DOMAIN
                and "_module_" not in identifier
                and identifier.partition(":")[2] == token
            ):
                sharing.append(device)
                break
    if (
        len(sharing) != 1
        or is_legacy_orphan_signature(sharing[0], entry.entry_id) != token
    ):
        return None
    return sharing[0]


_TEMP_SUFFIX = "_apex_legacy"


def _plan_entity_pairing(
    hass: HomeAssistant,
    entry: ConfigEntry,
    orphan: dr.DeviceEntry,
    live_identifier: str,
) -> tuple[list[tuple[str, str, str | None]], str | None]:
    """Pair each orphan entity with its live counterpart.

    Returns ``(plan, problem)``. Each plan item is ``(orphan_entity_id,
    live_entity_id, canonical_id)``; ``canonical_id`` is set when the live
    entity must take over the orphan's id. ``problem`` is set when any entity
    cannot be paired with certainty (or the pairing would disable a working
    entity), in which case nothing may be removed.

    An orphan entity id ending in ``_apex_legacy`` is a half-finished transfer
    from an earlier attempt and is recognised so it can be completed.
    """
    ent_reg = er.async_get(hass)
    orphan_token = next(iter(orphan.identifiers))[1].partition(":")[2]
    old_prefix = f"{_LEGACY_PREFIX}_{orphan_token}_".lower()
    live_prefix = f"{live_identifier.replace(':', '_')}_".lower()
    plan: list[tuple[str, str, str | None]] = []
    for reg_entry in er.async_entries_for_device(
        ent_reg, orphan.id, include_disabled_entities=True
    ):
        if reg_entry.config_entry_id != entry.entry_id:
            return [], f"{reg_entry.entity_id} belongs to another config entry"
        if not reg_entry.unique_id.startswith(old_prefix):
            return [], f"{reg_entry.entity_id} has an unrecognised unique_id"
        key = reg_entry.unique_id[len(old_prefix) :]
        live_id = ent_reg.async_get_entity_id(
            reg_entry.domain, reg_entry.platform, f"{live_prefix}{key}"
        )
        live_entry = ent_reg.async_get(live_id) if live_id else None
        if live_entry is None or live_entry.config_entry_id != entry.entry_id:
            return [], f"{reg_entry.entity_id} has no live counterpart"
        if reg_entry.disabled_by is None and live_entry.disabled_by is not None:
            return [], f"live counterpart of {reg_entry.entity_id} is disabled"
        old_id, new_id = reg_entry.entity_id, live_entry.entity_id
        canonical = old_id.removesuffix(_TEMP_SUFFIX)
        if re.fullmatch(rf"{re.escape(canonical)}_\d+", new_id):
            # The orphan holds the canonical id; the live entity takes it over.
            plan.append((old_id, new_id, canonical))
        elif re.fullmatch(rf"{re.escape(new_id)}_(\d+|apex_legacy)", old_id):
            plan.append((old_id, new_id, None))
        else:
            return [], f"{old_id} and {new_id} are not a suffix pair"
    return plan, None


def _transfer_entity_id(
    ent_reg: er.EntityRegistry, old_id: str, live_id: str, canonical: str
) -> None:
    """Give ``canonical`` to the live entity so that no step can lose the id.

    The orphan entity is parked at a temporary id, the live entity is renamed,
    and only then is the orphan removed. If the live rename fails the orphan is
    put back, so the canonical id always stays on an entity. A leftover parked
    entity is recognised by the next setup and the transfer is completed.
    """
    parked = old_id
    if old_id == canonical:
        parked = f"{canonical}{_TEMP_SUFFIX}"
        ent_reg.async_update_entity(old_id, new_entity_id=parked)
    try:
        ent_reg.async_update_entity(live_id, new_entity_id=canonical)
    except Exception:
        if parked != old_id:
            ent_reg.async_update_entity(parked, new_entity_id=old_id)
        raise
    ent_reg.async_remove(parked)


def async_remove_orphan_controller_device(
    hass: HomeAssistant, entry: ConfigEntry, live_identifier: str
) -> bool:
    """Remove the old ``AC6:<token>`` controller device when it is provably a dupe.

    Does nothing (and logs why) if the live identity is unverified, the orphan
    is ambiguous, an entity cannot be paired with a live one, or pairing would
    hand an id to a disabled entity. If a registry step fails part way, the
    canonical entity id stays on an entity, the device is kept, and the next
    setup completes the work.

    Returns:
        True if a device was removed.
    """
    orphan = find_orphan_controller_device(hass, entry, live_identifier)
    if orphan is None:
        return False
    plan, problem = _plan_entity_pairing(hass, entry, orphan, live_identifier)
    if problem is not None:
        _LOGGER.info(
            "Apex entry %s: leaving old controller device in place (%s)",
            entry.entry_id,
            problem,
        )
        return False
    ent_reg = er.async_get(hass)
    try:
        for old_id, live_id, canonical in plan:
            if canonical is None:
                ent_reg.async_remove(old_id)
            else:
                _transfer_entity_id(ent_reg, old_id, live_id, canonical)
        dr.async_get(hass).async_remove_device(orphan.id)
    except Exception:  # noqa: BLE001
        _LOGGER.warning(
            "Apex entry %s: could not finish removing the old controller device; "
            "it will be retried on the next start",
            entry.entry_id,
            exc_info=True,
        )
        return False
    _LOGGER.info(
        "Apex entry %s: removed duplicate controller device %s (%d entities)",
        entry.entry_id,
        next(iter(orphan.identifiers))[1],
        len(plan),
    )
    return True

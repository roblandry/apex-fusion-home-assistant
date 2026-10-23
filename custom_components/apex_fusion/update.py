"""Update entities for Apex Fusion (Local).

Home Assistant has a first-class Update platform for firmware/software update
availability. The local Apex REST API exposes controller-level update metadata
via `nstat.latestFirmware` and `nstat.updateFirmware`.

Module-level update availability is not consistently exposed in controller
payloads. This platform only creates module update entities when there are
strong signals that an update is relevant/available.

Update availability is decided by `firmware_update_available` rather than by the
controller's `updateFirmware` flag alone: the flag can be stale (False) while the
controller reports a newer `latestFirmware`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, cast

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .apex_fusion import (
    ApexFusionContext,
    mconf_modules_from_data,
    raw_modules_from_data,
    raw_nstat_from_data,
)
from .const import DOMAIN
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
    build_device_info,
    build_module_device_info,
    build_module_device_info_from_data,
    build_trident_device_info,
)

# Apex firmware strings look like "5.15J_6B26" (installed) or "5.16_AC26"
# (latest): <major>.<minor>[family letter]_<build>. The optional J/L letter is the
# hardware family, not part of the release identity.
_FIRMWARE_RE = re.compile(r"^(\d+)\.(\d+)[A-Za-z]?_([0-9A-Za-z]+)$")


def normalize_firmware(value: str | None) -> tuple[int, int, str] | None:
    """Parse an Apex firmware string into (major, minor, build).

    The optional family letter (e.g. the "J" in "5.15J_6B26") is dropped.

    Returns:
        The normalized tuple, or None when the string is missing or unparseable.
    """
    if value is None:
        return None
    m = _FIRMWARE_RE.match(value.strip())
    if m is None:
        return None
    return int(m.group(1)), int(m.group(2)), m.group(3)


def firmware_update_available(
    latest: str | None, installed: str | None, flag: bool | None = None
) -> bool:
    """Decide whether `latest` represents an update over `installed`.

    Rules:
    - If major.minor differs, the numerically greater one is newer.
    - If major.minor is equal and the build code differs, an update is
      available. Build codes are opaque; their order is never inferred.
    - If the normalized versions are equal, the controller `flag` decides
      (True means update available; False/None means none).
    - If either string is unparseable, fall back to string inequality when both
      are present.
    - If either string is missing, only a True `flag` reports an update.

    A False flag never hides a visibly newer version.
    """
    if latest is None or installed is None:
        return flag is True

    new = normalize_firmware(latest)
    old = normalize_firmware(installed)
    if new is None or old is None:
        return latest != installed or flag is True

    if new[:2] != old[:2]:
        return new[:2] > old[:2] or flag is True
    if new[2] != old[2]:
        return True
    return flag is True


def _raw_nstat(data: dict[str, Any]) -> dict[str, Any]:
    return raw_nstat_from_data(data)


def _raw_modules(data: dict[str, Any]) -> list[dict[str, Any]]:
    return raw_modules_from_data(data)


def _config_root(data: dict[str, Any]) -> dict[str, Any]:
    config_any: Any = data.get("config")
    return cast(dict[str, Any], config_any) if isinstance(config_any, dict) else {}


def _config_nconf(data: dict[str, Any]) -> dict[str, Any]:
    nconf_any: Any = _config_root(data).get("nconf")
    return cast(dict[str, Any], nconf_any) if isinstance(nconf_any, dict) else {}


def _config_mconf_modules(data: dict[str, Any]) -> list[dict[str, Any]]:
    return mconf_modules_from_data(data)


def _find_status_module(
    data: dict[str, Any], *, hwtype: str, module_id: str
) -> dict[str, Any] | None:
    for m in _raw_modules(data):
        m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
        if m_hw != hwtype:
            continue
        m_ab = m.get("abaddr")
        m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
        if not m_id:
            m_id = str(m.get("did") or m.get("id") or hwtype).strip()
        if m_id != module_id:
            continue
        return m
    return None


def _find_mconf_module(
    data: dict[str, Any], *, hwtype: str, module_id: str
) -> dict[str, Any] | None:
    for m in _config_mconf_modules(data):
        m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
        if m_hw != hwtype:
            continue
        m_ab = m.get("abaddr")
        m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
        if not m_id:
            m_id = str(m.get("did") or m.get("id") or hwtype).strip()
        if m_id != module_id:
            continue
        return m
    return None


def _controller_update_firmware_flag(data: dict[str, Any]) -> bool | None:
    # Prefer sanitized config (from /rest/config) when present.
    flag_any: Any = _config_nconf(data).get("updateFirmware")
    if isinstance(flag_any, bool):
        return flag_any

    nstat = _raw_nstat(data)
    flag_any = nstat.get("updateFirmware")
    return flag_any if isinstance(flag_any, bool) else None


@dataclass(frozen=True)
class _UpdateRef:
    unique_id: str
    name: str
    installed_fn: Callable[[dict[str, Any]], str | None]
    latest_fn: Callable[[dict[str, Any]], str | None]
    release_summary_fn: Callable[[dict[str, Any]], str | None]
    update_flag_fn: Callable[[dict[str, Any]], bool | None] = lambda _data: None
    module_hwtype: str | None = None
    module_abaddr: int | None = None


class ApexUpdateEntity(UpdateEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_device_class = UpdateDeviceClass.FIRMWARE

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _UpdateRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = ref.unique_id
        self._attr_name = ref.name

        # Suggest entity ids that remain unique across multiple tanks.
        tank_slug = ctx.tank_slug_with_entry_title(entry.title)

        installed_version = ref.installed_fn(coordinator.data or {})

        # Only attach Trident-family modules by explicit hwtype (no heuristics).
        if ref.module_hwtype in {"TRI", "TNP"} and isinstance(ref.module_abaddr, int):
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug, "trident", ref.module_abaddr, "firmware"
            )

            trident_any: Any = (coordinator.data or {}).get("trident")
            trident = (
                cast(dict[str, Any], trident_any)
                if isinstance(trident_any, dict)
                else {}
            )
            self._attr_device_info = build_trident_device_info(
                host=ctx.host,
                meta=ctx.meta,
                controller_device_identifier=coordinator.device_identifier,
                tank_slug=tank_slug,
                trident_abaddr=ref.module_abaddr,
                trident_hwtype=ref.module_hwtype,
                trident_hwrev=(str(trident.get("hwrev") or "").strip() or None),
                trident_swrev=(str(trident.get("swrev") or "").strip() or None),
                trident_serial=(str(trident.get("serial") or "").strip() or None),
            )
        elif ref.module_hwtype and isinstance(ref.module_abaddr, int):
            hw = str(ref.module_hwtype).strip().upper()
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug,
                ctx.module_token(hw),
                ref.module_abaddr,
                "firmware",
            )

            # Prefer coordinator-derived module metadata (name/hwrev/serial).
            # Fall back to minimal device info if the module can't be resolved.
            module_device_info = build_module_device_info_from_data(
                host=ctx.host,
                controller_device_identifier=coordinator.device_identifier,
                data=coordinator.data or {},
                module_abaddr=ref.module_abaddr,
                tank_slug=tank_slug,
            )
            self._attr_device_info = module_device_info or build_module_device_info(
                host=ctx.host,
                controller_device_identifier=coordinator.device_identifier,
                module_hwtype=hw,
                module_abaddr=ref.module_abaddr,
                module_swrev=str(installed_version or "").strip() or None,
                tank_slug=tank_slug,
            )
        else:
            # Controller update entity ids should also be tank-prefixed.
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug, "apex", "firmware"
            )
            self._attr_device_info = build_device_info(
                host=ctx.host,
                meta=ctx.meta,
                device_identifier=coordinator.device_identifier,
                tank_slug=tank_slug,
            )

        self._refresh_attrs()

    def _refresh_attrs(self) -> None:
        data = self._coordinator.data or {}
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        installed = self._ref.installed_fn(data)
        latest = self._ref.latest_fn(data)
        if installed is None and latest == _UPDATE_PLACEHOLDER:
            # Without an installed version HA reports "unknown" rather than an
            # available update.
            installed = _UNKNOWN_INSTALLED
        self._attr_installed_version = installed
        self._attr_latest_version = latest
        self._attr_release_summary = self._ref.release_summary_fn(data)

    def version_is_newer(self, latest_version: str, installed_version: str) -> bool:
        """Compare Apex firmware strings instead of using AwesomeVersion.

        Home Assistant only calls this when the two strings are not identical
        (see `UpdateEntity.state`). Apex build codes are not orderable and the
        family letter must be ignored, so use `firmware_update_available`.
        """
        flag = self._ref.update_flag_fn(self._coordinator.data or {})
        return firmware_update_available(latest_version, installed_version, flag)

    def _handle_coordinator_update(self) -> None:
        self._refresh_attrs()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_coordinator_update)
        )
        self._handle_coordinator_update()


def _controller_installed(data: dict[str, Any]) -> str | None:
    meta_any: Any = data.get("meta")
    if not isinstance(meta_any, dict):
        return None
    meta = cast(dict[str, Any], meta_any)
    v = meta.get("software")
    return str(v).strip() or None if v is not None else None


def _controller_latest(data: dict[str, Any]) -> str | None:
    meta_any: Any = data.get("meta")
    if not isinstance(meta_any, dict):
        return None
    meta = cast(dict[str, Any], meta_any)
    v = meta.get("firmware_latest")
    if v is not None and str(v).strip():
        return str(v).strip()

    # Latest firmware may be present in sanitized config (from /rest/config).
    latest_any: Any = _config_nconf(data).get("latestFirmware")
    return str(latest_any).strip() or None if latest_any is not None else None


def _controller_release_summary(data: dict[str, Any]) -> str | None:
    """Controller firmware has no extra context beyond the version strings."""
    return None


# The controller UI never offers a software update for these module types.
_NO_UPDATE_HWTYPES = frozenset({"IOTA", "MXM", "PM3"})

# Old-hardware Trident modules (hwrev 2) are not offered an update while the
# *controller* runs software older than this (the UI's `OLDVALID` constant).
_OLD_TRI_CONTROLLER_MIN = "5.06_CD21"

# Shown as latest (and, with no installed version, installed) when the
# controller says a module is out of date but there is no distinct version.
_UPDATE_PLACEHOLDER = "Update available"
_UNKNOWN_INSTALLED = "Unknown"

# The controller UI's software identifier grammar:
# <major>.<minor 2 digits>[family letter]_<month 1-9A-C><build letter><year 2 digits>[type letter]
_UI_SOFTWARE_RE = re.compile(r"^(\d+)\.(\d{2})[A-Z]?_([1-9A-C])([A-Z])(\d{2})([A-Z])?$")


def _ui_software_key(value: Any) -> int | None:
    """Order key matching the controller UI's software comparison, or None."""
    if value is None:
        return None
    m = _UI_SOFTWARE_RE.match(str(value).strip())
    if m is None:
        return None
    packed = (
        int(m.group(1)) << 26
        | int(m.group(2)) << 19
        | int(m.group(5)) << 12
        | int(m.group(3), 16) << 8
        | ord(m.group(4)) << 1
        | (1 if m.group(6) else 0)
    )
    # The UI packs this with JavaScript bitwise operators, which wrap to a
    # signed 32-bit integer; reproduce that so large majors order the same way.
    packed &= 0xFFFFFFFF
    return packed - (1 << 32) if packed >= 1 << 31 else packed


_OLD_TRI_CONTROLLER_MIN_KEY = cast(int, _ui_software_key(_OLD_TRI_CONTROLLER_MIN))


def _module_excluded(module: dict[str, Any], data: dict[str, Any]) -> bool:
    """True for modules the controller UI never offers a software update for."""
    hwtype = str(module.get("hwtype") or module.get("hwType") or "").strip().upper()
    if hwtype in _NO_UPDATE_HWTYPES:
        return True

    hwrev: Any = module.get("hwrev")
    # The UI tests `2 === hwrev`: only a JSON number equal to 2 matches (not "2"
    # or true).
    if (
        hwtype == "TRI"
        and isinstance(hwrev, (int, float))
        and not isinstance(hwrev, bool)
        and hwrev == 2
    ):
        controller_key = _ui_software_key(_controller_installed(data))
        # Exclude conservatively when the controller software can't be compared.
        return controller_key is None or controller_key < _OLD_TRI_CONTROLLER_MIN_KEY

    return False


def _module_swstat_update(
    module: dict[str, Any] | None, data: dict[str, Any]
) -> bool | None:
    """Return True when the controller reports an eligible module as out of date.

    Mirrors the controller web UI: `swstat == "OLD"` means an update is
    available. `OK`, `PENDING` (an update is already queued or running) and any
    other value are not an update offer, and excluded modules never are.

    `mconf.update` is the UI's install trigger, not an availability signal, and
    is deliberately ignored here.
    """
    if not module or _module_excluded(module, data):
        return None
    swstat = str(module.get("swstat") or "").strip().upper()
    return True if swstat == "OLD" else None


def _module_effective_latest(
    module: dict[str, Any], data: dict[str, Any], installed: str | None
) -> str | None:
    """Latest version to display for a present module."""
    if _module_excluded(module, data):
        # Never an update, whatever the controller reports as latest.
        return installed

    if str(module.get("swstat") or "").strip().upper() == "PENDING":
        # An update is already queued or running; the UI offers none.
        return installed

    reported_any: Any = module.get("latestFirmware") or module.get("latestSw")
    reported = str(reported_any).strip() or None if reported_any is not None else None

    if _module_swstat_update(module, data) is True:
        # Home Assistant reports "off" when latest == installed and "unknown"
        # without an installed version, so use the placeholder in those cases.
        if reported is None or installed is None or reported == installed:
            return _UPDATE_PLACEHOLDER
        return reported

    return reported if reported is not None else installed


def _module_refs(data: dict[str, Any], serial_for_ids: str) -> list[_UpdateRef]:
    refs: list[_UpdateRef] = []

    mconf_modules = _config_mconf_modules(data)
    if mconf_modules:
        # When config is available, use it to enumerate modules. Update availability
        # still comes from the status swstat, never from mconf[].update (the UI's
        # install trigger).
        for mconf in mconf_modules:
            hwtype = (
                str(mconf.get("hwtype") or mconf.get("hwType") or "").strip().upper()
            )
            if not hwtype:
                continue

            abaddr_any: Any = mconf.get("abaddr")
            module_id = str(abaddr_any) if isinstance(abaddr_any, int) else ""
            if not module_id:
                module_id = str(mconf.get("did") or mconf.get("id") or hwtype).strip()

            def _installed_from_status_fn(
                _data: dict[str, Any],
                *,
                hwtype: str = hwtype,
                module_id: str = module_id,
            ) -> str | None:
                m = _find_status_module(_data, hwtype=hwtype, module_id=module_id)
                if not m:
                    return None
                v: Any = m.get("software")
                if v is None:
                    v = m.get("swrev")
                return str(v).strip() or None if v is not None else None

            def _latest_effective_fn(
                _data: dict[str, Any],
                *,
                hwtype: str = hwtype,
                module_id: str = module_id,
            ) -> str | None:
                installed = _installed_from_status_fn(
                    _data, hwtype=hwtype, module_id=module_id
                )
                status_module = _find_status_module(
                    _data, hwtype=hwtype, module_id=module_id
                )
                if not status_module:
                    return None

                present_any: Any = status_module.get("present")
                present = bool(present_any) if isinstance(present_any, bool) else True
                if not present:
                    # When a Trident-family module is disconnected, we still want the
                    # entity to exist and to show installed firmware without implying
                    # update availability.
                    if hwtype in {"TRI", "TNP"} and installed:
                        return installed
                    return None

                return _module_effective_latest(status_module, _data, installed)

            def _update_flag_fn(
                _data: dict[str, Any],
                *,
                hwtype: str = hwtype,
                module_id: str = module_id,
            ) -> bool | None:
                return _module_swstat_update(
                    _find_status_module(_data, hwtype=hwtype, module_id=module_id),
                    _data,
                )

            def _release_summary_fn_config(
                _data: dict[str, Any],
                *,
                hwtype: str = hwtype,
                module_id: str = module_id,
            ) -> str | None:
                status_module = _find_status_module(
                    _data, hwtype=hwtype, module_id=module_id
                )
                if not status_module:
                    return None

                mconf_module = _find_mconf_module(
                    _data, hwtype=hwtype, module_id=module_id
                )
                update_stat_any: Any = (mconf_module or {}).get("updateStat")
                if isinstance(update_stat_any, int) and update_stat_any:
                    return f"updateStat={update_stat_any}"

                sw = str(status_module.get("swstat") or "").strip() or None
                return sw

            # Only create entities for modules that are actually present in
            # status (prevents phantom entities from stale config).
            status_module = _find_status_module(
                data, hwtype=hwtype, module_id=module_id
            )
            if status_module is None:
                continue

            present_any: Any = status_module.get("present")
            present = bool(present_any) if isinstance(present_any, bool) else True
            if not present and hwtype not in {"TRI", "TNP"}:
                continue

            installed_now = _installed_from_status_fn(
                data, hwtype=hwtype, module_id=module_id
            )
            if not present and hwtype in {"TRI", "TNP"} and not installed_now:
                continue

            refs.append(
                _UpdateRef(
                    unique_id=f"{serial_for_ids}_update_{module_id}".lower(),
                    name="Firmware",
                    installed_fn=_installed_from_status_fn,
                    latest_fn=_latest_effective_fn,
                    release_summary_fn=_release_summary_fn_config,
                    update_flag_fn=_update_flag_fn,
                    module_hwtype=hwtype,
                    module_abaddr=abaddr_any if isinstance(abaddr_any, int) else None,
                )
            )

        return refs

    for module in _raw_modules(data):
        hwtype = str(module.get("hwtype") or module.get("hwType") or "").strip().upper()
        if not hwtype:
            continue

        present_any: Any = module.get("present")
        present = bool(present_any) if isinstance(present_any, bool) else True
        if not present and hwtype not in {"TRI", "TNP"}:
            continue

        if not present and hwtype in {"TRI", "TNP"}:
            if module.get("software") is None and module.get("swrev") is None:
                continue

        abaddr = module.get("abaddr")
        module_id = (
            str(abaddr) if isinstance(abaddr, int) else str(abaddr or "").strip()
        )
        if not module_id:
            module_id = str(module.get("did") or module.get("id") or hwtype).strip()

        def _installed_fn(
            _data: dict[str, Any], *, module_id: str = module_id, hwtype: str = hwtype
        ) -> str | None:
            for m in _raw_modules(_data):
                m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
                if m_hw != hwtype:
                    continue
                m_ab = m.get("abaddr")
                m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
                if not m_id:
                    m_id = str(m.get("did") or m.get("id") or hwtype).strip()
                if m_id != module_id:
                    continue
                v: Any = m.get("software")
                if v is None:
                    v = m.get("swrev")
                return str(v).strip() or None if v is not None else None
            return None

        def _latest_fn(
            _data: dict[str, Any], *, module_id: str = module_id, hwtype: str = hwtype
        ) -> str | None:
            for m in _raw_modules(_data):
                m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
                if m_hw != hwtype:
                    continue
                m_ab = m.get("abaddr")
                m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
                if not m_id:
                    m_id = str(m.get("did") or m.get("id") or hwtype).strip()
                if m_id != module_id:
                    continue

                present_any: Any = m.get("present")
                present = bool(present_any) if isinstance(present_any, bool) else True
                if not present:
                    installed = _installed_fn(_data, module_id=module_id, hwtype=hwtype)
                    return installed

                installed = _installed_fn(_data, module_id=module_id, hwtype=hwtype)
                return _module_effective_latest(m, _data, installed)
            return None

        def _release_summary_fn(
            _data: dict[str, Any], *, module_id: str = module_id, hwtype: str = hwtype
        ) -> str | None:
            for m in _raw_modules(_data):
                m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
                if m_hw != hwtype:
                    continue
                m_ab = m.get("abaddr")
                m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
                if not m_id:
                    m_id = str(m.get("did") or m.get("id") or hwtype).strip()
                if m_id != module_id:
                    continue
                sw_any: Any = m.get("swstat")
                sw = str(sw_any).strip() or None if sw_any is not None else None
                # Provide status as context (not as the source of truth for availability).
                return sw
            return None

        def _update_flag_fn_raw(
            _data: dict[str, Any], *, module_id: str = module_id, hwtype: str = hwtype
        ) -> bool | None:
            for m in _raw_modules(_data):
                m_hw = str(m.get("hwtype") or m.get("hwType") or "").strip().upper()
                if m_hw != hwtype:
                    continue
                m_ab = m.get("abaddr")
                m_id = str(m_ab) if isinstance(m_ab, int) else str(m_ab or "").strip()
                if not m_id:
                    m_id = str(m.get("did") or m.get("id") or hwtype).strip()
                if m_id != module_id:
                    continue
                return _module_swstat_update(m, _data)
            return None

        refs.append(
            _UpdateRef(
                unique_id=f"{serial_for_ids}_update_{module_id}".lower(),
                name="Firmware",
                installed_fn=_installed_fn,
                latest_fn=_latest_fn,
                release_summary_fn=_release_summary_fn,
                update_flag_fn=_update_flag_fn_raw,
                module_hwtype=hwtype,
                module_abaddr=abaddr if isinstance(abaddr, int) else None,
            )
        )

    return refs


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)
    serial_for_ids = ctx.serial_for_ids

    controller_ref = _UpdateRef(
        unique_id=f"{serial_for_ids}_update_firmware".lower(),
        name="Firmware",
        installed_fn=_controller_installed,
        latest_fn=_controller_latest,
        release_summary_fn=_controller_release_summary,
        update_flag_fn=_controller_update_firmware_flag,
    )

    async_add_entities([ApexUpdateEntity(coordinator, entry, ref=controller_ref)])

    added_ids: set[str] = set()

    def _add_module_entities() -> None:
        data = coordinator.data or {}
        new: list[ApexUpdateEntity] = []
        for ref in _module_refs(data, serial_for_ids):
            if ref.unique_id in added_ids:
                continue
            added_ids.add(ref.unique_id)
            new.append(ApexUpdateEntity(coordinator, entry, ref=ref))

        if new:
            async_add_entities(new)

    _add_module_entities()
    entry.async_on_unload(coordinator.async_add_listener(_add_module_entities))

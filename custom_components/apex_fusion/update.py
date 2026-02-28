"""Update entities for Apex Fusion (Local).

Home Assistant has a first-class Update platform for firmware/software update
availability. The local Apex REST API exposes controller-level update metadata
via `nstat.latestFirmware` and `nstat.updateFirmware`.

Module-level update availability is not consistently exposed in controller
payloads. This platform only creates module update entities when there are
strong signals that an update is relevant/available.
"""

from __future__ import annotations

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
        self._attr_installed_version = self._ref.installed_fn(data)
        self._attr_latest_version = self._ref.latest_fn(data)
        self._attr_release_summary = self._ref.release_summary_fn(data)

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


def _controller_latest_effective(data: dict[str, Any]) -> str | None:
    """Return the effective latest version.

    Home Assistant derives update availability from whether latest_version differs
    from installed_version, so we suppress the reported latest when the controller
    explicitly says there is no update available.

    Args:
        data: Coordinator data dict.

    Returns:
        Effective latest version string, or None if unknown.
    """
    installed = _controller_installed(data)
    reported_latest = _controller_latest(data)

    flag = _controller_update_firmware_flag(data)
    if flag is False and installed:
        return installed

    return reported_latest


def _controller_release_summary(data: dict[str, Any]) -> str | None:
    installed = _controller_installed(data)
    reported_latest = _controller_latest(data)
    if not installed or not reported_latest:
        return None

    flag = _controller_update_firmware_flag(data)
    if flag is False and installed != reported_latest:
        return f"Latest reported by controller: {reported_latest}"

    return None


def _module_refs(data: dict[str, Any], serial_for_ids: str) -> list[_UpdateRef]:
    refs: list[_UpdateRef] = []

    def _swstat_indicates_update(swstat: str | None) -> bool | None:
        if not swstat:
            return None
        t = swstat.strip().upper()
        if not t:
            return None
        if t == "OK":
            return False
        if "UPDATE" in t or t.startswith("UPD"):
            return True
        return None

    mconf_modules = _config_mconf_modules(data)
    if mconf_modules:
        # When config is available, prefer it because it includes authoritative
        # update flags (mconf[].update/updateStat). Config is sourced from /rest/config.
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

                reported_latest_any: Any = status_module.get(
                    "latestFirmware"
                ) or status_module.get("latestSw")
                reported_latest = (
                    str(reported_latest_any).strip() or None
                    if reported_latest_any is not None
                    else None
                )

                mconf_module = _find_mconf_module(
                    _data, hwtype=hwtype, module_id=module_id
                )
                update_any: Any = (mconf_module or {}).get("update")
                update_flag = update_any if isinstance(update_any, bool) else None

                # If config explicitly says there is no update, suppress any
                # reported "latest" so HA shows state=off.
                if update_flag is False and installed:
                    return installed

                # If an update is available but no version is provided, expose
                # a placeholder so HA can represent availability.
                if update_flag is True and reported_latest is None:
                    return "Update available"

                # If the module doesn't report a latest version and config is
                # unavailable, assume up-to-date so HA doesn't show "unknown".
                if update_flag is None and reported_latest is None and installed:
                    return installed

                return reported_latest

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

                installed = _installed_from_status_fn(
                    _data, hwtype=hwtype, module_id=module_id
                )

                mconf_module = _find_mconf_module(
                    _data, hwtype=hwtype, module_id=module_id
                )
                update_stat_any: Any = (mconf_module or {}).get("updateStat")
                if isinstance(update_stat_any, int) and update_stat_any:
                    return f"updateStat={update_stat_any}"

                update_any: Any = (mconf_module or {}).get("update")
                if isinstance(update_any, bool) and update_any is False and installed:
                    reported_latest_any: Any = status_module.get(
                        "latestFirmware"
                    ) or status_module.get("latestSw")
                    reported_latest = (
                        str(reported_latest_any).strip() or None
                        if reported_latest_any is not None
                        else None
                    )
                    if reported_latest and installed != reported_latest:
                        return f"Latest reported by controller: {reported_latest}"

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

                v: Any = m.get("latestFirmware") or m.get("latestSw")
                reported_latest = str(v).strip() or None if v is not None else None
                if reported_latest is not None:
                    return reported_latest

                installed = _installed_fn(_data, module_id=module_id, hwtype=hwtype)
                sw_any: Any = m.get("swstat")
                sw = str(sw_any) if sw_any is not None else None
                update_signal = _swstat_indicates_update(sw)

                if update_signal is True:
                    return "Update available"
                if installed:
                    return installed
                return None
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

        refs.append(
            _UpdateRef(
                unique_id=f"{serial_for_ids}_update_{module_id}".lower(),
                name="Firmware",
                installed_fn=_installed_fn,
                latest_fn=_latest_fn,
                release_summary_fn=_release_summary_fn,
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
        latest_fn=_controller_latest_effective,
        release_summary_fn=_controller_release_summary,
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

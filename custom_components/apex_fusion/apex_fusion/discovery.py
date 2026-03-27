"""Entity discovery helpers for Apex Fusion.

Entity platforms should avoid interpreting coordinator payloads directly.
This module centralizes schema-tolerant extraction of entity references
(lightweight dataclasses describing what to create).

This module does not perform network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, cast

from .outputs import OutletMode, friendly_outlet_name
from .probes import friendly_probe_name

# -----------------------------------------------------------------------------
# Entity References
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeRef:
    """Reference to a non-digital probe sensor.

    Attributes:
        key: Probe key from the controller payload.
        name: Friendly name for display in Home Assistant.
    """

    key: str
    name: str


@dataclass(frozen=True)
class DigitalProbeRef:
    """Reference to a digital probe (open/closed) binary sensor.

    Attributes:
        key: Probe key from the controller payload.
        name: Friendly name for display in Home Assistant.
    """

    key: str
    name: str


@dataclass(frozen=True)
class OutletIntensityRef:
    """Reference to an outlet intensity sensor.

    Attributes:
        did: Outlet device id from the controller payload.
        name: Friendly name for display in Home Assistant.
    """

    did: str
    name: str
    dedupe_key: str


@dataclass(frozen=True)
class OutletRef:
    """Reference to an outlet mode SelectEntity.

    Attributes:
        did: Outlet device id from the controller payload.
        name: Friendly name for display in Home Assistant.
    """

    did: str
    name: str
    dedupe_key: str


@dataclass(frozen=True)
class OutletDoserRemainingRef:
    """Reference to a doser remaining-volume sensor.

    Attributes:
        did: Outlet device id from the controller payload.
        name: Friendly name for display in Home Assistant.
        dedupe_key: Stable dedupe key used in unique_id/object_id generation.
    """

    did: str
    name: str
    dedupe_key: str


@dataclass(frozen=True)
class OutletDoserCapacityRef:
    """Reference to a doser capacity sensor.

    Attributes:
        did: Outlet device id from the controller payload.
        name: Friendly name for display in Home Assistant.
        dedupe_key: Stable dedupe key used in unique_id/object_id generation.
    """

    did: str
    name: str
    dedupe_key: str


# -----------------------------------------------------------------------------
# Discovery
# -----------------------------------------------------------------------------


class ApexDiscovery:
    """Discover entities from coordinator data.

    Methods return (new_refs, new_ids) so callers can maintain per-platform
    deduplication without this module mutating caller-owned sets.
    """

    @staticmethod
    def new_probe_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_keys: set[str],
    ) -> tuple[list[ProbeRef], set[str]]:
        """Discover new non-digital probes.

        Args:
            data: Coordinator data.
            already_added_keys: Keys that have already been used to create
                entities.

        Returns:
            Tuple of:
              - A list of discovered probe references.
              - A set of probe keys discovered during this call.
        """

        coordinator_data = data or {}
        probes_any: Any = coordinator_data.get("probes")
        if not isinstance(probes_any, dict):
            return [], set()

        refs: list[ProbeRef] = []
        seen: set[str] = set()

        for key, probe_any in cast(dict[str, Any], probes_any).items():
            key_str = str(key)
            if not key_str or key_str in already_added_keys or key_str in seen:
                continue
            probe: dict[str, Any] = (
                cast(dict[str, Any], probe_any) if isinstance(probe_any, dict) else {}
            )
            probe_type = str(probe.get("type") or "")
            if probe_type.strip().lower() == "digital":
                seen.add(key_str)
                continue

            probe_name = str(probe.get("name") or key_str)
            refs.append(
                ProbeRef(
                    key=key_str,
                    name=friendly_probe_name(name=probe_name, probe_type=probe_type),
                )
            )
            seen.add(key_str)

        return refs, seen

    @staticmethod
    def new_digital_probe_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_keys: set[str],
    ) -> tuple[list[DigitalProbeRef], set[str]]:
        """Discover new digital probes.

        Args:
            data: Coordinator data.
            already_added_keys: Keys that have already been used to create
                entities.

        Returns:
            Tuple of:
              - A list of discovered digital probe references.
              - A set of probe keys discovered during this call.
        """

        coordinator_data = data or {}
        probes_any: Any = coordinator_data.get("probes")
        if not isinstance(probes_any, dict):
            return [], set()

        refs: list[DigitalProbeRef] = []
        seen: set[str] = set()

        for key, probe_any in cast(dict[str, Any], probes_any).items():
            key_str = str(key)
            if not key_str or key_str in already_added_keys or key_str in seen:
                continue
            if not isinstance(probe_any, Mapping):
                continue

            probe = cast(Mapping[str, Any], probe_any)
            probe_type = str(probe.get("type") or "").strip().lower()
            if probe_type != "digital":
                continue

            probe_name = str(probe.get("name") or key_str).strip() or key_str
            friendly = probe_name.replace("_", " ").strip()

            refs.append(DigitalProbeRef(key=key_str, name=friendly))
            seen.add(key_str)

        return refs, seen

    @staticmethod
    def new_outlet_intensity_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_dids: set[str],
    ) -> tuple[list[OutletIntensityRef], set[str]]:
        """Discover new outlet intensity sensors.

        Args:
            data: Coordinator data.
            already_added_dids: Outlet DIDs that have already been used to
                create entities.

        Returns:
            Tuple of:
              - A list of discovered outlet intensity references.
              - A set of outlet DIDs discovered during this call.
        """

        coordinator_data = data or {}
        outlets_any: Any = coordinator_data.get("outlets")
        if not isinstance(outlets_any, list):
            return [], set()

        # Preserve stable unique_ids when DIDs are unique by only suffixing
        # identifiers that actually collide within this payload.
        did_counts: dict[str, int] = {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue
            did_any: Any = cast(Mapping[str, Any], outlet_any).get("device_id")
            if isinstance(did_any, str) and did_any:
                did_counts[did_any] = did_counts.get(did_any, 0) + 1

        refs: list[OutletIntensityRef] = []
        seen: set[str] = set()

        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue

            outlet = cast(Mapping[str, Any], outlet_any)
            did_any: Any = outlet.get("device_id")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue

            module_abaddr_any: Any = outlet.get("module_abaddr")
            module_abaddr = (
                module_abaddr_any if isinstance(module_abaddr_any, int) else None
            )
            module_hwtype_any: Any = outlet.get("module_hwtype")
            module_hwtype = (
                str(module_hwtype_any).strip().upper()
                if isinstance(module_hwtype_any, str) and module_hwtype_any.strip()
                else None
            )

            if did_counts.get(did, 0) > 1:
                # DIDs can collide (e.g. Trident-family), so suffix with module
                # identity for stable deduping.
                if module_abaddr is not None:
                    dedupe_key = f"{did}@{module_abaddr}"
                elif module_hwtype:
                    dedupe_key = f"{did}@{module_hwtype}"
                else:
                    dedupe_key = did
            else:
                dedupe_key = did

            if dedupe_key in already_added_dids or dedupe_key in seen:
                continue

            intensity_any: Any = outlet.get("intensity")
            if not isinstance(intensity_any, (int, float)) or isinstance(
                intensity_any, bool
            ):
                continue

            outlet_type_any: Any = outlet.get("type")
            outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
            outlet_name = friendly_outlet_name(
                outlet_name=str(outlet.get("name") or did),
                outlet_type=outlet_type,
            )

            refs.append(
                OutletIntensityRef(
                    did=did,
                    name=f"{outlet_name} Intensity",
                    dedupe_key=dedupe_key,
                )
            )
            seen.add(dedupe_key)

        # NOTE: returned set contains dedupe keys, not raw DIDs.
        return refs, seen

    @staticmethod
    def new_outlet_select_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_dids: set[str],
    ) -> tuple[list[OutletRef], set[str]]:
        """Discover new outlet select references.

        Args:
            data: Coordinator data.
            already_added_dids: Outlet DIDs that have already been used to
                create entities.

        Returns:
            Tuple of:
              - A list of discovered outlet references.
              - A set of outlet DIDs discovered during this call.
        """

        coordinator_data = data or {}
        outlets_any: Any = coordinator_data.get("outlets")
        if not isinstance(outlets_any, list):
            return [], set()

        did_counts: dict[str, int] = {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue
            did_any: Any = cast(Mapping[str, Any], outlet_any).get("device_id")
            if isinstance(did_any, str) and did_any:
                did_counts[did_any] = did_counts.get(did_any, 0) + 1

        refs: list[OutletRef] = []
        seen: set[str] = set()

        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue

            outlet = cast(dict[str, Any], outlet_any)
            did_any: Any = outlet.get("device_id")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue

            module_abaddr_any: Any = outlet.get("module_abaddr")
            module_abaddr = (
                module_abaddr_any if isinstance(module_abaddr_any, int) else None
            )
            module_hwtype_any: Any = outlet.get("module_hwtype")
            module_hwtype = (
                str(module_hwtype_any).strip().upper()
                if isinstance(module_hwtype_any, str) and module_hwtype_any.strip()
                else None
            )

            if did_counts.get(did, 0) > 1:
                if module_abaddr is not None:
                    dedupe_key = f"{did}@{module_abaddr}"
                elif module_hwtype:
                    dedupe_key = f"{did}@{module_hwtype}"
                else:
                    dedupe_key = did
            else:
                dedupe_key = did

            if dedupe_key in already_added_dids or dedupe_key in seen:
                continue
            if not OutletMode.is_selectable_outlet(outlet):
                continue

            outlet_type_any: Any = outlet.get("type")
            outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
            outlet_name = friendly_outlet_name(
                outlet_name=str(outlet.get("name") or did),
                outlet_type=outlet_type,
            )

            refs.append(OutletRef(did=did, name=outlet_name, dedupe_key=dedupe_key))
            seen.add(dedupe_key)

        # NOTE: returned set contains dedupe keys, not raw DIDs.
        return refs, seen

    @staticmethod
    def new_outlet_doser_remaining_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_dids: set[str],
    ) -> tuple[list[OutletDoserRemainingRef], set[str]]:
        """Discover new doser remaining-volume sensors.

        This targets DOS and DOS Quiet Drive (DQD) outputs that expose
        `doser_remaining_ml` in coordinator-normalized outlet dicts.

        Args:
            data: Coordinator data.
            already_added_dids: Outlet DIDs that have already been used to
                create entities.

        Returns:
            Tuple of:
              - A list of discovered doser remaining-volume references.
              - A set of outlet DIDs discovered during this call.
        """

        coordinator_data = data or {}
        outlets_any: Any = coordinator_data.get("outlets")
        if not isinstance(outlets_any, list):
            return [], set()

        did_counts: dict[str, int] = {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue
            did_any: Any = cast(Mapping[str, Any], outlet_any).get("device_id")
            if isinstance(did_any, str) and did_any:
                did_counts[did_any] = did_counts.get(did_any, 0) + 1

        refs: list[OutletDoserRemainingRef] = []
        seen: set[str] = set()

        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue

            outlet = cast(Mapping[str, Any], outlet_any)
            did_any: Any = outlet.get("device_id")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue

            module_abaddr_any: Any = outlet.get("module_abaddr")
            module_abaddr = (
                module_abaddr_any if isinstance(module_abaddr_any, int) else None
            )
            module_hwtype_any: Any = outlet.get("module_hwtype")
            module_hwtype = (
                str(module_hwtype_any).strip().upper()
                if isinstance(module_hwtype_any, str) and module_hwtype_any.strip()
                else None
            )

            if did_counts.get(did, 0) > 1:
                if module_abaddr is not None:
                    dedupe_key = f"{did}@{module_abaddr}"
                elif module_hwtype:
                    dedupe_key = f"{did}@{module_hwtype}"
                else:
                    dedupe_key = did
            else:
                dedupe_key = did

            if dedupe_key in already_added_dids or dedupe_key in seen:
                continue

            outlet_type_any: Any = outlet.get("type")
            outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
            if str(outlet_type or "").strip().lower() not in {"dos", "dqd"}:
                continue

            remaining_any: Any = outlet.get("doser_remaining_ml")
            if not isinstance(remaining_any, (int, float)) or isinstance(
                remaining_any, bool
            ):
                continue

            outlet_name = friendly_outlet_name(
                outlet_name=str(outlet.get("name") or did),
                outlet_type=outlet_type,
            )

            refs.append(
                OutletDoserRemainingRef(
                    did=did,
                    name=f"{outlet_name} Remaining Volume",
                    dedupe_key=dedupe_key,
                )
            )
            seen.add(dedupe_key)

        # NOTE: returned set contains dedupe keys, not raw DIDs.
        return refs, seen

    @staticmethod
    def new_outlet_doser_capacity_refs(
        data: Mapping[str, Any] | None,
        *,
        already_added_dids: set[str],
    ) -> tuple[list[OutletDoserCapacityRef], set[str]]:
        """Discover new doser capacity sensors.

        This targets DOS and DOS Quiet Drive (DQD) outputs that expose
        `doser_capacity_ml` in coordinator-normalized outlet dicts.
        """

        coordinator_data = data or {}
        outlets_any: Any = coordinator_data.get("outlets")
        if not isinstance(outlets_any, list):
            return [], set()

        did_counts: dict[str, int] = {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue
            did_any: Any = cast(Mapping[str, Any], outlet_any).get("device_id")
            if isinstance(did_any, str) and did_any:
                did_counts[did_any] = did_counts.get(did_any, 0) + 1

        refs: list[OutletDoserCapacityRef] = []
        seen: set[str] = set()

        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, Mapping):
                continue

            outlet = cast(Mapping[str, Any], outlet_any)
            did_any: Any = outlet.get("device_id")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue

            module_abaddr_any: Any = outlet.get("module_abaddr")
            module_abaddr = (
                module_abaddr_any if isinstance(module_abaddr_any, int) else None
            )
            module_hwtype_any: Any = outlet.get("module_hwtype")
            module_hwtype = (
                str(module_hwtype_any).strip().upper()
                if isinstance(module_hwtype_any, str) and module_hwtype_any.strip()
                else None
            )

            if did_counts.get(did, 0) > 1:
                if module_abaddr is not None:
                    dedupe_key = f"{did}@{module_abaddr}"
                elif module_hwtype:
                    dedupe_key = f"{did}@{module_hwtype}"
                else:
                    dedupe_key = did
            else:
                dedupe_key = did

            if dedupe_key in already_added_dids or dedupe_key in seen:
                continue

            outlet_type_any: Any = outlet.get("type")
            outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
            if str(outlet_type or "").strip().lower() not in {"dos", "dqd"}:
                continue

            capacity_any: Any = outlet.get("doser_capacity_ml")
            if not isinstance(capacity_any, (int, float)) or isinstance(
                capacity_any, bool
            ):
                continue

            outlet_name = friendly_outlet_name(
                outlet_name=str(outlet.get("name") or did),
                outlet_type=outlet_type,
            )

            refs.append(
                OutletDoserCapacityRef(
                    did=did,
                    name=f"{outlet_name} Capacity",
                    dedupe_key=dedupe_key,
                )
            )
            seen.add(dedupe_key)

        # NOTE: returned set contains dedupe keys, not raw DIDs.
        return refs, seen

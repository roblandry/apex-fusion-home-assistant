"""Internal Apex Fusion domain package.

This package centralizes Apex-specific behavior so Home Assistant platform files
can stay small and focused.

The package provides:
    - Identity/context helpers (host/meta/serial/tank slug)
    - Schema-tolerant payload extraction helpers
    - Conservative module candidate selection (no guessing)
    - Entity discovery helpers that yield lightweight reference objects
"""

from __future__ import annotations

# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
from .context import ApexFusionContext
from .data_fields import section_field
from .discovery import (
    ApexDiscovery,
    DigitalProbeRef,
    OutletIntensityRef,
    OutletRef,
    ProbeRef,
)
from .extract import (
    RAW_CONTAINER_KEYS,
    find_in_raw_containers,
    iter_present_module_items,
    mconf_modules_from_data,
    raw_modules_from_data,
    raw_modules_from_raw,
    raw_nstat_from_data,
)
from .inputs import DigitalValueCodec
from .modules import best_module_candidates_by_abaddr, hwtype_from_module
from .network import network_bool, network_field
from .outputs import OutletMode
from .probes import ProbeMetaResolver, as_float, units_and_meta
from .trident import (
    trident_field_by_abaddr,
    trident_is_testing,
    trident_is_testing_by_abaddr,
    trident_level_ml,
    trident_level_ml_by_abaddr,
    trident_reagent_empty,
    trident_reagent_empty_by_abaddr,
    trident_waste_full,
    trident_waste_full_by_abaddr,
)
from .util import to_int

__all__ = [
    "ApexDiscovery",
    "ApexFusionContext",
    "DigitalProbeRef",
    "DigitalValueCodec",
    "OutletIntensityRef",
    "OutletMode",
    "OutletRef",
    "ProbeMetaResolver",
    "ProbeRef",
    "RAW_CONTAINER_KEYS",
    "as_float",
    "best_module_candidates_by_abaddr",
    "find_in_raw_containers",
    "hwtype_from_module",
    "iter_present_module_items",
    "mconf_modules_from_data",
    "network_bool",
    "network_field",
    "raw_modules_from_data",
    "raw_modules_from_raw",
    "raw_nstat_from_data",
    "section_field",
    "to_int",
    "trident_is_testing",
    "trident_is_testing_by_abaddr",
    "trident_field_by_abaddr",
    "trident_level_ml",
    "trident_level_ml_by_abaddr",
    "trident_reagent_empty",
    "trident_reagent_empty_by_abaddr",
    "trident_waste_full",
    "trident_waste_full_by_abaddr",
    "units_and_meta",
]

"""Trident-specific helpers.

These helpers operate on the coordinator's `data["trident"]` section.
"""

from typing import Any, Callable, cast

# -----------------------------------------------------------------------------
# Status / booleans
# -----------------------------------------------------------------------------


def trident_is_testing(data: dict[str, Any]) -> bool | None:
    """Return whether the Trident is currently testing.

    Args:
        data: Coordinator data dict.

    Returns:
        `True/False` when present, otherwise `None`.
    """
    trident_any: Any = data.get("trident")
    if not isinstance(trident_any, dict):
        return None
    trident = cast(dict[str, Any], trident_any)
    value: Any = trident.get("is_testing")
    if isinstance(value, bool):
        return value
    return None


def trident_is_testing_by_abaddr(
    trident_abaddr: int,
) -> Callable[[dict[str, Any]], bool | None]:
    def _get(data: dict[str, Any]) -> bool | None:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            if t.get("abaddr") != trident_abaddr:
                continue
            value: Any = t.get("is_testing")
            return value if isinstance(value, bool) else None
        return None

    return _get


def trident_present_by_abaddr(
    trident_abaddr: int,
) -> Callable[[dict[str, Any]], bool | None]:
    """Return whether a Trident-family module is reported present.

    This reads from the multi-module `data["tridents"]` list.

    Args:
        trident_abaddr: Aquabus address.

    Returns:
        `True/False` when present, otherwise `None`.
    """

    def _get(data: dict[str, Any]) -> bool | None:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            if t.get("abaddr") != trident_abaddr:
                continue
            value: Any = t.get("present")
            return value if isinstance(value, bool) else None
        return None

    return _get


def trident_waste_full(data: dict[str, Any]) -> bool | None:
    """Return whether the Trident waste container is full.

    Args:
        data: Coordinator data dict.

    Returns:
        `True/False` when present, otherwise `None`.
    """
    trident_any: Any = data.get("trident")
    if not isinstance(trident_any, dict):
        return None
    trident = cast(dict[str, Any], trident_any)
    value: Any = trident.get("waste_full")
    if isinstance(value, bool):
        return value
    return None


def trident_waste_full_by_abaddr(
    trident_abaddr: int,
) -> Callable[[dict[str, Any]], bool | None]:
    def _get(data: dict[str, Any]) -> bool | None:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            if t.get("abaddr") != trident_abaddr:
                continue
            value: Any = t.get("waste_full")
            return value if isinstance(value, bool) else None
        return None

    return _get


def trident_reagent_empty(field: str) -> Callable[[dict[str, Any]], bool | None]:
    """Build an extractor for a reagent-empty flag.

    Args:
        field: Key within the `trident` section (e.g. `reagent_a_empty`).

    Returns:
        Callable that returns `bool | None`.
    """

    def _get(data: dict[str, Any]) -> bool | None:
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return None
        trident = cast(dict[str, Any], trident_any)
        value: Any = trident.get(field)
        if isinstance(value, bool):
            return value
        return None

    return _get


def trident_reagent_empty_by_abaddr(
    trident_abaddr: int, field: str
) -> Callable[[dict[str, Any]], bool | None]:
    def _get(data: dict[str, Any]) -> bool | None:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            if t.get("abaddr") != trident_abaddr:
                continue
            value: Any = t.get(field)
            return value if isinstance(value, bool) else None
        return None

    return _get


def trident_level_ml(index: int) -> Callable[[dict[str, Any]], Any]:
    """Build an extractor for a Trident container level by index.

    Args:
        index: Index into the `levels_ml` list.

    Returns:
        Callable that accepts coordinator `data` and returns the indexed level
        value when present.
    """

    def _get(data: dict[str, Any]) -> Any:
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return None
        trident = cast(dict[str, Any], trident_any)
        levels_any: Any = trident.get("levels_ml")
        if not isinstance(levels_any, list):
            return None
        levels = cast(list[Any], levels_any)
        if index < 0 or index >= len(levels):
            return None
        return levels[index]

    return _get


def trident_level_ml_by_abaddr(
    trident_abaddr: int, index: int
) -> Callable[[dict[str, Any]], Any]:
    """Build an extractor for a Trident container level for a specific module.

    Args:
        trident_abaddr: Aquabus address of the Trident-family module.
        index: Index into the `levels_ml` list.

    Returns:
        Callable that accepts coordinator `data` and returns the indexed level
        value for the matching Trident module when present.
    """

    def _get(data: dict[str, Any]) -> Any:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            abaddr_any: Any = t.get("abaddr")
            if abaddr_any != trident_abaddr:
                continue
            levels_any: Any = t.get("levels_ml")
            if not isinstance(levels_any, list):
                return None
            levels = cast(list[Any], levels_any)
            if index < 0 or index >= len(levels):
                return None
            return levels[index]
        return None

    return _get


def trident_field_by_abaddr(
    trident_abaddr: int, field: str
) -> Callable[[dict[str, Any]], Any]:
    """Build an extractor for a single Trident field for a specific module.

    Args:
        trident_abaddr: Aquabus address of the Trident-family module.
        field: Key to fetch from the Trident dict (e.g. "status").

    Returns:
        Callable that accepts coordinator `data` and returns the field value
        for the matching Trident module when present.
    """

    def _get(data: dict[str, Any]) -> Any:
        tridents_any: Any = data.get("tridents")
        if not isinstance(tridents_any, list):
            return None
        for item_any in cast(list[Any], tridents_any):
            if not isinstance(item_any, dict):
                continue
            t = cast(dict[str, Any], item_any)
            abaddr_any: Any = t.get("abaddr")
            if abaddr_any != trident_abaddr:
                continue
            return t.get(field)
        return None

    return _get

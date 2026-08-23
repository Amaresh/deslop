"""Default adapter discovery for the engineering rules package."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..engine import RulesAdapter


class _AdapterLike(Protocol):
    adapter_key: str


class _AdapterCollector:
    def __init__(self) -> None:
        self._adapters: dict[str, _AdapterLike] = {}

    def register(self, adapter: _AdapterLike, *, source: str | None = None) -> None:
        raw_adapter_key = getattr(adapter, "adapter_key", None)
        adapter_key = raw_adapter_key.strip() if isinstance(raw_adapter_key, str) else None
        source_suffix = f" from {source}" if source else ""

        if not adapter_key:
            raise ValueError("Default rules adapters must define a non-empty adapter_key")
        if not callable(getattr(adapter, "run", None)):
            raise TypeError(
                f"Default rules adapter {adapter_key!r}{source_suffix} must define a callable run()"
            )
        if adapter_key in self._adapters:
            raise ValueError(
                f"Duplicate default adapter registration for {adapter_key!r}{source_suffix}"
            )
        self._adapters[adapter_key] = adapter

    def extend(self, adapters: Iterable[_AdapterLike], *, source: str | None = None) -> None:
        for adapter in adapters:
            self.register(adapter, source=source)

    def as_tuple(self) -> tuple[RulesAdapter, ...]:
        return tuple(self._adapters.values())  # type: ignore[return-value]


def _iter_default_adapter_modules(package_name: str) -> Iterable[object]:
    package = importlib.import_module(package_name)
    package_paths = getattr(package, "__path__", None)
    if not package_paths:
        return ()

    modules: list[object] = []
    for module_info in sorted(pkgutil.iter_modules(package_paths), key=lambda item: item.name):
        if module_info.name.startswith("_"):
            continue
        modules.append(importlib.import_module(f"{package_name}.{module_info.name}"))
    return tuple(modules)


def load_default_adapters(
    *, package_name: str = "engineering_rules.adapters"
) -> tuple[RulesAdapter, ...]:
    """Load default adapters from module-local registrations in an adapters package."""

    collector = _AdapterCollector()
    for module in _iter_default_adapter_modules(package_name):
        default_adapters = getattr(module, "DEFAULT_ADAPTERS", None)
        if default_adapters is not None:
            collector.extend(default_adapters, source=module.__name__)

        register_default_adapters = getattr(module, "register_default_adapters", None)
        if callable(register_default_adapters):
            module_name = module.__name__
            register_default_adapters(
                lambda adapter, *, _module_name=module_name: collector.register(
                    adapter, source=_module_name
                )
            )

    return collector.as_tuple()

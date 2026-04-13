"""
Check registry and base class.

To add a new check, create a module in this package that subclasses
``BaseCheck`` and decorate it with ``@register``.  The orchestrator
discovers all registered checks automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from bhapi.client import BHSession


@dataclass
class CheckResult:
    """Structured output from a single check."""

    check_id: str
    title: str
    description: str
    headers: list[str]
    rows: list[list[str]]
    severity: str = "info"  # info | low | medium | high | critical
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.rows)


class BaseCheck(ABC):
    """
    Every check must implement ``run()`` and set the class-level
    ``check_id``, ``title``, and ``description`` attributes.
    """

    check_id: str = ""
    title: str = ""
    description: str = ""

    @abstractmethod
    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        ...


_REGISTRY: list[type[BaseCheck]] = []


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Class decorator that adds a check to the global registry."""
    _REGISTRY.append(cls)
    return cls


def get_all_checks() -> list[BaseCheck]:
    """Return an instance of every registered check."""
    return [cls() for cls in _REGISTRY]


# Import all check modules so their @register decorators fire.
from checks import outbound_control, kerberoastable, asrep_roastable, large_group_admin  # noqa: E402, F401

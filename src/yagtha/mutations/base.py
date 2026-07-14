"""Mutation interface and registry.

A mutation turns one event into a new event that keeps the same behaviour
but changes a detail an attacker controls (file name, path, case...).
Every mutation is a pure function: the input event is never modified, and
the output only depends on the input (no randomness), so runs are
reproducible.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from yagtha.errors import YagthaError
from yagtha.models import Event, Variant

MAX_VARIANTS = 100

# Returns the mutated event, or None when the mutation does not apply.
MutationFunc = Callable[[dict[str, object]], dict[str, object] | None]


class UnknownMutationError(YagthaError):
    """A mutation name was requested that is not registered."""


@dataclass(frozen=True)
class Mutation:
    """A named, documented, behaviour-preserving change to an event."""

    name: str
    description: str
    func: MutationFunc

    def apply(self, event: Event) -> dict[str, object] | None:
        """Return a mutated copy of ``event``, or None if not applicable."""
        working = copy.deepcopy(dict(event))
        result = self.func(working)
        if result is None or result == dict(event):
            return None
        return result


_REGISTRY: dict[str, Mutation] = {}


def register(name: str, description: str) -> Callable[[MutationFunc], MutationFunc]:
    """Decorator that adds a mutation function to the registry."""

    def decorator(func: MutationFunc) -> MutationFunc:
        if name in _REGISTRY:
            raise ValueError(f"mutation '{name}' is already registered")
        _REGISTRY[name] = Mutation(name=name, description=description, func=func)
        return func

    return decorator


def list_mutations() -> tuple[Mutation, ...]:
    """All registered mutations, sorted by name."""
    return tuple(_REGISTRY[name] for name in sorted(_REGISTRY))


def get_mutation(name: str) -> Mutation:
    """Look up one mutation by name."""
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise UnknownMutationError(f"unknown mutation '{name}' (known: {known})") from None


def generate_variants(
    event: Event,
    names: Iterable[str] | None = None,
    max_variants: int = MAX_VARIANTS,
) -> list[Variant]:
    """Apply each mutation once and return the variants that apply.

    The untouched event comes first as the ``original`` variant.
    """
    mutations = list_mutations() if names is None else tuple(get_mutation(n) for n in names)
    variants = [Variant(mutation_name="original", event=copy.deepcopy(dict(event)))]
    for mutation in mutations:
        if len(variants) > max_variants:
            raise YagthaError(f"more than {max_variants} variants requested")
        mutated = mutation.apply(event)
        if mutated is not None:
            variants.append(Variant(mutation_name=mutation.name, event=mutated))
    return variants

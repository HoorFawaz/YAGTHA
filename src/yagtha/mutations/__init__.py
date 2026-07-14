"""Behaviour-preserving mutations of events.

Importing this package registers every built-in mutation.
"""

from yagtha.mutations import powershell, process
from yagtha.mutations.base import (
    MAX_VARIANTS,
    Mutation,
    UnknownMutationError,
    generate_variants,
    get_mutation,
    list_mutations,
)

__all__ = [
    "MAX_VARIANTS",
    "Mutation",
    "UnknownMutationError",
    "generate_variants",
    "get_mutation",
    "list_mutations",
    "powershell",
    "process",
]

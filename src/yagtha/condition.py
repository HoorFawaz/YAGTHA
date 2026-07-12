"""Parser and evaluator for the Sigma ``condition`` expression.

Supported grammar (lowest to highest precedence)::

    expr    := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= "not" not_expr | primary
    primary := "(" expr ")" | ("1" | "all") "of" target | NAME
    target  := "them" | NAME   (NAME may contain * wildcards)

Aggregations (``| count() > 5``) and ``N of`` with N other than 1 are not
supported and raise ``UnsupportedRuleFeatureError``.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from yagtha.errors import RuleValidationError, UnsupportedRuleFeatureError

MAX_CONDITION_LENGTH = 2_000
MAX_NESTING_DEPTH = 32

_TOKEN_RE = re.compile(r"\s*(?:(\()|(\))|(\|)|([A-Za-z0-9_\-.*]+))")
_KEYWORDS = frozenset({"and", "or", "not", "of", "them"})


@dataclass(frozen=True)
class Ref:
    """Reference to one selection by name."""

    name: str


@dataclass(frozen=True)
class Not:
    """Logical negation."""

    child: Node


@dataclass(frozen=True)
class And:
    """All children must be true."""

    children: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    """At least one child must be true."""

    children: tuple[Node, ...]


@dataclass(frozen=True)
class Of:
    """``1 of`` (any) or ``all of`` a group of selections."""

    require_all: bool
    names: tuple[str, ...]


Node = Ref | Not | And | Or | Of


def parse_condition(text: str, selection_names: Iterable[str]) -> Node:
    """Parse a condition string and check it only references known selections."""
    if len(text) > MAX_CONDITION_LENGTH:
        raise RuleValidationError(f"condition is longer than {MAX_CONDITION_LENGTH} characters")
    parser = _Parser(_tokenize(text), tuple(selection_names))
    node = parser.parse_expression(depth=0)
    if not parser.at_end():
        raise RuleValidationError(f"unexpected '{parser.peek()}' in condition: {text!r}")
    return node


def evaluate_condition(node: Node, results: Mapping[str, bool]) -> bool:
    """Evaluate a parsed condition given the result of every selection."""
    if isinstance(node, Ref):
        return results[node.name]
    if isinstance(node, Not):
        return not evaluate_condition(node.child, results)
    if isinstance(node, And):
        return all(evaluate_condition(child, results) for child in node.children)
    if isinstance(node, Or):
        return any(evaluate_condition(child, results) for child in node.children)
    values = [results[name] for name in node.names]
    return all(values) if node.require_all else any(values)


def explain_condition(node: Node, results: Mapping[str, bool]) -> tuple[str, ...]:
    """Return the selections responsible for the condition's current value.

    When the condition is false, these are the selections that made it fail:
    a selection that did not match, or a negated filter that did match.
    """
    outcome = evaluate_condition(node, results)
    names = _explain(node, results, outcome)
    return tuple(dict.fromkeys(names))


def _explain(node: Node, results: Mapping[str, bool], want: bool) -> list[str]:
    """Collect selection names that make ``node`` evaluate to ``want``."""
    if isinstance(node, Ref):
        return [node.name]
    if isinstance(node, Not):
        return _explain(node.child, results, not want)
    if isinstance(node, Of):
        if node.require_all == want:
            # "all of" is true, or "1 of" is false: every member counts.
            return list(node.names)
        return [name for name in node.names if results[name] == want]
    is_and = isinstance(node, And)
    names: list[str] = []
    for child in node.children:
        value = evaluate_condition(child, results)
        # An AND that holds and an OR that fails depend on every child;
        # otherwise only the children with the deciding value matter.
        if (is_and == want) or value == want:
            names.extend(_explain(child, results, value))
    return names


def _tokenize(text: str) -> list[str]:
    """Split a condition into tokens, rejecting unsupported characters."""
    tokens: list[str] = []
    position = 0
    stripped_end = len(text.rstrip())
    while position < stripped_end:
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise RuleValidationError(
                f"invalid character {text[position:].lstrip()[:1]!r} in condition: {text!r}"
            )
        if match.group(3):
            raise UnsupportedRuleFeatureError(
                "aggregations in conditions (the '|' operator) are not supported"
            )
        tokens.append(match.group(1) or match.group(2) or match.group(4))
        position = match.end()
    if not tokens:
        raise RuleValidationError("condition is empty")
    return tokens


class _Parser:
    """Recursive-descent parser over a token list."""

    def __init__(self, tokens: list[str], names: tuple[str, ...]) -> None:
        self._tokens = tokens
        self._index = 0
        self._names = names

    def at_end(self) -> bool:
        return self._index >= len(self._tokens)

    def peek(self) -> str | None:
        return None if self.at_end() else self._tokens[self._index]

    def _next(self) -> str:
        token = self.peek()
        if token is None:
            raise RuleValidationError("condition ends unexpectedly")
        self._index += 1
        return token

    def parse_expression(self, depth: int) -> Node:
        if depth > MAX_NESTING_DEPTH:
            raise RuleValidationError(f"condition is nested deeper than {MAX_NESTING_DEPTH}")
        children = [self._parse_and(depth)]
        while self.peek() == "or":
            self._next()
            children.append(self._parse_and(depth))
        return children[0] if len(children) == 1 else Or(tuple(children))

    def _parse_and(self, depth: int) -> Node:
        children = [self._parse_not(depth)]
        while self.peek() == "and":
            self._next()
            children.append(self._parse_not(depth))
        return children[0] if len(children) == 1 else And(tuple(children))

    def _parse_not(self, depth: int) -> Node:
        if self.peek() == "not":
            self._next()
            return Not(self._parse_not(depth + 1))
        return self._parse_primary(depth)

    def _parse_primary(self, depth: int) -> Node:
        lexeme = self._next()
        if lexeme == "(":
            node = self.parse_expression(depth + 1)
            if self._next() != ")":
                raise RuleValidationError("missing ')' in condition")
            return node
        if lexeme == ")" or lexeme in _KEYWORDS:
            raise RuleValidationError(f"unexpected '{lexeme}' in condition")
        if self.peek() == "of":
            return self._parse_of(lexeme)
        if lexeme not in self._names:
            raise RuleValidationError(f"condition references unknown selection '{lexeme}'")
        return Ref(lexeme)

    def _parse_of(self, quantifier: str) -> Of:
        self._next()  # consume "of"
        if quantifier not in {"1", "all"}:
            raise UnsupportedRuleFeatureError(
                f"'{quantifier} of' is not supported; use '1 of' or 'all of'"
            )
        target = self._next()
        if target == "them":
            names = tuple(name for name in self._names if not name.startswith("_"))
        elif target in _KEYWORDS or target in {"(", ")"}:
            raise RuleValidationError(f"unexpected '{target}' after 'of'")
        else:
            names = tuple(name for name in self._names if fnmatch.fnmatchcase(name, target))
        if not names:
            raise RuleValidationError(f"'{quantifier} of {target}' matches no selection")
        return Of(require_all=quantifier == "all", names=names)

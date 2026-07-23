"""Exceptions raised by YAGTHA.

Every error a user can trigger with a bad rule or bad input is a subclass of
``YagthaError``, so the CLI can show a clear message instead of a traceback.
"""


class YagthaError(Exception):
    """Base class for all YAGTHA errors."""


class RuleParseError(YagthaError):
    """The rule file could not be read or is not valid YAML."""


class RuleValidationError(YagthaError):
    """The rule is valid YAML but is not a well-formed Sigma rule."""


class UnsupportedRuleFeatureError(YagthaError):
    """The rule uses a Sigma feature outside the supported subset.

    See ``docs/supported-sigma-subset.md``. YAGTHA never ignores such a
    feature silently, because that would give wrong results.
    """


class RuleEvaluationError(YagthaError):
    """A rule could not be evaluated safely on an event (for example a regex timeout)."""


class EventValidationError(YagthaError):
    """An events file is missing, too large, or not a list of flat JSON objects."""


class ExportError(YagthaError):
    """The export bundle cannot be written safely (for example a path outside output/)."""

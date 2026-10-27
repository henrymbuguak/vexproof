"""Typed exceptions. Every failure is explicit; nothing fails silently into a verdict."""


class VexproofError(Exception):
    """Base class for all vexproof errors."""


class ConfigError(VexproofError):
    """Invalid or missing configuration."""


class IngestError(VexproofError):
    """A repository, SBOM or profile could not be read."""


class IntelError(VexproofError):
    """A vulnerability-intelligence source returned unusable data."""

"""wafproof - validate your own detection rules against a labeled canary corpus.

Defensive tooling by Cognis Digital. wafproof never sends traffic anywhere; it
measures how well a detection function or regex ruleset catches known-bad inputs
while leaving benign look-alikes alone.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

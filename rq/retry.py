"""Retry configuration placeholder."""

from dataclasses import dataclass


@dataclass
class Retry:
    """Simple retry configuration matching RQ's API subset."""

    max: int = 0


"""Minimal subset of the ``rq`` package used for unit tests.

This lightweight implementation provides the few classes required by the
project's tests: :class:`Queue`, :class:`SimpleWorker` and :class:`Retry`.
It is **not** a full featured task queue but mimics enough behaviour for the
tests to execute without the real RQ dependency or a Redis server.
"""

from .queue import Queue
from .worker import SimpleWorker
from .retry import Retry

__all__ = ["Queue", "SimpleWorker", "Retry"]


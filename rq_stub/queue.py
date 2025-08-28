"""Simplified in-memory queue used for tests.

Jobs are stored in a list and executed synchronously by :class:`SimpleWorker`.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional
from .retry import Retry


class Job:
    def __init__(self, func: Callable[..., Any], args: tuple, kwargs: dict, retry: Optional[Retry]):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.retry = retry
        self.attempts = 0

    def perform(self) -> None:
        self.func(*self.args, **self.kwargs)


class Queue:
    def __init__(self, name: str = "default", connection: Any | None = None) -> None:
        self.name = name
        self.connection = connection
        self.jobs: List[Job] = []

    def enqueue(self, func: Callable[..., Any], *args: Any, retry: Retry | None = None, **kwargs: Any) -> Job:
        job = Job(func, args, kwargs, retry)
        self.jobs.append(job)
        return job


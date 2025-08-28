"""Very small synchronous worker used for tests."""

from __future__ import annotations

from typing import Iterable, List

from .queue import Job, Queue


class SimpleWorker:
    """Process jobs from the provided queues synchronously."""

    def __init__(self, queues: Iterable[Queue], connection=None) -> None:
        self.queues: List[Queue] = list(queues)
        self.connection = connection

    def work(self, burst: bool = True) -> None:
        for queue in self.queues:
            while queue.jobs:
                job: Job = queue.jobs.pop(0)
                try:
                    job.attempts += 1
                    job.perform()
                except Exception:
                    if job.retry and job.attempts <= job.retry.max:
                        queue.jobs.append(job)
                    else:
                        raise


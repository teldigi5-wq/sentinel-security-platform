"""Per-process admission control for costly full-history evidence scans.

This prevents overlapping scans and caps scan bursts from authenticated users.
It is NOT global/multi-process denial-of-service protection.
"""
from collections import deque
from contextlib import contextmanager
from threading import Lock
from time import monotonic


class IntegrityScanBusy(RuntimeError):
    pass


class IntegrityScanRateLimited(RuntimeError):
    pass


class IntegrityScanGuard:
    def __init__(self, *, limit=12, window_seconds=60.0, clock=monotonic):
        if type(limit) is not int or limit < 1 or window_seconds <= 0:
            raise ValueError("Invalid integrity admission policy")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._lock = Lock()
        self._in_flight = False
        self._starts = deque()

    @contextmanager
    def permit(self):
        with self._lock:
            now = self._clock()
            while self._starts and self._starts[0] <= now - self._window:
                self._starts.popleft()
            if self._in_flight:
                raise IntegrityScanBusy("Scan already in progress")
            if len(self._starts) >= self._limit:
                raise IntegrityScanRateLimited("Scan budget exhausted")
            self._in_flight = True
            self._starts.append(now)  # Failed scans consume budget.
        try:
            yield
        finally:
            with self._lock:
                self._in_flight = False

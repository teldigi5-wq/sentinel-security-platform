"""Small in-process abuse guard for authenticated sensor ingestion (v0.34).

Ported from PR #48 onto the cumulative v0.33 candidate and applied to every
signed sensor route (events and heartbeats share one quota per sensor).

This is defense in depth, NOT a distributed quota: each worker process keeps
its own counters and they reset on restart. Production deployments with
several workers or instances still need an ingress rate limiter in front.
"""
import math
from collections import OrderedDict, deque
from threading import Lock
from time import monotonic
from typing import Callable


class SensorIngestLimiter:
    def __init__(
        self,
        max_events: int = 300,
        window_seconds: float = 60.0,
        max_sensors: int = 512,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if max_events < 1 or window_seconds <= 0 or max_sensors < 1:
            raise ValueError("Rate limit bounds must be positive")
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.max_sensors = max_sensors
        self.clock = clock
        self._lock = Lock()
        self._windows: OrderedDict[str, deque[float]] = OrderedDict()

    @property
    def retry_after_seconds(self) -> int:
        return max(1, math.ceil(self.window_seconds))

    def allow(self, sensor_id: str) -> bool:
        """Count one signature-verified, not-yet-seen request for ``sensor_id``.

        Callers must authenticate the request and reject replayed nonces BEFORE
        calling this, otherwise forged or replayed traffic could burn a
        legitimate sensor's quota.
        """
        now = self.clock()
        with self._lock:
            timestamps = self._windows.get(sensor_id)
            if timestamps is None:
                timestamps = deque()
                self._windows[sensor_id] = timestamps
            else:
                self._windows.move_to_end(sensor_id)
            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if len(timestamps) >= self.max_events:
                return False
            timestamps.append(now)
            # Identity state is bounded; only configured (keyed) sensors reach
            # this point, so eviction cannot be driven by unauthenticated input.
            while len(self._windows) > self.max_sensors:
                self._windows.popitem(last=False)
            return True

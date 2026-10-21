"""Small in-process abuse guard for authenticated sensor ingestion.

This is defense in depth, NOT a distributed quota. Place a production ingress
rate limiter in front of multiple workers/instances and manage storage retention.
"""
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

    def allow(self, sensor_id: str) -> bool:
        """Count only signature-verified ingestion requests, one worker at a time."""
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
            while len(self._windows) > self.max_sensors:
                self._windows.popitem(last=False)
            return True

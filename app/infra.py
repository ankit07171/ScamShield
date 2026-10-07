"""Cache and rate limiter: Redis when REDIS_URL is set, in-process fallback otherwise."""
from __future__ import annotations

import json
import time


class Cache:
    def __init__(self, redis_url: str | None, ttl: int):
        self.ttl = ttl
        self._mem: dict[str, tuple[float, str]] = {}
        self._redis = None
        if redis_url:
            try:
                import redis
                self._redis = redis.Redis.from_url(redis_url, socket_timeout=1)
                self._redis.ping()
            except Exception:
                self._redis = None

    def get(self, key: str) -> dict | None:
        try:
            if self._redis:
                raw = self._redis.get(key)
                return json.loads(raw) if raw else None
        except Exception:
            pass
        item = self._mem.get(key)
        if item and item[0] > time.time():
            return json.loads(item[1])
        return None

    def set(self, key: str, value: dict) -> None:
        raw = json.dumps(value)
        try:
            if self._redis:
                self._redis.setex(key, self.ttl, raw)
                return
        except Exception:
            pass
        self._mem[key] = (time.time() + self.ttl, raw)


class RateLimiter:
    """Fixed-window counter per client key."""

    def __init__(self, redis_url: str | None, per_minute: int):
        self.per_minute = per_minute
        self._mem: dict[tuple[str, int], int] = {}
        self._redis = None
        if redis_url:
            try:
                import redis
                self._redis = redis.Redis.from_url(redis_url, socket_timeout=1)
                self._redis.ping()
            except Exception:
                self._redis = None

    def allow(self, key: str) -> bool:
        window = int(time.time() // 60)
        try:
            if self._redis:
                k = f"rl:{key}:{window}"
                n = self._redis.incr(k)
                if n == 1:
                    self._redis.expire(k, 70)
                return n <= self.per_minute
        except Exception:
            pass
        for old in [k for k in self._mem if k[1] < window]:
            del self._mem[old]
        n = self._mem.get((key, window), 0) + 1
        self._mem[(key, window)] = n
        return n <= self.per_minute

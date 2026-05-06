"""Simple in-memory cache to satisfy optional plugin caching in tests.
This is intentionally minimal for test environments; production deployments
should replace this with a persistent cache backend (Redis, DB, etc.).
"""

_cache = {}


def get_cached(namespace: str, key: str):
    return _cache.get((namespace, key))


def set_cached(namespace: str, key: str, value):
    _cache[(namespace, key)] = value


def clear_cache():
    _cache.clear()

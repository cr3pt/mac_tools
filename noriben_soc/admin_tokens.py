"""Token management for admin websocket auth. Uses Redis if available, otherwise falls back to in-memory store."""
from typing import Optional
import time
import os

try:
    import redis
except Exception:
    redis = None

from ..config import settings

# Fallback in-memory store
_tokens = {}

REDIS_PREFIX = 'noriben:admintoken:'


def _get_redis_client():
    if redis is None:
        return None
    url = getattr(settings, 'REDIS_URL', None) or getattr(settings, 'CELERY_BROKER', None)
    try:
        return redis.from_url(url)
    except Exception:
        return None


def issue_token(ttl: int = 300) -> str:
    token = os.urandom(16).hex()
    r = _get_redis_client()
    if r is not None:
        try:
            r.setex(f"{REDIS_PREFIX}{token}", ttl, '1')
            return token
        except Exception:
            pass
    # fallback
    _tokens[token] = time.time() + ttl
    return token


def validate_token(token: str) -> bool:
    r = _get_redis_client()
    if r is not None:
        try:
            return r.exists(f"{REDIS_PREFIX}{token}") == 1
        except Exception:
            pass
    exp = _tokens.get(token)
    if not exp:
        return False
    if time.time() > exp:
        del _tokens[token]
        return False
    return True


def revoke_token(token: str) -> None:
    r = _get_redis_client()
    if r is not None:
        try:
            r.delete(f"{REDIS_PREFIX}{token}")
            return
        except Exception:
            pass
    if token in _tokens:
        del _tokens[token]

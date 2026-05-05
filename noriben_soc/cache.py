"""Simple result cache for scanner plugins.
Uses a JSON file (cache.json) in the project root to store scan results keyed by
file path and engine name. This is a lightweight implementation suitable for
development and testing.
"""
import json
import pathlib
from threading import Lock

_cache_file = pathlib.Path(__file__).parent.parent / "cache.json"
_lock = Lock()

def _load_cache() -> dict:
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            return {}
    return {}

def _save_cache(data: dict) -> None:
    with _lock:
        cache_file.write_text(json.dumps(data, indent=2))

def get_cached(engine: str, file_path: str) -> dict | None:
    data = _load_cache()
    return data.get(engine, {}).get(file_path)

def set_cached(engine: str, file_path: str, result: dict) -> None:
    data = _load_cache()
    data.setdefault(engine, {})[file_path] = result
    _save_cache(data)


"""Simple imphash index stored as JSON for clustering by imphash.
Provides add_imphash(imphash, sha256, meta) and query_imphash(imphash).
File located at data/imphash_index.json under repo root.
"""
import json
from pathlib import Path
from typing import Dict, Any, List

DB_PATH = Path('data') / 'imphash_index.json'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# in-memory cache
_index: Dict[str, List[Dict[str, Any]]] = {}

# load existing on import
if DB_PATH.exists():
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as f:
            _index = json.load(f)
    except Exception:
        _index = {}


def _save():
    try:
        with open(DB_PATH, 'w', encoding='utf-8') as f:
            json.dump(_index, f, indent=2)
    except Exception:
        pass


def add_imphash(imphash: str, sha256: str, meta: Dict[str, Any] = None) -> None:
    """Add a sample to the imphash index."""
    if not imphash:
        return
    if meta is None:
        meta = {}
    arr = _index.get(imphash, [])
    # avoid duplicates
    for e in arr:
        if e.get('sha256') == sha256:
            return
    arr.append({'sha256': sha256, 'meta': meta})
    _index[imphash] = arr
    _save()


def query_imphash(imphash: str) -> List[Dict[str, Any]]:
    """Return list of entries with same imphash."""
    return list(_index.get(imphash, []))


def get_all() -> Dict[str, List[Dict[str, Any]]]:
    return dict(_index)

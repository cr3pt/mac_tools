"""Simple rules manager: tracks last reload and lists rule files.
This is intentionally minimal: it exposes paths and a reload() hook. Integration with
workers/pipeline should call reload_rules() to refresh in-memory compiled rules.
"""
import pathlib
import time
from typing import Dict, Any, List, Optional

_state: Dict[str, Any] = {
    'last_reload': None,
    'yara_files': [],
    'sigma_files': []
}


def _scan_rules() -> None:
    base = pathlib.Path('rules')
    yara_dir = base / 'yara'
    sigma_dir = base / 'sigma'
    yara_dir.mkdir(parents=True, exist_ok=True)
    sigma_dir.mkdir(parents=True, exist_ok=True)
    _state['yara_files'] = [str(p) for p in sorted(yara_dir.glob('*')) if p.is_file()]
    _state['sigma_files'] = [str(p) for p in sorted(sigma_dir.glob('*')) if p.is_file()]


def reload_rules() -> Dict[str, Any]:
    """Refresh rules list and update last_reload timestamp."""
    _scan_rules()
    _state['last_reload'] = time.time()
    return {
        'last_reload': _state['last_reload'],
        'yara_count': len(_state['yara_files']),
        'sigma_count': len(_state['sigma_files']),
        'yara_files': _state['yara_files'][:20],
        'sigma_files': _state['sigma_files'][:20],
    }


def get_status() -> Dict[str, Any]:
    return {
        'last_reload': _state['last_reload'],
        'yara_count': len(_state.get('yara_files', [])),
        'sigma_count': len(_state.get('sigma_files', [])),
    }


def get_yara_files() -> List[str]:
    return list(_state.get('yara_files', []))


def get_sigma_files() -> List[str]:
    return list(_state.get('sigma_files', []))


# initialize on import
_scan_rules()
_state['last_reload'] = time.time()
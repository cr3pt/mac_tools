"""Rules manager: scans rules directories and compiles/loads rules for runtime.

- Compiles YARA rules using python-yara when available and caches a compiled
  rules object for fast matching.
- Loads SIGMA rules (YAML) if PyYAML is available and extracts simple
  detection keywords; falls back to naive string extraction if PyYAML missing.

Expose functions:
- reload_rules(): rescan and (re)compile
- get_compiled_yara(): returns compiled yara object or None
- get_sigma_patterns(): returns list of lowercased keyword patterns
- get_status(): counts and last_reload
"""
import pathlib
import time
from typing import Dict, Any, List, Optional

_state: Dict[str, Any] = {
    'last_reload': None,
    'yara_files': [],
    'sigma_files': [],
    'compiled_yara': None,
    'sigma_patterns': [],
}


def _scan_rules() -> None:
    base = pathlib.Path('rules')
    yara_dir = base / 'yara'
    sigma_dir = base / 'sigma'
    yara_dir.mkdir(parents=True, exist_ok=True)
    sigma_dir.mkdir(parents=True, exist_ok=True)
    _state['yara_files'] = [p for p in sorted(yara_dir.glob('*')) if p.is_file()]
    _state['sigma_files'] = [p for p in sorted(sigma_dir.glob('*')) if p.is_file()]


def _compile_yara():
    """Attempt to compile all yara files into a single rules object.
    If python-yara is not available, compiled_yara remains None.
    """
    try:
        import yara
    except Exception:
        _state['compiled_yara'] = None
        return
    files = _state.get('yara_files', [])
    if not files:
        _state['compiled_yara'] = None
        return
    try:
        # build a dictionary mapping namespace -> filename
        sources = {}
        for idx, p in enumerate(files):
            name = f'rule_{idx}'
            try:
                sources[name] = p.read_text(encoding='utf-8')
            except Exception:
                try:
                    sources[name] = p.read_text(encoding='latin-1')
                except Exception:
                    sources[name] = ''
        compiled = yara.compile(sources=sources)
        _state['compiled_yara'] = compiled
    except Exception:
        _state['compiled_yara'] = None


def _load_sigma_patterns():
    """Load sigma rules and extract simple detection keywords.
    Prefer PyYAML to parse structures; fallback to naive extraction.
    """
    patterns: List[str] = []
    try:
        import yaml
        use_yaml = True
    except Exception:
        use_yaml = False
    for p in _state.get('sigma_files', []):
        try:
            txt = p.read_text(encoding='utf-8')
        except Exception:
            try:
                txt = p.read_text(encoding='latin-1')
            except Exception:
                txt = ''
        if not txt:
            continue
        if use_yaml:
            try:
                doc = yaml.safe_load(txt)
                # naive: find 'detection' section and extract strings recursively
                def extract_strings(node):
                    found = []
                    if isinstance(node, str):
                        found.append(node)
                    elif isinstance(node, dict):
                        for v in node.values():
                            found.extend(extract_strings(v))
                    elif isinstance(node, list):
                        for it in node:
                            found.extend(extract_strings(it))
                    return found
                det = doc.get('detection') if isinstance(doc, dict) else None
                if det:
                    strs = extract_strings(det)
                    for s in strs:
                        if not isinstance(s, str):
                            continue
                        t = s.strip().lower()
                        if len(t) >= 4:
                            patterns.append(t)
            except Exception:
                # fallback to naive
                pass
        # naive fallback: heuristically extract words and quoted strings
        import re
        for m in re.findall(r"'([^']{4,})'|\"([^\"]{4,})\"|(\b[a-zA-Z0-9_\-]{4,}\b)", txt):
            for g in m:
                if not g:
                    continue
                gg = g.strip().lower()
                if len(gg) >= 4:
                    patterns.append(gg)
    # dedupe
    seen = set()
    out = []
    for p in patterns:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    _state['sigma_patterns'] = out


def reload_rules() -> Dict[str, Any]:
    """Refresh rules list and recompile / reload patterns."""
    _scan_rules()
    _compile_yara()
    _load_sigma_patterns()
    _state['last_reload'] = time.time()
    return {
        'last_reload': _state['last_reload'],
        'yara_count': len(_state['yara_files']),
        'sigma_count': len(_state['sigma_files']),
        'yara_files': [str(p.name) for p in _state['yara_files'][:50]],
        'sigma_files': [str(p.name) for p in _state['sigma_files'][:50]],
    }


def get_status() -> Dict[str, Any]:
    return {
        'last_reload': _state['last_reload'],
        'yara_count': len(_state.get('yara_files', [])),
        'sigma_count': len(_state.get('sigma_files', [])),
    }


def get_yara_files() -> List[str]:
    return [str(p.name) for p in _state.get('yara_files', [])]


def get_sigma_files() -> List[str]:
    return [str(p.name) for p in _state.get('sigma_files', [])]


def get_compiled_yara():
    return _state.get('compiled_yara')


def get_sigma_patterns() -> List[str]:
    return list(_state.get('sigma_patterns', []))


# initialize on import
reload_rules()
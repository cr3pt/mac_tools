import os
import math
import hashlib
import re
from pathlib import Path


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for v in freq.values():
        p = v / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_ascii_strings(data: bytes, min_len: int = 4):
    pattern = rb"[ -~]{%d,}" % (min_len,)
    return [s.decode('latin1') for s in re.findall(pattern, data)]


def _extract_wide_strings(data: bytes, min_len: int = 4):
    # utf-16le wide strings: ASCII chars followed by 0x00
    pattern = (rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}')
    raws = re.findall(pattern, data)
    out = []
    for r in raws:
        try:
            out.append(r.decode('utf-16le', errors='ignore'))
        except Exception:
            pass
    return out


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def analyze_file(path: str, strings_limit: int = 50) -> dict:
    """Analyze a file for static indicators: type (PE/ELF/other), entropy, strings, imphash (PE), sections, yara matches when possible.

    Returns a dict with keys:
      filename, size, sha256, entropy, strings, type, pe, elf, yara_matches
    """
    p = Path(path)
    data = p.read_bytes()
    out = {
        'filename': p.name,
        'size': p.stat().st_size,
        'sha256': _sha256_file(p),
        'entropy': _shannon_entropy(data),
        'strings': [],
        'type': 'unknown',
        'pe': None,
        'elf': None,
        'yara_matches': [],
    }

    # strings
    asc = _extract_ascii_strings(data)
    wide = _extract_wide_strings(data)
    combined = []
    # prioritize ASCII then wide
    combined.extend(asc[:strings_limit])
    if len(combined) < strings_limit:
        combined.extend(wide[: max(0, strings_limit - len(combined))])
    out['strings'] = combined

    # detect PE
    try:
        import pefile
        if data[:2] == b'MZ':
            out['type'] = 'pe'
            try:
                pe = pefile.PE(str(p), fast_load=True)
                pe.parse_data_directories(directories=[])
                pe_info = {}
                # sections
                pe_info['sections'] = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections]
                # imports
                try:
                    imps = []
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                            for imp in entry.imports:
                                if imp.name:
                                    imps.append({'dll': dll, 'name': imp.name.decode(errors='ignore') if isinstance(imp.name, bytes) else str(imp.name)})
                                else:
                                    imps.append({'dll': dll, 'ordinal': imp.ordinal})
                    pe_info['imports'] = imps
                except Exception:
                    pe_info['imports'] = []
                # exports
                try:
                    exps = []
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            exps.append(e.name.decode(errors='ignore') if e.name else '')
                    pe_info['exports'] = exps
                except Exception:
                    pe_info['exports'] = []
                # imphash
                try:
                    imph = pe.get_imphash()
                except Exception:
                    imph = None
                pe_info['imphash'] = imph
                out['pe'] = pe_info
            except Exception:
                out['pe'] = {'error': 'pefile parse failed'}
    except Exception:
        # pefile not available or not PE
        if data[:4] == b'\x7fELF':
            out['type'] = 'elf'
        else:
            # basic magic sniff
            if data[:2] == b'PK':
                out['type'] = 'zip'

    # detect ELF with lief if available
    if out['type'] != 'pe':
        try:
            import lief
            if lief is not None:
                try:
                    elf = lief.parse(str(p))
                    if elf is not None:
                        out['type'] = 'elf'
                        elf_info = {'segments': [s.type for s in elf.segments], 'sections': [s.name for s in elf.sections]}
                        out['elf'] = elf_info
                except Exception:
                    pass
        except Exception:
            pass

    # YARA matching (scan repository rules if available)
    try:
        import yara
        rules_dir = Path('rules/yara')
        if rules_dir.exists():
            for rf in rules_dir.iterdir():
                if rf.is_file() and rf.suffix in ('.yar', '.yara', '.txt'):
                    try:
                        r = yara.compile(str(rf))
                        matches = r.match(data=data)
                        for m in matches:
                            try:
                                meta = dict(m.meta) if getattr(m, 'meta', None) else {}
                            except Exception:
                                meta = {}
                            out['yara_matches'].append({'rule': m.rule, 'meta': meta})
                    except Exception:
                        # try match without compile
                        try:
                            rules = yara.compile(filepath=str(rf))
                            for m in rules.match(data=data):
                                out['yara_matches'].append({'rule': m.rule, 'meta': dict(getattr(m, 'meta', {}))})
                        except Exception:
                            pass
    except Exception:
        # yara not available
        pass

    return out

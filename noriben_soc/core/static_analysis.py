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


def _extract_iocs_from_strings(strings):
    iocs = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'registry': [], 'mutexes': []}
    url_re = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    # domain regex simplified
    domain_re = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
    email_re = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    reg_re = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)[\\/][^\s\t\n\r]+', re.IGNORECASE)
    mutex_re = re.compile(r'(?:Global\\|Local\\)?[A-Za-z0-9_\-]{4,}')

    seen = set()
    for s in strings:
        for m in url_re.findall(s):
            if m not in seen:
                iocs['urls'].append(m); seen.add(m)
        for m in email_re.findall(s):
            if m not in seen:
                iocs['emails'].append(m); seen.add(m)
        for m in ip_re.findall(s):
            if m not in seen:
                iocs['ips'].append(m); seen.add(m)
        for m in domain_re.findall(s):
            if m not in seen:
                iocs['domains'].append(m.lower()); seen.add(m.lower())
        for m in reg_re.findall(s):
            if m not in seen:
                iocs['registry'].append(m); seen.add(m)
        # mutex heuristic: looks like Global\Name or plain token
        for m in mutex_re.findall(s):
            if len(m) >= 4 and m not in seen:
                iocs['mutexes'].append(m); seen.add(m)
    return iocs


def analyze_file(path: str, strings_limit: int = 50, report: bool = True, report_dir: str = 'results/reports') -> dict:
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

    # YARA matching: prefer compiled in-memory rules from rules_manager
    try:
        from .. import rules_manager
        compiled = rules_manager.get_compiled_yara()
        if compiled is not None:
            try:
                matches = compiled.match(data=data)
                for m in matches:
                    try:
                        meta = dict(m.meta) if getattr(m, 'meta', None) else {}
                    except Exception:
                        meta = {}
                    out['yara_matches'].append({'rule': m.rule, 'meta': meta})
            except Exception:
                pass
        else:
            # fallback to on-disk per-file compile
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
                            try:
                                rules = yara.compile(filepath=str(rf))
                                for m in rules.match(data=data):
                                    out['yara_matches'].append({'rule': m.rule, 'meta': dict(getattr(m, 'meta', {}))})
                            except Exception:
                                pass
    except Exception:
        # yara or rules_manager not available
        pass

    # IOC extraction from strings
    try:
        iocs = _extract_iocs_from_strings(asc + wide)
        out['iocs'] = iocs
    except Exception:
        out['iocs'] = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'registry': [], 'mutexes': []}

    # imphash indexing
    try:
        if out.get('pe') and out['pe'].get('imphash'):
            from ..core import imphash_db
            imph = out['pe'].get('imphash')
            imphash_db.add_imphash(imph, out['sha256'], {'filename': out['filename']})
    except Exception:
        pass

    # generate report if requested
    if report:
        try:
            rep = {
                'analysis': out,
            }
            rep_dir = Path(report_dir)
            rep_dir.mkdir(parents=True, exist_ok=True)
            jsonp = rep_dir / f"{out['sha256']}.json"
            with open(jsonp, 'w', encoding='utf-8') as jf:
                import json
                jf.write(json.dumps(rep, indent=2))
            # simple HTML summary
            htmlp = rep_dir / f"{out['sha256']}.html"
            with open(htmlp, 'w', encoding='utf-8') as hf:
                hf.write('<html><body>')
                hf.write(f"<h1>Report for {out['filename']} ({out['sha256']})</h1>")
                hf.write(f"<p>Size: {out['size']} bytes, Entropy: {out['entropy']:.2f}</p>")
                hf.write('<h2>IOCs</h2>')
                for k,v in out['iocs'].items():
                    hf.write(f"<h3>{k}</h3><pre>{v}</pre>")
                hf.write('<h2>YARA Matches</h2>')
                hf.write(f"<pre>{out['yara_matches']}</pre>")
                hf.write('</body></html>')
        except Exception:
            pass

    return out

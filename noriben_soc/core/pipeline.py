import asyncio, hashlib
from pathlib import Path
from .yara_engine import run_yara_scan; from .sigma_engine import run_sigma_scan
from .evtx_parser import parse_evtx;    from .qemu_engine import run_dynamic_analysis
from .db import save_result

async def analyze_sample(sample_path: Path) -> dict:
    raw = sample_path.read_bytes(); sha256 = hashlib.sha256(raw).hexdigest()
    text = raw.decode('utf-8', errors='ignore')
    yara_hits = run_yara_scan(raw); sigma_hits = run_sigma_scan(text)
    evtx_evts = parse_evtx(sample_path) if sample_path.suffix == '.evtx' else []
    static_score = min(
        sum(25 for h in yara_hits  if h.get('severity')=='HIGH') +
        sum(15 for h in yara_hits  if h.get('severity')=='MEDIUM') +
        sum(20 for h in sigma_hits if h.get('severity')=='HIGH') +
        sum(10 for h in sigma_hits if h.get('severity')=='MEDIUM'), 100)
    dynamic = None
    if static_score >= 70 or sample_path.suffix in ('.exe','.dll','.scr','.ps1'):
        dynamic = await run_dynamic_analysis(sample_path)
    dyn_score = dynamic.get('behavior_score', 0) if dynamic else 0
    result = dict(sha256=sha256, filename=sample_path.name,
        static=dict(yara=yara_hits, sigma=sigma_hits, evtx=evtx_evts, score=static_score),
        dynamic=dynamic, severity=max(static_score, dyn_score),
        mitre=_map_mitre(yara_hits + sigma_hits))
    await save_result(result); return result

def _map_mitre(hits):
    m = {'powershell':'T1059.001','lsass':'T1003.001','wevtutil':'T1070.001',
         'reg add':'T1547.001','schtasks':'T1053.005'}
    return list({tid for h in hits for kw,tid in m.items() if kw in h.get('rule','').lower()})

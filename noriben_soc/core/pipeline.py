import asyncio, hashlib
from pathlib import Path
from .yara_engine      import run_yara_scan
from .sigma_engine     import run_sigma_scan
from .evtx_parser      import parse_evtx
from .qemu_engine      import run_dynamic_analysis
from .results_merger   import merge_dual_results
from .db               import save_result

async def analyze_sample(sample_path: Path) -> dict:
    raw    = sample_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    text   = raw.decode('utf-8', errors='ignore')

    yara_hits  = run_yara_scan(raw)
    sigma_hits = run_sigma_scan(text)
    evtx_evts  = parse_evtx(sample_path) if sample_path.suffix == '.evtx' else []

    static_score = min(
        sum(25 for h in yara_hits  if h.get('severity') == 'HIGH')  +
        sum(15 for h in yara_hits  if h.get('severity') == 'MEDIUM')+
        sum(20 for h in sigma_hits if h.get('severity') == 'HIGH')  +
        sum(10 for h in sigma_hits if h.get('severity') == 'MEDIUM'), 100)

    dynamic_win10 = None
    dynamic_win11 = None

    if static_score >= 70 or sample_path.suffix in ('.exe','.dll','.scr','.ps1'):
        # Rownolegla analiza na Win10 i Win11
        dynamic_win10, dynamic_win11 = await asyncio.gather(
            run_dynamic_analysis(sample_path, vm='win10'),
            run_dynamic_analysis(sample_path, vm='win11'),
        )

    # Polacz wyniki dual-VM
    merged = merge_dual_results(dynamic_win10, dynamic_win11)

    result = dict(
        sha256         = sha256,
        filename       = sample_path.name,
        static         = dict(yara=yara_hits, sigma=sigma_hits, evtx=evtx_evts, score=static_score),
        dynamic_win10  = dynamic_win10,
        dynamic_win11  = dynamic_win11,
        dynamic_merged = merged,
        severity       = max(static_score, merged.get('max_score', 0)),
        mitre          = _map_mitre(yara_hits + sigma_hits),
    )
    await save_result(result)
    return result

def _map_mitre(hits):
    m = {'powershell':'T1059.001','lsass':'T1003.001','wevtutil':'T1070.001',
         'reg add':'T1547.001','schtasks':'T1053.005','mimikatz':'T1003.001',
         'certutil':'T1140','mshta':'T1218.005','regsvr32':'T1218.010'}
    return list({tid for h in hits for kw,tid in m.items() if kw in h.get('rule','').lower()})

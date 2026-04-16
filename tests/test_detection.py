from pathlib import Path
from noriben58.models import SampleSession
from noriben58.detection import analyze_text

def test_detection_basic(tmp_path):
    s = SampleSession(Path('sample.exe'), 'sample', tmp_path, tmp_path/'log.txt', tmp_path/'audit.jsonl')
    txt = 'powershell -enc AAA\nWriteProcessMemory\nCreateRemoteThread\nURLDownloadToFile\nwevtutil cl system\nAmsiUtils\nwhoami\nsysteminfo\nlsass'
    analyze_text(txt, 'vm1', s)
    assert s.dynamic_findings
    assert s.mitre_hits

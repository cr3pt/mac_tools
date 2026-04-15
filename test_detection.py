from pathlib import Path
from noriben55.models import SampleSession
from noriben55.detection import analyze_text

def test_detection_basic(tmp_path):
    s = SampleSession(Path('sample.exe'), 'sample', tmp_path, tmp_path/'log.txt', tmp_path/'audit.jsonl')
    txt = 'powershell -enc AAA\nWriteProcessMemory\nCreateRemoteThread\nURLDownloadToFile\nwevtutil cl system'
    analyze_text(txt, 'vm1', s)
    assert s.dynamic_findings
    assert s.mitre_hits
    assert any('SIGMA-like' in f.description for f in s.dynamic_findings)

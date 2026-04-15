from pathlib import Path
from noriben57.models import SampleSession
from noriben57.reporting import export_session

def test_reporting_outputs(tmp_path):
    s = SampleSession(Path('sample.exe'), 'sample', tmp_path, tmp_path/'log.txt', tmp_path/'audit.jsonl')
    export_session(s, '5.7', 'balanced', {'platform':'linux'})
    assert (tmp_path / 'session_summary.json').exists()
    assert list(tmp_path.glob('REPORT_*.html'))

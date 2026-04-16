from pathlib import Path
from noriben_soc.core.sigma_engine import run_sigma_on_text

def test_sigma_condition(tmp_path):
    (tmp_path/'sigma').mkdir()
    (tmp_path/'sigma'/'r.yml').write_text('title: t\ndetection:\n  selection1:\n    CommandLine|contains: powershell\n  selection2:\n    CommandLine|contains: wevtutil\n  condition: selection1 and selection2\n', encoding='utf-8')
    hits = run_sigma_on_text('powershell wevtutil', tmp_path)
    assert hits

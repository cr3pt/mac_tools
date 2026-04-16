from pathlib import Path
from noriben_soc.core.pipeline import analyze_file

def test_pipeline(tmp_path):
    sample = tmp_path/'sample.txt'
    sample.write_text('powershell test', encoding='utf-8')
    sess = analyze_file(sample, Path('noriben_soc/rules'))
    assert sess.iocs is not None
    assert sess.events

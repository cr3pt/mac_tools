from noriben59.prepare import prepare_environment
from noriben59.config import DEFAULT_CONFIG

def test_prepare_environment_creates_outputs(tmp_path):
    cfg = dict(DEFAULT_CONFIG)
    cfg['host_tools_dir'] = str(tmp_path / 'tools')
    cfg['host_results_dir'] = str(tmp_path / 'results')
    prep_file, prep_script, guest_file, plan = prepare_environment(cfg)
    assert prep_file.exists()
    assert prep_script.exists()
    assert guest_file.exists()
    assert 'guest_checklist' in plan

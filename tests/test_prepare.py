from noriben58.prepare import prepare_environment
from noriben58.config import DEFAULT_CONFIG

def test_prepare_environment_creates_plan(tmp_path, monkeypatch):
    cfg = dict(DEFAULT_CONFIG)
    cfg['host_tools_dir'] = str(tmp_path / 'tools')
    cfg['host_results_dir'] = str(tmp_path / 'results')
    prep_file, plan = prepare_environment(cfg)
    assert prep_file.exists()
    assert 'recommended_profile' in plan

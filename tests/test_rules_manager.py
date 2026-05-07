import pytest
from noriben_soc import rules_manager

def test_reload_rules_creates_lists(tmp_path, monkeypatch):
    # create rules dirs
    rdir = tmp_path / 'rules'
    y = rdir / 'yara'
    s = rdir / 'sigma'
    y.mkdir(parents=True)
    s.mkdir(parents=True)
    f1 = y / 'r1.yar'
    f1.write_text('rule test { condition: true }')
    f2 = s / 's1.yml'
    f2.write_text('title: test\ndetection:\n  selection:\n    - cmd')
    # monkeypatch cwd
    monkeypatch.chdir(tmp_path)
    res = rules_manager.reload_rules()
    assert res['yara_count'] == 1
    assert res['sigma_count'] == 1

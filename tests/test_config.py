from noriben59.config import load_config

def test_load_config_kv(tmp_path):
    cfg_file = tmp_path / 'cfg.txt'
    cfg_file.write_text('analysis_timeout=123\ndual_vm_mode=true\nqemu_accel_mode=auto\n', encoding='utf-8')
    cfg = load_config(cfg_file)
    assert cfg['analysis_timeout'] == 123
    assert cfg['dual_vm_mode'] is True

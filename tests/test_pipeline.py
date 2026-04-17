import pytest
from pathlib import Path
from unittest.mock import patch
from noriben_soc.core.pipeline import analyze_sample

@pytest.fixture
def sample(tmp_path):
    f = tmp_path / 'test.exe'
    f.write_bytes(b'MZ' + b'\x00' * 100)
    return f

@pytest.mark.asyncio
async def test_static_only_low(sample):
    with patch('noriben_soc.core.pipeline.run_yara_scan',  return_value=[{'rule':'X','severity':'LOW','type':'YARA'}]), \
         patch('noriben_soc.core.pipeline.run_sigma_scan', return_value=[]), \
         patch('noriben_soc.core.pipeline.parse_evtx',     return_value=[]), \
         patch('noriben_soc.core.pipeline.run_dynamic_analysis', return_value={'behavior_score':0}) as dyn, \
         patch('noriben_soc.core.pipeline.save_result'):
        r = await analyze_sample(sample)
        assert len(r['sha256']) == 64
        dyn.assert_called_once()  # .exe triggers dynamic

@pytest.mark.asyncio
async def test_dynamic_high_score(sample):
    high = [{'rule':'Ransomware','severity':'HIGH','type':'YARA'}] * 4
    with patch('noriben_soc.core.pipeline.run_yara_scan',  return_value=high), \
         patch('noriben_soc.core.pipeline.run_sigma_scan', return_value=[]), \
         patch('noriben_soc.core.pipeline.parse_evtx',     return_value=[]), \
         patch('noriben_soc.core.pipeline.run_dynamic_analysis', return_value={'behavior_score':95}) as dyn, \
         patch('noriben_soc.core.pipeline.save_result'):
        r = await analyze_sample(sample)
        assert r['severity'] == 95
        dyn.assert_called_once()

@pytest.mark.asyncio
async def test_mitre_mapping(sample):
    hits = [{'rule':'lsass dump','severity':'HIGH','type':'YARA'}]
    with patch('noriben_soc.core.pipeline.run_yara_scan',  return_value=hits), \
         patch('noriben_soc.core.pipeline.run_sigma_scan', return_value=[]), \
         patch('noriben_soc.core.pipeline.parse_evtx',     return_value=[]), \
         patch('noriben_soc.core.pipeline.run_dynamic_analysis', return_value={'behavior_score':0}), \
         patch('noriben_soc.core.pipeline.save_result'):
        r = await analyze_sample(sample)
        assert 'T1003.001' in r['mitre']

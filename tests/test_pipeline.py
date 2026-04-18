import pytest
from pathlib import Path
from unittest.mock import patch, AsyncMock
from noriben_soc.core.pipeline import analyze_sample

@pytest.fixture
def sample(tmp_path):
    f = tmp_path / 'test.exe'; f.write_bytes(b'MZ' + b'\x00'*100); return f

EMPTY = {'behavior_score':0,'network':[],'network_iocs':[],'files_dropped':[],'processes':[],'registry':[],'vm':''}

@pytest.mark.asyncio
async def test_static(sample):
    with patch('noriben_soc.core.pipeline.run_yara_scan',  return_value=[{'rule':'X','severity':'LOW','type':'YARA'}]), \
         patch('noriben_soc.core.pipeline.run_sigma_scan', return_value=[]), \
         patch('noriben_soc.core.pipeline.parse_evtx',     return_value=[]), \
         patch('noriben_soc.core.pipeline.run_dynamic_analysis', new_callable=AsyncMock, return_value={**EMPTY}), \
         patch('noriben_soc.core.pipeline.save_result',    new_callable=AsyncMock):
        r = await analyze_sample(sample)
        assert len(r['sha256']) == 64

@pytest.mark.asyncio
async def test_network_ioc_merge(sample):
    w10 = {**EMPTY, 'vm':'win10','behavior_score':80,
           'network_iocs':[{'type':'IP','value':'1.2.3.4','severity':'MEDIUM'}]}
    w11 = {**EMPTY, 'vm':'win11','behavior_score':70,
           'network_iocs':[{'type':'IP','value':'1.2.3.4','severity':'MEDIUM'},
                           {'type':'DNS','value':'evil.ru','severity':'HIGH'}]}
    with patch('noriben_soc.core.pipeline.run_yara_scan',  return_value=[{'rule':'R','severity':'HIGH','type':'YARA'}]*4), \
         patch('noriben_soc.core.pipeline.run_sigma_scan', return_value=[]), \
         patch('noriben_soc.core.pipeline.parse_evtx',     return_value=[]), \
         patch('noriben_soc.core.pipeline.run_dynamic_analysis', new_callable=AsyncMock, side_effect=[w10, w11]), \
         patch('noriben_soc.core.pipeline.save_result',    new_callable=AsyncMock):
        r = await analyze_sample(sample)
        iocs = r['dynamic_merged']['network_iocs']
        ip_ioc = next(i for i in iocs if i['value']=='1.2.3.4')
        assert 'win10' in ip_ioc['seen_on'] and 'win11' in ip_ioc['seen_on']
        dns_ioc = next(i for i in iocs if i['value']=='evil.ru')
        assert dns_ioc['seen_on'] == ['win11']

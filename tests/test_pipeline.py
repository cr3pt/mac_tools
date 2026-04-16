import pytest, asyncio
from pathlib import Path
from unittest.mock import patch

from noriben_soc.core.pipeline import analyze_sample

@pytest.fixture
def sample(tmp_path):
    f = tmp_path / "test.exe"
    f.write_bytes(b"X5O!P%@AP[4\x00EICAR-TEST")
    return f

@pytest.mark.asyncio
async def test_static_only(sample):
    with patch("noriben_soc.core.pipeline.run_yara_scan",  return_value=[{"rule":"X","severity":"LOW","type":"YARA"}]),          patch("noriben_soc.core.pipeline.run_sigma_scan", return_value=[]),          patch("noriben_soc.core.pipeline.parse_evtx",     return_value=[]),          patch("noriben_soc.core.pipeline.run_dynamic_analysis") as dyn,          patch("noriben_soc.core.pipeline.save_result"):
        r = await analyze_sample(sample)
        assert r["sha256"]
        dyn.assert_called_once()   # .exe triggers dynamic

@pytest.mark.asyncio
async def test_dynamic_triggered(sample):
    high = [{"rule":"RansomHIGH","severity":"HIGH","type":"YARA"}]*4
    with patch("noriben_soc.core.pipeline.run_yara_scan",  return_value=high),          patch("noriben_soc.core.pipeline.run_sigma_scan", return_value=[]),          patch("noriben_soc.core.pipeline.parse_evtx",     return_value=[]),          patch("noriben_soc.core.pipeline.run_dynamic_analysis",
               return_value={"behavior_score":95}) as dyn,          patch("noriben_soc.core.pipeline.save_result"):
        r = await analyze_sample(sample)
        assert r["severity"] == 95
        dyn.assert_called_once()
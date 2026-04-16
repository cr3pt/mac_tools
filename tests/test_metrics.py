from fastapi.testclient import TestClient
from noriben_soc.api.app import app

def test_metrics_endpoint():
    c = TestClient(app)
    r = c.get('/metrics')
    assert r.status_code == 200
    assert 'noriben_' in r.text

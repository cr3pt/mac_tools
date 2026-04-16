from fastapi.testclient import TestClient
from noriben_soc.api.app import app

def test_health():
    c = TestClient(app)
    r = c.get('/health')
    assert r.status_code == 200

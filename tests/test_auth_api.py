from fastapi.testclient import TestClient
from noriben_soc.api.app import app

def test_login_and_health():
    c = TestClient(app)
    r = c.post('/auth/login', params={'username':'tier1','password':'tier1pass'})
    assert r.status_code == 200
    token = r.json()['token']
    h = c.get('/health', headers={'x-session-token': token})
    assert h.status_code == 200

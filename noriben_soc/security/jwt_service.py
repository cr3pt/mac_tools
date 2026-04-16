import time, base64, hmac, hashlib, json
from ..core.config import settings
REVOKED = set()

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _ub64(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def issue_token(subject: str, role: str, ttl_seconds: int = 43200):
    header = {'alg':'HS256','typ':'JWT'}
    payload = {'sub': subject, 'role': role, 'iss': settings.jwt_issuer, 'exp': int(time.time()) + ttl_seconds}
    h = _b64(json.dumps(header, separators=(',',':')).encode())
    p = _b64(json.dumps(payload, separators=(',',':')).encode())
    sig = hmac.new(settings.jwt_secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest()
    return f'{h}.{p}.{_b64(sig)}'

def revoke_token(token: str):
    REVOKED.add(token)

def verify_token(token: str):
    try:
        if token in REVOKED: return None
        h, p, s = token.split('.')
        expected = _b64(hmac.new(settings.jwt_secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, s): return None
        payload = json.loads(_ub64(p).decode())
        if payload.get('iss') != settings.jwt_issuer: return None
        if int(payload.get('exp',0)) < int(time.time()): return None
        return payload
    except Exception:
        return None

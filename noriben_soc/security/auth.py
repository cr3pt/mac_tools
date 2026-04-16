import hashlib
from fastapi import Header, HTTPException
from .jwt_service import issue_token, verify_token, revoke_token
from ..core.db import DB
try:
    import bcrypt
except Exception:
    bcrypt = None

def hash_password(password):
    if bcrypt: return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return 'sha256$' + hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, stored):
    if stored.startswith('sha256$'): return stored == 'sha256$' + hashlib.sha256(password.encode('utf-8')).hexdigest()
    if bcrypt: return bcrypt.checkpw(password.encode('utf-8'), stored.encode('utf-8'))
    return False

def ensure_default_users(db: DB):
    if not db.get_user('tier1'): db.ensure_user('tier1', hash_password('tier1pass'), 'tier1')
    if not db.get_user('tier2'): db.ensure_user('tier2', hash_password('tier2pass'), 'tier2')
    if not db.get_user('admin'): db.ensure_user('admin', hash_password('adminpass'), 'admin')

def login(db: DB, username: str, password: str):
    u = db.get_user(username)
    if not u or not verify_password(password, u['password_hash']): return None
    token = issue_token(u['username'], u['role'])
    return {'token': token, 'username': u['username'], 'role': u['role']}

def logout(token: str):
    revoke_token(token)

def require_role(min_role):
    order = {'tier1':1, 'tier2':2, 'hunter':3, 'admin':4}
    def dep(authorization: str = Header(default='')):
        if not authorization.startswith('Bearer '): raise HTTPException(status_code=401, detail='missing bearer token')
        token = authorization.split(' ',1)[1]
        payload = verify_token(token)
        if not payload: raise HTTPException(status_code=401, detail='invalid or expired token')
        if order.get(payload['role'],0) < order[min_role]: raise HTTPException(status_code=403, detail='insufficient role')
        return {'user': payload['sub'], 'role': payload['role'], 'token': token}
    return dep

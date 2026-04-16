import secrets, datetime, hashlib
from fastapi import Header, HTTPException
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
    token = secrets.token_hex(24)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=12)).isoformat() + 'Z'
    db.save_auth(token, u['username'], u['role'], exp)
    return {'token': token, 'username': u['username'], 'role': u['role'], 'expires_at': exp}

def require_role(db: DB, min_role):
    order = {'tier1':1, 'tier2':2, 'hunter':3, 'admin':4}
    def dep(x_session_token: str = Header(default='')):
        sess = db.get_auth(x_session_token)
        if not sess: raise HTTPException(status_code=401, detail='invalid session')
        if order.get(sess['role'],0) < order[min_role]: raise HTTPException(status_code=403, detail='insufficient role')
        return {'user': sess['username'], 'role': sess['role']}
    return dep

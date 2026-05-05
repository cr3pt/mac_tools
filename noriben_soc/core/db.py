import json, os
from datetime import datetime
try:
    import asyncpg
except ImportError:
    asyncpg = None

DSN = os.getenv('DATABASE_URL','postgresql://noriben:noriben123@localhost/noriben')
async def save_result(result: dict):
    conn = await asyncpg.connect(DSN)
    await conn.execute(
        'INSERT INTO analysis_sessions(sha256,filename,severity,result_json,created_at)'
        ' VALUES($1,$2,$3,$4,$5) ON CONFLICT(sha256)'
        ' DO UPDATE SET result_json=$4,created_at=$5',
        result['sha256'], result['filename'], result['severity'],
        json.dumps(result, default=str), datetime.utcnow())
    await conn.close()

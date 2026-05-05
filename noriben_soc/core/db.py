import json, os
from datetime import datetime
# asyncpg is optional; if unavailable, database operations become no‑ops.
try:
    import asyncpg
except ImportError:  # pragma: no cover
    asyncpg = None

DSN = os.getenv('DATABASE_URL','postgresql://noriben:noriben123@localhost/noriben')
async def save_result(result: dict):
    """Persist analysis result to PostgreSQL if asyncpg is available.
    When asyncpg is not installed (e.g., in test environments), the function
    simply logs the result and returns without raising an error.
    """
    if asyncpg is None:
        # Fallback: write JSON to a local file for debugging purposes.
        try:
            with open(f"{result['sha256']}_result.json", "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        except Exception:
            pass
        return
    conn = await asyncpg.connect(DSN)
    await conn.execute(
        'INSERT INTO analysis_sessions(sha256,filename,severity,result_json,created_at)'
        ' VALUES($1,$2,$3,$4,$5) ON CONFLICT(sha256)'
        ' DO UPDATE SET result_json=$4,created_at=$5',
        result['sha256'], result['filename'], result['severity'],
        json.dumps(result, default=str), datetime.utcnow())
    await conn.close()

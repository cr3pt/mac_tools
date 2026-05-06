import sqlite3
from typing import Optional, List, Dict
from datetime import datetime
import os

DB_PATH = os.getenv('AUDIT_DB_PATH', 'data/tasks_audit.sqlite3')

CREATE_SQL = '''
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    script TEXT,
    initiator TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT,
    returncode INTEGER
);
'''


def _get_conn():
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn


def init_db():
    conn = _get_conn()
    c = conn.cursor()
    c.executescript(CREATE_SQL)
    conn.commit()
    conn.close()


def record_start(task_id: str, script: str, initiator: Optional[str]):
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO tasks(task_id, script, initiator, start_time, status) VALUES(?,?,?,?,?)',
              (task_id, script, initiator, datetime.utcnow().isoformat(), 'running'))
    conn.commit()
    conn.close()


def record_end(task_id: str, status: str, returncode: Optional[int]):
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute('UPDATE tasks SET end_time=?, status=?, returncode=? WHERE task_id=?',
              (datetime.utcnow().isoformat(), status, returncode, task_id))
    conn.commit()
    conn.close()


def list_tasks(limit: int = 100) -> List[Dict]:
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    rows = c.execute('SELECT task_id,script,initiator,start_time,end_time,status,returncode FROM tasks ORDER BY start_time DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    return [dict(task_id=r[0], script=r[1], initiator=r[2], start_time=r[3], end_time=r[4], status=r[5], returncode=r[6]) for r in rows]


def delete_task(task_id: str) -> bool:
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute('DELETE FROM tasks WHERE task_id=?', (task_id,))
    changed = c.rowcount
    conn.commit()
    conn.close()
    return changed > 0

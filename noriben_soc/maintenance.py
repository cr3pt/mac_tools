import pathlib
import time
import asyncio
from typing import Tuple


def prune_logs_older_than(days: int) -> int:
    """Delete log files in logs/tasks older than `days` days. Returns number deleted."""
    log_dir = pathlib.Path('logs/tasks')
    if not log_dir.exists():
        return 0
    cutoff = time.time() - int(days) * 86400
    removed = 0
    for p in log_dir.glob('*'):
        try:
            try:
                mtime = p.stat().st_mtime
            except Exception:
                try:
                    p.unlink()
                    removed += 1
                except Exception:
                    pass
                continue
            if mtime < cutoff:
                try:
                    p.unlink()
                    removed += 1
                except Exception:
                    try:
                        import os
                        os.remove(str(p))
                        removed += 1
                    except Exception:
                        pass
        except Exception:
            continue
    return removed


def prune_audit_older_than(days: int) -> int:
    """Prune audit DB records older than days. Returns number deleted."""
    try:
        from . import task_audit
        return task_audit.prune_tasks_older_than(int(days))
    except Exception:
        return 0


async def prune_loop(interval_seconds: int = 24 * 3600):
    """Background loop that prunes logs and audit periodically."""
    from .config import settings as cfg
    while True:
        try:
            days_logs = int(getattr(cfg, 'LOG_RETENTION_DAYS', 30))
            days_audit = int(getattr(cfg, 'AUDIT_RETENTION_DAYS', 90))
            removed_logs = prune_logs_older_than(days_logs)
            removed_db = prune_audit_older_than(days_audit)
        except Exception:
            removed_logs = removed_db = 0
        # sleep interval
        try:
            await asyncio.sleep(int(interval_seconds))
        except asyncio.CancelledError:
            break

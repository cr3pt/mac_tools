import asyncio
import uuid
from typing import Dict, Any
import os

_tasks: Dict[str, Dict[str, Any]] = {}

async def _run_process(task_id: str, script: str):
    """Run script asynchronously, capture stdout/stderr lines into queue and file."""
    # ensure log dir
    import pathlib
    log_dir = pathlib.Path('logs/tasks')
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{task_id}.log"

    proc = await asyncio.create_subprocess_exec(script, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, shell=True)
    q: asyncio.Queue = asyncio.Queue()
    _tasks[task_id] = {'proc': proc, 'queue': q, 'returncode': None, 'done': False, 'log_file': str(log_file)}
    # read stdout
    try:
        with open(log_file, 'ab') as lf:
            from noriben_soc.config import settings as cfg
            max_bytes = int(getattr(cfg, 'LOG_ROTATE_MAX_BYTES', 5 * 1024 * 1024))
            backups = int(getattr(cfg, 'LOG_ROTATE_BACKUPS', 3))
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode(errors='ignore')
                # write to queue and file
                await q.put(text)
                try:
                    lf.write(text.encode('utf-8', errors='ignore'))
                    lf.flush()
                except Exception:
                    pass
                # check rotation
                try:
                    if lf.tell() > max_bytes:
                        _rotate_log_if_needed(log_file, max_size=max_bytes, backups=backups)
                        # reopen new file
                        lf.close()
                        lf = open(log_file, 'ab')
                except Exception:
                    pass
        await proc.wait()
        _tasks[task_id]['returncode'] = proc.returncode
    except Exception as e:
        await q.put(f"ERROR: {e}\n")
        _tasks[task_id]['returncode'] = -1
    finally:
        _tasks[task_id]['done'] = True
        # update audit
        try:
            from . import task_audit
            status = 'success' if _tasks[task_id].get('returncode', 1) == 0 else 'failed'
            task_audit.record_end(task_id, status, _tasks[task_id].get('returncode'))
        except Exception:
            pass
        # put sentinel
        await q.put(None)


def _rotate_log_if_needed(log_file: 'pathlib.Path', max_size: int = 5 * 1024 * 1024, backups: int = 3):
    """Rotate log file if it exceeds max_size. Keeps up to `backups` rotated files.
    Rotation scheme: taskid.log -> taskid.1, taskid.1 -> taskid.2, ..."""
    try:
        import pathlib
        p = pathlib.Path(log_file)
        if not p.exists():
            return
        try:
            if p.stat().st_size <= max_size:
                return
        except Exception:
            return
        # rotate
        for i in range(backups - 1, 0, -1):
            older = p.with_suffix(f'.{i}')
            newer = p.with_suffix(f'.{i+1}')
            if older.exists():
                try:
                    older.replace(newer)
                except Exception:
                    pass
        first = p.with_suffix('.1')
        try:
            p.replace(first)
        except Exception:
            pass
    except Exception:
        return


def cancel_task(task_id: str) -> bool:
    """Attempt to cancel/kill a running task. Returns True if killed/was running."""
    t = _tasks.get(task_id)
    if not t:
        return False
    proc = t.get('proc')
    if not proc:
        return False
    try:
        proc.kill()
        t['done'] = True
        t['returncode'] = -9
        # push sentinel into queue so readers finish
        q: asyncio.Queue = t.get('queue')
        if q is not None:
            try:
                asyncio.get_event_loop().create_task(q.put(None))
            except Exception:
                pass
        return True
    except Exception:
        return False


async def start_script(script_path: str, initiator: str = None) -> str:
    task_id = uuid.uuid4().hex
    # record start in audit
    try:
        from . import task_audit
        task_audit.record_start(task_id, script_path, initiator)
    except Exception:
        pass
    # schedule background task
    loop = asyncio.get_event_loop()
    loop.create_task(_run_process(task_id, script_path))
    return task_id


def get_task(task_id: str):
    return _tasks.get(task_id)


async def read_lines(task_id: str):
    t = _tasks.get(task_id)
    if not t:
        return
    q: asyncio.Queue = t['queue']
    while True:
        line = await q.get()
        if line is None:
            break
        yield line


def task_status(task_id: str):
    t = _tasks.get(task_id)
    if not t:
        return {'exists': False}
    return {'exists': True, 'done': t.get('done', False), 'returncode': t.get('returncode')}


def get_task(task_id: str):
    return _tasks.get(task_id)


async def read_lines(task_id: str):
    t = _tasks.get(task_id)
    if not t:
        return
    q: asyncio.Queue = t['queue']
    while True:
        line = await q.get()
        if line is None:
            break
        yield line


def task_status(task_id: str):
    t = _tasks.get(task_id)
    if not t:
        return {'exists': False}
    return {'exists': True, 'done': t.get('done', False), 'returncode': t.get('returncode')}

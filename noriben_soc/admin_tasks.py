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
        await proc.wait()
        _tasks[task_id]['returncode'] = proc.returncode
    except Exception as e:
        await q.put(f"ERROR: {e}\n")
        _tasks[task_id]['returncode'] = -1
    finally:
        _tasks[task_id]['done'] = True
        # put sentinel
        await q.put(None)


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


async def start_script(script_path: str) -> str:
    task_id = uuid.uuid4().hex
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

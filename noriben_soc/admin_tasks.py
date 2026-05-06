import asyncio
import uuid
from typing import Dict, Any
import os

_tasks: Dict[str, Dict[str, Any]] = {}

async def _run_process(task_id: str, script: str):
    """Run script asynchronously, capture stdout/stderr lines into queue."""
    proc = await asyncio.create_subprocess_exec(script, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, shell=True)
    q: asyncio.Queue = asyncio.Queue()
    _tasks[task_id] = {'proc': proc, 'queue': q, 'returncode': None, 'done': False}
    # read stdout
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors='ignore')
            await q.put(text)
        await proc.wait()
        _tasks[task_id]['returncode'] = proc.returncode
    except Exception as e:
        await q.put(f"ERROR: {e}\n")
        _tasks[task_id]['returncode'] = -1
    finally:
        _tasks[task_id]['done'] = True
        # put sentinel
        await q.put(None)


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

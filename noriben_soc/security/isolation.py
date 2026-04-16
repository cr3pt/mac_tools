from pathlib import Path

def isolated_dir(root, job_id):
    p = Path(root) / 'isolated' / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p

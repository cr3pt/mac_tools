import asyncio, os
from celery import Celery; from pathlib import Path
from .core.pipeline import analyze_sample
celery_app = Celery('noriben', broker=os.getenv('CELERY_BROKER','redis://localhost:6379/0'))
@celery_app.task(name='run_analysis_task', bind=True, max_retries=2)
def run_analysis_task(self, path: str, filename: str):
    return asyncio.run(analyze_sample(Path(path)))

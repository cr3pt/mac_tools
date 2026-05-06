import asyncio
from celery import Celery
from pathlib import Path
from .core.pipeline import analyze_sample
from .config import settings
import logging

logger = logging.getLogger(__name__)

celery_app = Celery('noriben', broker=settings.CELERY_BROKER)

@celery_app.task(name='run_analysis_task', bind=True, max_retries=2)
def run_analysis_task(self, path: str, filename: str):
    logger.info('Starting analysis task for %s', filename)
    try:
        return asyncio.run(analyze_sample(Path(path)))
    except Exception as e:
        logger.exception('Analysis task failed for %s: %s', filename, e)
        raise

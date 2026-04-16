from celery import Celery
from .config import settings
celery_app = Celery('noriben_soc', broker=settings.celery_broker_url, backend=settings.celery_result_backend)
celery_app.conf.update(task_routes={'noriben_soc.core.tasks.run_analysis': {'queue': 'analysis'}}, task_acks_late=True, task_reject_on_worker_lost=True, worker_prefetch_multiplier=1, task_default_retry_delay=5, task_annotations={'noriben_soc.core.tasks.run_analysis': {'max_retries': 3}})

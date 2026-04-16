from pathlib import Path
from .celery_app import celery_app
from .config import settings
from .db import DB
from .pipeline import analyze_sample
from .observability import Observability
from ..security.isolation import isolated_dir

ROOT = Path.home() / 'NoribenSOCPlatform101'; ROOT.mkdir(parents=True, exist_ok=True)
DBH = DB(settings.db_url)
OBS = Observability(ROOT)
RULES = Path(__file__).resolve().parents[1] / 'rules'

@celery_app.task(bind=True, name='noriben_soc.core.tasks.run_analysis', autoretry_for=(Exception,), retry_backoff=True, retry_jitter=True, max_retries=3)
def run_analysis(self, path: str, job_id: str, trace_id: str):
    sample_path = Path(path)
    iso = isolated_dir(ROOT, job_id)
    result = analyze_sample(sample_path, RULES)
    result['meta']['trace_id'] = trace_id
    result['meta']['isolated_dir'] = str(iso)
    DBH.upsert_analysis(result)
    DBH.upsert_job(job_id, self.request.id, trace_id, 'done')
    OBS.inc('sessions_total')
    OBS.inc('jobs_total')
    OBS.log('INFO', f"session stored {result['session_id']}", trace_id)
    return {'session_id': result['session_id']}

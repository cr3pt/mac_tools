from queue import Queue
from threading import Thread
import traceback
class LocalOrchestrator:
    def __init__(self, handler, obs, size=2):
        self.handler=handler; self.obs=obs; self.q=Queue(); self.results={}; self.threads=[]
        for _ in range(size):
            t=Thread(target=self._run, daemon=True); t.start(); self.threads.append(t)
    def _run(self):
        while True:
            job_id,payload,trace_id=self.q.get()
            try:
                self.results[job_id]={'status':'running'}; self.obs.log('INFO', f'job start {job_id}', trace_id); result=self.handler(payload, trace_id); self.results[job_id]={'status':'done','result':result}; self.obs.inc('jobs_total')
            except Exception as e:
                self.results[job_id]={'status':'error','error':str(e),'trace':traceback.format_exc()}; self.obs.inc('jobs_error'); self.obs.log('ERROR', f'job error {job_id}: {e}', trace_id)
            finally:
                self.q.task_done()
    def submit(self, job_id, payload, trace_id): self.results[job_id]={'status':'queued'}; self.q.put((job_id,payload,trace_id))
    def get(self, job_id): return self.results.get(job_id, {'status':'unknown'})

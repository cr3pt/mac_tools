import time, uuid, json
from pathlib import Path
class Observability:
    def __init__(self, root):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True); self.metrics = self.root/'metrics.json'; self.logs = self.root/'aggregated.log'; self.traces = self.root/'traces.jsonl'
        if not self.metrics.exists(): self.metrics.write_text(json.dumps({'jobs_total':0,'jobs_error':0,'sessions_total':0,'last_updated':time.time()}), encoding='utf-8')
    def trace_id(self): return str(uuid.uuid4())
    def log(self, level, message, trace_id=''):
        line = json.dumps({'ts':time.time(),'level':level,'trace_id':trace_id,'message':message})
        for p in [self.logs, self.traces]:
            prev = p.read_text(encoding='utf-8') if p.exists() else ''
            p.write_text(prev + line + '\n', encoding='utf-8')
    def inc(self, key):
        data=json.loads(self.metrics.read_text(encoding='utf-8')); data[key]=data.get(key,0)+1; data['last_updated']=time.time(); self.metrics.write_text(json.dumps(data), encoding='utf-8')
    def get_metrics(self): return json.loads(self.metrics.read_text(encoding='utf-8'))
    def prometheus_text(self):
        m=self.get_metrics(); return '\n'.join([f'noriben_{k} {v}' for k,v in m.items() if isinstance(v,(int,float))])

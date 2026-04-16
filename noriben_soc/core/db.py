import json
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from .models import Base, User, AnalysisSession, JobRecord
from .config import settings
class DB:
    def __init__(self, url=None):
        self.url = url or settings.db_url
        self.engine = create_engine(self.url, future=True)
        self.Session = sessionmaker(self.engine, future=True)
        Base.metadata.create_all(self.engine)
    def ensure_user(self, username, password_hash, role):
        with self.Session() as s:
            obj = s.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if not obj: s.add(User(username=username, password_hash=password_hash, role=role)); s.commit()
    def get_user(self, username):
        with self.Session() as s:
            obj = s.execute(select(User).where(User.username == username)).scalar_one_or_none()
            return {'username':obj.username,'password_hash':obj.password_hash,'role':obj.role} if obj else None
    def upsert_job(self, job_id, celery_id, trace_id, status):
        with self.Session() as s:
            obj = s.execute(select(JobRecord).where(JobRecord.job_id == job_id)).scalar_one_or_none()
            if not obj: s.add(JobRecord(job_id=job_id, celery_id=celery_id, trace_id=trace_id, status=status))
            else:
                obj.celery_id = celery_id; obj.trace_id = trace_id; obj.status = status
            s.commit()
    def get_job(self, job_id):
        with self.Session() as s:
            obj = s.execute(select(JobRecord).where(JobRecord.job_id == job_id)).scalar_one_or_none()
            return {'job_id':obj.job_id,'celery_id':obj.celery_id,'trace_id':obj.trace_id,'status':obj.status} if obj else None
    def upsert_analysis(self, data):
        with self.Session() as s:
            obj = s.execute(select(AnalysisSession).where(AnalysisSession.session_id == data['session_id'])).scalar_one_or_none()
            payload = {'sample_name':data['sample_name'],'sha256':data['sha256'],'status':data['status'],'assignee':data.get('assignee'),'severity':data['severity'],'confidence':data['confidence'],'static_score':data['static_score'],'dynamic_score':data['dynamic_score'],'mitre_json':json.dumps(data.get('mitre',[])),'iocs_json':json.dumps(data.get('iocs',[])),'findings_json':json.dumps(data.get('findings',[])),'events_json':json.dumps(data.get('events',[])),'artifacts_json':json.dumps(data.get('artifacts',[])),'comments_json':json.dumps(data.get('comments',[])),'meta_json':json.dumps(data.get('meta',{}))}
            if not obj: s.add(AnalysisSession(session_id=data['session_id'], **payload))
            else:
                for k,v in payload.items(): setattr(obj, k, v)
            s.commit()
    def list_analysis(self):
        with self.Session() as s:
            rows = s.execute(select(AnalysisSession)).scalars().all()
            return [{'session_id':r.session_id,'sample_name':r.sample_name,'status':r.status,'assignee':r.assignee,'severity':r.severity,'confidence':r.confidence,'static_score':r.static_score,'dynamic_score':r.dynamic_score} for r in rows]
    def get_analysis(self, session_id):
        with self.Session() as s:
            r = s.execute(select(AnalysisSession).where(AnalysisSession.session_id == session_id)).scalar_one_or_none()
            if not r: return None
            return {'session_id':r.session_id,'sample_name':r.sample_name,'sha256':r.sha256,'status':r.status,'assignee':r.assignee,'severity':r.severity,'confidence':r.confidence,'static_score':r.static_score,'dynamic_score':r.dynamic_score,'mitre':json.loads(r.mitre_json),'iocs':json.loads(r.iocs_json),'findings':json.loads(r.findings_json),'events':json.loads(r.events_json),'artifacts':json.loads(r.artifacts_json),'comments':json.loads(r.comments_json),'meta':json.loads(r.meta_json)}

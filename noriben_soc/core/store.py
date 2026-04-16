from pathlib import Path
import json
from .models import SessionRecord, CanonicalEvent

class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.sessions_dir = self.root / 'sessions'
        self.sessions_dir.mkdir(exist_ok=True)
    def save_session(self, session: SessionRecord):
        sdir = self.sessions_dir / session.session_id
        sdir.mkdir(parents=True, exist_ok=True)
        (sdir / 'session.json').write_text(json.dumps(session.to_dict(), indent=2, ensure_ascii=False), encoding='utf-8')
        return sdir
    def load_session(self, session_id: str):
        p = self.sessions_dir / session_id / 'session.json'
        data = json.loads(p.read_text(encoding='utf-8'))
        events = [CanonicalEvent(**e) for e in data.pop('events', [])]
        s = SessionRecord(**data)
        s.events = events
        return s
    def list_sessions(self):
        out = []
        for p in sorted(self.sessions_dir.glob('*/session.json')):
            data = json.loads(p.read_text(encoding='utf-8'))
            out.append({'session_id': data['session_id'], 'sample_name': data['sample_name'], 'severity': data['severity'], 'confidence': data['confidence'], 'status': data['status'], 'static_score': data['static_score'], 'dynamic_score': data['dynamic_score']})
        return out

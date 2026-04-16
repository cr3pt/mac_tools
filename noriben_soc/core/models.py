from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

@dataclass
class CanonicalEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    host: Dict[str, Any]
    process: Dict[str, Any]
    file: Dict[str, Any] = field(default_factory=dict)
    registry: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    tags: List[str] = field(default_factory=list)
    def to_dict(self): return asdict(self)

@dataclass
class SessionRecord:
    session_id: str
    sample_name: str
    sha256: str
    status: str = 'new'
    assignee: Optional[str] = None
    severity: str = 'low'
    confidence: str = 'low'
    static_score: int = 0
    dynamic_score: int = 0
    mitre: List[str] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    events: List[CanonicalEvent] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        d = asdict(self)
        d['events'] = [e.to_dict() for e in self.events]
        return d

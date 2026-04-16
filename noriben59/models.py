from dataclasses import dataclass, field
from pathlib import Path
from typing import List

@dataclass
class Finding:
    kind: str
    description: str
    score: int = 0
    vm: str = ''
    mitre: str = ''

@dataclass
class TimelineEvent:
    source: str
    category: str
    event: str
    vm: str = ''
    mitre: str = ''

@dataclass
class VMConfig:
    name: str
    arch: str
    disk: Path
    snapshot: str
    mem: str
    smp: int
    ssh_port: int
    monitor_port: int
    pidfile: Path
    logfile: Path

@dataclass
class SampleSession:
    sample_file: Path
    sample_id: str
    session_dir: Path
    log_file: Path
    audit_file: Path
    static_score: int = 0
    dynamic_score: int = 0
    static_findings: List[Finding] = field(default_factory=list)
    dynamic_findings: List[Finding] = field(default_factory=list)
    sigma_hits: List[str] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    mitre_hits: List[str] = field(default_factory=list)
    reports: List[Path] = field(default_factory=list)
    evtx_summaries: List[Path] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

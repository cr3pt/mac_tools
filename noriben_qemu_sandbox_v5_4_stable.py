#!/usr/bin/env python3
import argparse, csv, hashlib, html, json, os, re, shutil, signal, subprocess, threading, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

VERSION = "5.4.0-python-orchestrator-stable"
HOME = Path.home()
HOST_TOOLS_DIR = Path(os.getenv("HOST_TOOLS_DIR", HOME / "NoribenTools"))
HOST_RESULTS_DIR = Path(os.getenv("HOST_RESULTS_DIR", HOME / "NoribenResults"))

DEFAULT_CONFIG = {
    "analysis_timeout": 300,
    "analysis_profile": "balanced",
    "dual_vm_mode": False,
    "parallel_dual_vm": True,
    "preflight_strict": True,
    "retry_count": 3,
    "retry_delay": 3,
    "qemu_disk": str(HOST_TOOLS_DIR / "windows_arm_sandbox.qcow2"),
    "qemu_snapshot": "Baseline_Clean",
    "qemu_mem": "16G",
    "qemu_smp": 4,
    "qemu_ssh_port": 2222,
    "qemu_monitor_port": 4444,
    "qemu_disk_x86": str(HOST_TOOLS_DIR / "windows_x86_sandbox.qcow2"),
    "qemu_snapshot_x86": "Baseline_Clean",
    "qemu_mem_x86": "8G",
    "qemu_smp_x86": 4,
    "qemu_ssh_port_x86": 2223,
    "qemu_monitor_port_x86": 4445,
    "vm_user": "Administrator",
    "vm_python": r"C:\\Python3\\python.exe",
    "vm_noriben": r"C:\\Tools\\Noriben.py",
    "vm_malware_dir": r"C:\\Malware",
    "vm_output_dir": r"C:\\NoribenLogs",
}

MITRE_MAP = {
    "powershell": "T1059.001",
    "rundll32": "T1218.011",
    "regsvr32": "T1218.010",
    "mshta": "T1218.005",
    "wmic": "T1047",
    "certutil": "T1105",
    "bitsadmin": "T1197",
    "lsass": "T1003.001",
    "MiniDumpWriteDump": "T1003.001",
    "Set-MpPreference": "T1562.001",
    "vssadmin": "T1490",
    "CurrentVersion\\Run": "T1547.001",
    "schtasks": "T1053.005",
}

SIGMA_RULES = {
    "Suspicious PowerShell": ["powershell", "-enc", "FromBase64String", "DownloadString", "Invoke-WebRequest"],
    "LOLBins Download or Exec": ["rundll32", "regsvr32", "mshta", "wmic", "certutil", "bitsadmin"],
    "Credential Access": ["lsass", "MiniDumpWriteDump", "sekurlsa", "LogonPasswords"],
    "Defense Evasion": ["Set-MpPreference", "DisableRealtimeMonitoring", "vssadmin", "wevtutil cl"],
    "Persistence": [r"CurrentVersion\\Run", r"CurrentVersion\\RunOnce", "schtasks", "Startup"],
}

@dataclass
class Finding:
    kind: str
    description: str
    score: int = 0
    vm: str = ""
    mitre: str = ""

@dataclass
class TimelineEvent:
    source: str
    category: str
    event: str
    vm: str = ""
    mitre: str = ""

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
    stage_status: List[dict] = field(default_factory=list)
    vm_result_dirs: List[Path] = field(default_factory=list)
    reports: List[Path] = field(default_factory=list)
    evtx_summaries: List[Path] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class StableOrchestrator:
    def __init__(self):
        self.cfg = dict(DEFAULT_CONFIG)
        self.args = None
        self.root_session_id = time.strftime("%Y%m%d_%H%M%S")
        self.root_dir = HOST_RESULTS_DIR / f"campaign_{self.root_session_id}"
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.run_log = self.root_dir / "campaign.log"

    def run(self, cmd, capture=True):
        try:
            res = subprocess.run(cmd, text=True, capture_output=capture)
            return res.returncode, res.stdout if capture else "", res.stderr if capture else ""
        except Exception as e:
            return 1, "", str(e)

    def log(self, level, msg, session: Optional[SampleSession] = None):
        line = f"[{level}] {time.strftime('%H:%M:%S')} {msg}"
        print(line)
        with self.run_log.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        if session:
            with session.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            with session.audit_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "level": level, "msg": msg}, ensure_ascii=False) + "\n")

    def parse_args(self):
        p = argparse.ArgumentParser(description="Noriben QEMU Sandbox v5.4 stable")
        p.add_argument("sample", nargs="?", help="plik lub katalog do analizy")
        p.add_argument("--config")
        p.add_argument("--profile")
        p.add_argument("--dual-vm", action="store_true")
        p.add_argument("--preflight-only", action="store_true")
        p.add_argument("--static-only", action="store_true")
        p.add_argument("--dynamic-only", action="store_true")
        p.add_argument("--no-revert", action="store_true")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--batch", action="store_true")
        self.args = p.parse_args()

    def parse_scalar(self, val, current):
        val = val.strip().strip('"').strip("'")
        if isinstance(current, bool): return val.lower() in {"1","true","yes","y"}
        if isinstance(current, int):
            try: return int(val)
            except: return current
        return val

    def load_config(self):
        if not self.args.config: return
        path = Path(self.args.config)
        if not path.is_file(): raise SystemExit(f"Brak config: {path}")
        stack = []
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip() or raw.strip().startswith("#"): continue
            indent = len(raw) - len(raw.lstrip())
            line = raw.strip()
            while stack and stack[-1][0] >= indent: stack.pop()
            if ":" in line and "=" not in line: key, val = line.split(":", 1)
            elif "=" in line: key, val = line.split("=", 1)
            else: continue
            key = key.strip().lower().replace('-', '_')
            full = "_".join([x[1] for x in stack] + [key]) if stack else key
            if val.strip() == "":
                stack.append((indent, key))
                continue
            if full in self.cfg:
                self.cfg[full] = self.parse_scalar(val, self.cfg[full])

    def dump_effective_config(self):
        (self.root_dir / "effective_config.json").write_text(json.dumps(self.cfg, indent=2, ensure_ascii=False), encoding="utf-8")

    def apply_profile(self):
        profile = self.args.profile or self.cfg["analysis_profile"]
        self.cfg["analysis_profile"] = profile
        if profile == "quick": self.cfg["analysis_timeout"] = 180
        elif profile == "deep": self.cfg["analysis_timeout"] = 900
        elif profile == "ransomware": self.cfg["analysis_timeout"] = 600
        elif profile == "lolbins": self.cfg["analysis_timeout"] = 420
        if self.args.dual_vm: self.cfg["dual_vm_mode"] = True

    def build_vm(self, name, arch, disk_key, snap_key, mem_key, smp_key, ssh_key, mon_key, session_dir):
        return VMConfig(name, arch, Path(self.cfg[disk_key]), self.cfg[snap_key], self.cfg[mem_key], int(self.cfg[smp_key]), int(self.cfg[ssh_key]), int(self.cfg[mon_key]), session_dir / f"{name}.pid", session_dir / f"{name}.qemu.log")

    def preflight(self):
        missing = []
        for tool in ["python3", "ssh", "scp", "qemu-img"]:
            if not shutil.which(tool): missing.append(tool)
        if not (shutil.which("qemu-system-aarch64") or shutil.which("qemu-system-x86_64")): missing.append("qemu-system-*")
        if missing and self.cfg["preflight_strict"]:
            raise SystemExit("Brak narzędzi: " + ", ".join(missing))

    def retry_cmd(self, func, *args, label="operation", **kwargs):
        tries, delay = int(self.cfg.get("retry_count", 3)), int(self.cfg.get("retry_delay", 3))
        last = (1, "", "retry exhausted")
        for i in range(1, tries + 1):
            rc, out, err = func(*args, **kwargs)
            if rc == 0: return rc, out, err
            last = (rc, out, err)
            time.sleep(delay)
        return last

    def ssh_raw(self, vm: VMConfig, command: str):
        return self.run(["ssh","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o","LogLevel=ERROR","-o","ConnectTimeout=10","-p",str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1",command])

    def ssh(self, vm: VMConfig, command: str, required=False):
        if self.args.dry_run: return 0, "", ""
        rc,out,err = self.retry_cmd(self.ssh_raw, vm, command)
        if required and rc != 0: raise RuntimeError(f"SSH failed on {vm.name}: {err or out}")
        return rc,out,err

    def scp_to_raw(self, vm: VMConfig, src: Path, dst: str):
        return self.run(["scp","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o","LogLevel=ERROR","-P",str(vm.ssh_port),str(src),f"{self.cfg['vm_user']}@127.0.0.1:{dst}"])

    def scp_from_raw(self, vm: VMConfig, src: str, dst: Path):
        return self.run(["scp","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o","LogLevel=ERROR","-P",str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1:{src}",str(dst)])

    def scp_to(self, vm: VMConfig, src: Path, dst: str, required=False):
        if self.args.dry_run: return 0, "", ""
        rc,out,err = self.retry_cmd(self.scp_to_raw, vm, src, dst)
        if required and rc != 0: raise RuntimeError(f"SCP to failed {vm.name}: {err or out}")
        return rc,out,err

    def scp_from(self, vm: VMConfig, src: str, dst: Path, required=False):
        if self.args.dry_run: return 0, "", ""
        rc,out,err = self.retry_cmd(self.scp_from_raw, vm, src, dst)
        if required and rc != 0: raise RuntimeError(f"SCP from failed {vm.name}: {err or out}")
        return rc,out,err

    def revert_snapshot(self, vm: VMConfig):
        if self.args.dry_run: return
        rc,_,err = self.run(["qemu-img", "snapshot", "-a", vm.snapshot, str(vm.disk)])
        if rc != 0: raise RuntimeError(f"Snapshot failed {vm.name}: {err}")

    def qemu_bin(self, arch):
        return shutil.which("qemu-system-aarch64") if arch == "aarch64" else shutil.which("qemu-system-x86_64")

    def start_vm(self, vm: VMConfig):
        if self.args.dry_run: return
        qbin = self.qemu_bin(vm.arch)
        if not qbin: raise RuntimeError(f"Brak QEMU dla {vm.arch}")
        host_arch = os.uname().machine
        if vm.arch == "aarch64":
            accel = ["-machine", "virt,accel=hvf:tcg", "-cpu", "host"] if host_arch == "arm64" else ["-machine","virt,accel=tcg","-cpu","max"]
            netdev = ["-device", "virtio-net-device,netdev=net0"]
        else:
            accel = ["-machine", "q35,accel=tcg", "-cpu", "qemu64"] if host_arch == "arm64" else ["-machine","q35,accel=hvf:tcg","-cpu","host"]
            netdev = ["-device", "virtio-net-pci,netdev=net0"]
        cmd = [qbin, *accel, "-m", str(vm.mem), "-smp", str(vm.smp), "-drive", f"file={vm.disk},format=qcow2,if=virtio,cache=writeback", "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{vm.ssh_port}-:22,restrict=on", *netdev, "-monitor", f"tcp:127.0.0.1:{vm.monitor_port},server,nowait", "-display", "none", "-daemonize", "-pidfile", str(vm.pidfile)]
        with vm.logfile.open("w", encoding="utf-8") as logf:
            proc = subprocess.run(cmd, stdout=logf, stderr=logf, text=True)
        if proc.returncode != 0: raise RuntimeError(f"Start VM failed {vm.name}")

    def wait_for_ssh(self, vm: VMConfig, timeout=120):
        if self.args.dry_run: return
        start = time.time()
        while time.time() - start < timeout:
            rc,out,_ = self.run(["ssh","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o","LogLevel=ERROR","-o","ConnectTimeout=5","-p",str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1","echo ready"])
            if rc == 0 and "ready" in out: return
            time.sleep(3)
        raise RuntimeError(f"SSH timeout {vm.name}")

    def prepare_vm(self, vm: VMConfig):
        self.ssh(vm, f"cmd /c \"mkdir {self.cfg['vm_malware_dir']} {self.cfg['vm_output_dir']} C:\\Tools 2>nul & exit 0\"", required=True)
        noriben = HOST_TOOLS_DIR / "Noriben.py"
        if noriben.is_file(): self.scp_to(vm, noriben, self.cfg["vm_noriben"], required=True)

    def map_mitre(self, text: str, session: SampleSession):
        hits = []
        for k, v in MITRE_MAP.items():
            if k.lower() in text.lower() and v not in hits:
                hits.append(v)
        for h in hits:
            if h not in session.mitre_hits: session.mitre_hits.append(h)
        return ",".join(hits)

    def static_analysis(self, sample: Path, session: SampleSession):
        data = sample.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        session.static_findings.append(Finding("static", f"SHA256: {sha256}", 5))
        session.static_score += 5
        (session.session_dir / "sample_sha256.txt").write_text(sha256, encoding="utf-8")

    def run_noriben(self, vm: VMConfig, remote_sample: str):
        ps = f"Start-Process -FilePath '{self.cfg['vm_python']}' -ArgumentList '{self.cfg['vm_noriben']}','--cmd','{remote_sample}','--timeout','{self.cfg['analysis_timeout']}','--output','{self.cfg['vm_output_dir']}','--headless','--generalize' -Wait -NoNewWindow -RedirectStandardOutput '{self.cfg['vm_output_dir']}\\noriben_stdout.txt' -RedirectStandardError '{self.cfg['vm_output_dir']}\\noriben_stderr.txt'"
        self.ssh(vm, f'powershell -Command "{ps}"', required=True)

    def collect_results(self, vm: VMConfig, outdir: Path):
        outdir.mkdir(parents=True, exist_ok=True)
        if self.args.dry_run: return outdir
        zip_remote = self.cfg["vm_output_dir"] + r"\results.zip"
        rc,_,_ = self.ssh(vm, f'powershell -Command "Compress-Archive -Path {self.cfg["vm_output_dir"]}\\* -DestinationPath {zip_remote} -Force"')
        local_zip = outdir / "results.zip"
        if rc == 0:
            self.scp_from(vm, zip_remote, local_zip, required=False)
            if local_zip.exists() and shutil.which("unzip"):
                subprocess.run(["unzip","-o",str(local_zip),"-d",str(outdir)], capture_output=True, text=True)
        if not any(outdir.iterdir()):
            rc,out,_ = self.ssh(vm, f'powershell -Command "Get-ChildItem {self.cfg["vm_output_dir"]} | Select-Object -ExpandProperty Name"')
            if rc == 0:
                for name in [x.strip() for x in out.splitlines() if x.strip()]:
                    self.scp_from(vm, self.cfg["vm_output_dir"] + '\\' + name, outdir / name, required=False)
        return outdir

    def sigma_scan_text(self, report_text: str, vm_name: str, session: SampleSession):
        for title, pats in SIGMA_RULES.items():
            matched = []
            for pat in pats:
                for line in report_text.splitlines():
                    if pat.lower() in line.lower() and line.strip() not in matched:
                        matched.append(line.strip())
            if matched:
                mitre = self.map_mitre("\n".join(matched), session)
                session.sigma_hits.append(f"{vm_name}:{title}")
                session.dynamic_findings.append(Finding("dynamic", f"SIGMA-like: {title}", 8, vm=vm_name, mitre=mitre))
                session.dynamic_score += 8
                for m in matched[:5]:
                    session.timeline.append(TimelineEvent("SIGMA", title, m, vm=vm_name, mitre=mitre))

    def ingest_evtx_sysmon(self, srcdir: Path, vm_name: str, session: SampleSession):
        out = session.session_dir / f"{vm_name}_evtx_sysmon_summary.txt"
        lines = []
        try:
            import Evtx.Evtx as PyEvtx  # type: ignore
            for evtx in srcdir.rglob("*.evtx"):
                try:
                    with PyEvtx.Evtx(str(evtx)) as log:
                        for idx, rec in enumerate(log.records()):
                            if idx >= 200: break
                            xml = rec.xml()
                            if re.search(r'powershell|rundll32|regsvr32|mshta|wmic|schtasks|lsass|vssadmin', xml, re.I):
                                lines.append(f"=== {evtx.name} ===")
                                lines.append(xml[:1000])
                except Exception:
                    pass
        except Exception:
            patt = re.compile(r"powershell|cmd.exe|rundll32|regsvr32|mshta|wmic|schtasks|lsass|vssadmin|defender|RunOnce|CurrentVersion\\Run", re.I)
            for f in srcdir.rglob("*"):
                if f.suffix.lower() in {".evtx", ".xml", ".txt"} or "sysmon" in f.name.lower():
                    try: txt = f.read_text(encoding="utf-8", errors="ignore")
                    except: continue
                    for ln in txt.splitlines():
                        if patt.search(ln): lines.append(ln.strip())
        if lines:
            out.write_text("\n".join(lines[:500]), encoding="utf-8")
            session.evtx_summaries.append(out)
            for ln in lines[:50]:
                mitre = self.map_mitre(ln, session)
                session.timeline.append(TimelineEvent("EVTX/SYSMON", "event", ln[:500], vm=vm_name, mitre=mitre))

    def analyze_results(self, srcdir: Path, vm_name: str, session: SampleSession):
        reports = list(srcdir.rglob("Noriben_*.txt")) + list(srcdir.rglob("*stdout*.txt")) + list(srcdir.rglob("*stderr*.txt"))
        text = "\n".join(r.read_text(encoding="utf-8", errors="ignore") for r in reports if r.exists())
        patterns = {
            "Nowe procesy": r"Process Create|CreateProcess|Spawned",
            "Sieć": r"TCP|UDP|Connect|DNS",
            "Persistence": r"RunOnce|CurrentVersion\\Run|schtasks|Startup",
            "Injection": r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread",
            "Defense evasion": r"Set-MpPreference|DisableRealtimeMonitoring|vssadmin|wevtutil",
        }
        for cat, rx in patterns.items():
            matches = re.findall(rx + r".*", text, flags=re.I)
            if matches:
                mitre = self.map_mitre("\n".join(matches), session)
                session.dynamic_findings.append(Finding("dynamic", f"{vm_name}: {cat}", 12, vm=vm_name, mitre=mitre))
                session.dynamic_score += 12
                for m in matches[:5]:
                    session.timeline.append(TimelineEvent(vm_name, cat, m.strip(), vm=vm_name, mitre=mitre))
        self.sigma_scan_text(text, vm_name, session)
        self.ingest_evtx_sysmon(srcdir, vm_name, session)

    def stop_vm(self, vm: VMConfig):
        if self.args.dry_run or not vm.pidfile.exists(): return
        try:
            pid = int(vm.pidfile.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        except Exception:
            pass

    def compare_vm_results(self, session: SampleSession):
        vm1_find = {f.description for f in session.dynamic_findings if f.vm == 'vm1'}
        vm2_find = {f.description for f in session.dynamic_findings if f.vm == 'vm2'}
        if not vm1_find and not vm2_find: return
        (session.session_dir / 'vm_comparison.json').write_text(json.dumps({
            'common': sorted(vm1_find & vm2_find),
            'only_vm1': sorted(vm1_find - vm2_find),
            'only_vm2': sorted(vm2_find - vm1_find),
        }, indent=2, ensure_ascii=False), encoding='utf-8')

    def export_session(self, session: SampleSession):
        with (session.session_dir / 'timeline.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(['source','category','event','vm','mitre'])
            for ev in session.timeline: w.writerow([ev.source, ev.category, ev.event, ev.vm, ev.mitre])
        with (session.session_dir / 'findings.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(['type','description','score','vm','mitre'])
            for x in session.static_findings + session.dynamic_findings: w.writerow([x.kind, x.description, x.score, x.vm, x.mitre])
        (session.session_dir / 'session_summary.json').write_text(json.dumps({
            'version': VERSION,
            'sample': str(session.sample_file),
            'profile': self.cfg['analysis_profile'],
            'static_score': session.static_score,
            'dynamic_score': session.dynamic_score,
            'sigma_hits': session.sigma_hits,
            'mitre_hits': session.mitre_hits,
            'timeline_count': len(session.timeline),
            'errors': session.errors,
            'evtx_summaries': [str(x) for x in session.evtx_summaries],
        }, indent=2, ensure_ascii=False), encoding='utf-8')
        total = min(100, session.static_score + session.dynamic_score // 2)
        sigmas = ''.join(f'<li>{html.escape(x)}</li>' for x in session.sigma_hits) or '<li>Brak</li>'
        mitres = ''.join(f'<li>{html.escape(x)}</li>' for x in sorted(set(session.mitre_hits))) or '<li>Brak</li>'
        statics = ''.join(f'<li>{html.escape(x.description)} ({x.score})</li>' for x in session.static_findings) or '<li>Brak</li>'
        dynamics = ''.join(f'<li>{html.escape(x.vm + ": " if x.vm else "")}{html.escape(x.description)} ({x.score}) {html.escape(x.mitre)}</li>' for x in session.dynamic_findings) or '<li>Brak</li>'
        timeline = ''.join(f'<tr><td>{html.escape(e.vm)}</td><td>{html.escape(e.source)}</td><td>{html.escape(e.category)}</td><td>{html.escape(e.event)}</td><td>{html.escape(e.mitre)}</td></tr>' for e in session.timeline[:400]) or '<tr><td colspan="5">Brak</td></tr>'
        report = session.session_dir / f'REPORT_{session.sample_id}.html'
        report.write_text(f'''<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>Report</title><style>body{{font-family:Arial,sans-serif;background:#0b1220;color:#e5e7eb;padding:24px}}.card{{background:#111827;border:1px solid #374151;border-radius:12px;padding:16px;margin:12px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top}}h1,h2{{color:#93c5fd}}.score{{font-size:32px;font-weight:bold;color:#fca5a5}}</style></head><body><h1>Noriben QEMU Sandbox Stable Report</h1><div class="card"><p>Wersja: {VERSION}</p><p>Próbka: {html.escape(str(session.sample_file))}</p><p>Profil: {html.escape(self.cfg['analysis_profile'])}</p><p>Wynik: <span class="score">{total}/100</span></p></div><div class="card"><h2>MITRE ATT&CK</h2><ul>{mitres}</ul></div><div class="card"><h2>Static</h2><ul>{statics}</ul></div><div class="card"><h2>Dynamic</h2><ul>{dynamics}</ul></div><div class="card"><h2>SIGMA</h2><ul>{sigmas}</ul></div><div class="card"><h2>Timeline</h2><table><thead><tr><th>VM</th><th>Źródło</th><th>Kategoria</th><th>Zdarzenie</th><th>MITRE</th></tr></thead><tbody>{timeline}</tbody></table></div></body></html>''', encoding='utf-8')
        session.reports.append(report)
        self.compare_vm_results(session)

    def build_sample_queue(self):
        if not self.args.sample: return []
        p = Path(self.args.sample).expanduser().resolve()
        if p.is_file(): return [p]
        if p.is_dir() and self.args.batch: return [x for x in p.iterdir() if x.is_file()]
        raise SystemExit(f"Nieprawidłowa ścieżka próbki: {p}")

    def new_sample_session(self, sample: Path):
        sample_id = re.sub(r'[^A-Za-z0-9._-]+', '_', sample.stem)[:80]
        sdir = self.root_dir / sample_id
        sdir.mkdir(parents=True, exist_ok=True)
        return SampleSession(sample, sample_id, sdir, sdir / 'sample.log', sdir / 'audit.jsonl')

    def run_vm_pipeline(self, vm: VMConfig, sample: Path, session: SampleSession, label: str):
        try:
            if not self.args.no_revert: self.revert_snapshot(vm)
            self.start_vm(vm)
            self.wait_for_ssh(vm)
            self.prepare_vm(vm)
            remote_sample = self.cfg['vm_malware_dir'] + '\\' + sample.name
            self.scp_to(vm, sample, remote_sample, required=True)
            self.run_noriben(vm, remote_sample)
            result_dir = self.collect_results(vm, session.session_dir / label)
            session.vm_result_dirs.append(result_dir)
            self.analyze_results(result_dir, label, session)
        except Exception as e:
            session.errors.append(f"{label}: {e}")
            self.log('ERR', f'{label}: {e}', session)
        finally:
            self.stop_vm(vm)

    def process_sample(self, sample: Path):
        session = self.new_sample_session(sample)
        self.log('INFO', f'Analiza próbki: {sample.name}', session)
        if not self.args.dynamic_only:
            self.static_analysis(sample, session)
        if not self.args.static_only:
            vm1 = self.build_vm('vm1', 'aarch64', 'qemu_disk', 'qemu_snapshot', 'qemu_mem', 'qemu_smp', 'qemu_ssh_port', 'qemu_monitor_port', session.session_dir)
            vm2 = self.build_vm('vm2', 'x86_64', 'qemu_disk_x86', 'qemu_snapshot_x86', 'qemu_mem_x86', 'qemu_smp_x86', 'qemu_ssh_port_x86', 'qemu_monitor_port_x86', session.session_dir)
            if self.cfg['dual_vm_mode'] and vm2.disk.exists() and self.cfg.get('parallel_dual_vm', True):
                t1 = threading.Thread(target=self.run_vm_pipeline, args=(vm1, sample, session, 'vm1'))
                t2 = threading.Thread(target=self.run_vm_pipeline, args=(vm2, sample, session, 'vm2'))
                t1.start(); t2.start(); t1.join(); t2.join()
            else:
                self.run_vm_pipeline(vm1, sample, session, 'vm1')
                if self.cfg['dual_vm_mode'] and vm2.disk.exists():
                    self.run_vm_pipeline(vm2, sample, session, 'vm2')
        self.export_session(session)
        return session

    def export_campaign_summary(self, sessions: List[SampleSession]):
        with (self.root_dir / 'campaign_summary.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['sample','static_score','dynamic_score','errors','mitre_hits','report'])
            for s in sessions:
                w.writerow([str(s.sample_file), s.static_score, s.dynamic_score, ' | '.join(s.errors), ','.join(sorted(set(s.mitre_hits))), str(s.reports[0]) if s.reports else ''])
        (self.root_dir / 'campaign_summary.json').write_text(json.dumps([
            {
                'sample': str(s.sample_file),
                'static_score': s.static_score,
                'dynamic_score': s.dynamic_score,
                'errors': s.errors,
                'mitre_hits': s.mitre_hits,
                'reports': [str(x) for x in s.reports]
            } for s in sessions
        ], indent=2, ensure_ascii=False), encoding='utf-8')

    def main(self):
        self.parse_args()
        self.load_config()
        self.apply_profile()
        self.dump_effective_config()
        self.preflight()
        if self.args.preflight_only: return
        queue = self.build_sample_queue()
        sessions = [self.process_sample(sample) for sample in queue]
        self.export_campaign_summary(sessions)
        self.log('OK', f'Campaign ready: {self.root_dir}')

if __name__ == '__main__':
    StableOrchestrator().main()

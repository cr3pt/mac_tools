import argparse, hashlib, os, re, shutil, signal, subprocess, threading, time, json
from pathlib import Path
from .config import load_config
from .models import VMConfig, SampleSession, Finding
from .detection import analyze_text
from .reporting import export_session
from .platform_qemu import detect_host, choose_accel, build_qemu_cmd, recommend_profile
from .prepare import prepare_environment

VERSION = '5.9.0-guest-checklist'

class App:
    def __init__(self):
        self.args = None
        self.cfg = None
        self.host_info = detect_host()
        self.root_id = time.strftime('%Y%m%d_%H%M%S')
        self.root_dir = Path.home() / 'NoribenResults' / f'campaign_{self.root_id}'
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def parse_args(self):
        p = argparse.ArgumentParser(description='Noriben QEMU Sandbox v5.9 guest checklist')
        p.add_argument('sample', nargs='?')
        p.add_argument('--config')
        p.add_argument('--profile')
        p.add_argument('--dual-vm', action='store_true')
        p.add_argument('--batch', action='store_true')
        p.add_argument('--dry-run', action='store_true')
        p.add_argument('--preflight-only', action='store_true')
        p.add_argument('--static-only', action='store_true')
        p.add_argument('--dynamic-only', action='store_true')
        p.add_argument('--show-host-info', action='store_true')
        p.add_argument('--prepare', action='store_true')
        self.args = p.parse_args()
        self.cfg = load_config(self.args.config)
        if self.args.profile: self.cfg['analysis_profile'] = self.args.profile
        if self.args.dual_vm: self.cfg['dual_vm_mode'] = True
        if self.cfg.get('platform_profile', 'auto') == 'auto':
            self.cfg['platform_profile'] = recommend_profile(self.host_info)

    def preflight(self):
        for tool in ['python3','ssh','scp','qemu-img']:
            if not shutil.which(tool) and self.cfg['preflight_strict']:
                raise SystemExit(f'Brak narzędzia: {tool}')
        if self.args.show_host_info:
            print(json.dumps(self.host_info, indent=2, ensure_ascii=False))

    def build_vm(self, name, arch, disk_key, snap_key, mem_key, smp_key, ssh_key, mon_key, sdir):
        return VMConfig(name, arch, Path(self.cfg[disk_key]), self.cfg[snap_key], self.cfg[mem_key], int(self.cfg[smp_key]), int(self.cfg[ssh_key]), int(self.cfg[mon_key]), sdir / f'{name}.pid', sdir / f'{name}.qemu.log')

    def run(self, cmd, capture=True):
        try:
            res = subprocess.run(cmd, text=True, capture_output=capture)
            return res.returncode, res.stdout if capture else '', res.stderr if capture else ''
        except Exception as e:
            return 1, '', str(e)

    def ssh(self, vm, command):
        if self.args.dry_run: return 0, '', ''
        return self.run(['ssh','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','ConnectTimeout=10','-p',str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1",command])

    def scp_to(self, vm, src, dst):
        if self.args.dry_run: return 0, '', ''
        return self.run(['scp','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-P',str(vm.ssh_port),str(src),f"{self.cfg['vm_user']}@127.0.0.1:{dst}"])

    def scp_from(self, vm, src, dst):
        if self.args.dry_run: return 0, '', ''
        return self.run(['scp','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-P',str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1:{src}",str(dst)])

    def revert_snapshot(self, vm):
        if self.args.dry_run: return
        rc,_,err = self.run(['qemu-img','snapshot','-a',vm.snapshot,str(vm.disk)])
        if rc != 0: raise RuntimeError(err)

    def start_vm(self, vm):
        if self.args.dry_run: return
        accel = choose_accel(self.host_info, vm.arch, self.cfg.get('qemu_accel_mode', 'auto'))
        cmd = build_qemu_cmd(vm, accel, self.host_info)
        with vm.logfile.open('w', encoding='utf-8') as logf:
            proc = subprocess.run(cmd, stdout=logf, stderr=logf, text=True)
        if proc.returncode != 0: raise RuntimeError(f'Start VM failed {vm.name}')

    def wait_for_ssh(self, vm, timeout=120):
        if self.args.dry_run: return
        start = time.time()
        while time.time() - start < timeout:
            rc,out,_ = self.run(['ssh','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','ConnectTimeout=5','-p',str(vm.ssh_port),f"{self.cfg['vm_user']}@127.0.0.1",'echo ready'])
            if rc == 0 and 'ready' in out: return
            time.sleep(3)
        raise RuntimeError(f'SSH timeout {vm.name}')

    def prepare_vm(self, vm):
        self.ssh(vm, f"cmd /c \"mkdir {self.cfg['vm_malware_dir']} {self.cfg['vm_output_dir']} C:\\Tools 2>nul & exit 0\"")
        noriben = Path(self.cfg['host_tools_dir']) / 'Noriben.py'
        if noriben.is_file(): self.scp_to(vm, noriben, self.cfg['vm_noriben'])

    def static_analysis(self, sample, session):
        sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
        session.static_findings.append(Finding('static', f'SHA256: {sha256}', 5))
        session.static_score += 5
        (session.session_dir / 'sample_sha256.txt').write_text(sha256, encoding='utf-8')

    def collect_and_analyze(self, vm, sample, session, label):
        try:
            self.revert_snapshot(vm)
            self.start_vm(vm)
            self.wait_for_ssh(vm)
            self.prepare_vm(vm)
            remote_sample = self.cfg['vm_malware_dir'] + '\\' + sample.name
            self.scp_to(vm, sample, remote_sample)
            ps = f"Start-Process -FilePath '{self.cfg['vm_python']}' -ArgumentList '{self.cfg['vm_noriben']}','--cmd','{remote_sample}','--timeout','{self.cfg['analysis_timeout']}','--output','{self.cfg['vm_output_dir']}','--headless','--generalize' -Wait -NoNewWindow -RedirectStandardOutput '{self.cfg['vm_output_dir']}\\noriben_stdout.txt' -RedirectStandardError '{self.cfg['vm_output_dir']}\\noriben_stderr.txt'"
            self.ssh(vm, f'powershell -Command "{ps}"')
            outdir = session.session_dir / label
            outdir.mkdir(parents=True, exist_ok=True)
            if not self.args.dry_run:
                rc,out,_ = self.ssh(vm, f'powershell -Command "Get-ChildItem {self.cfg["vm_output_dir"]} | Select-Object -ExpandProperty Name"')
                if rc == 0:
                    for name in [x.strip() for x in out.splitlines() if x.strip()]:
                        self.scp_from(vm, self.cfg['vm_output_dir'] + '\\' + name, outdir / name)
            text = ''
            for f in outdir.rglob('*'):
                if f.is_file() and f.suffix.lower() in {'.txt', '.csv', '.log', '.xml'}:
                    text += '\n' + f.read_text(encoding='utf-8', errors='ignore')
            analyze_text(text, label, session)
        except Exception as e:
            session.errors.append(f'{label}: {e}')
        finally:
            if not self.args.dry_run and vm.pidfile.exists():
                try:
                    pid = int(vm.pidfile.read_text().strip())
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass

    def new_session(self, sample):
        sid = re.sub(r'[^A-Za-z0-9._-]+', '_', sample.stem)[:80]
        sdir = self.root_dir / sid
        sdir.mkdir(parents=True, exist_ok=True)
        return SampleSession(sample, sid, sdir, sdir / 'sample.log', sdir / 'audit.jsonl')

    def queue(self):
        if not self.args.sample: return []
        p = Path(self.args.sample).expanduser().resolve()
        if p.is_file(): return [p]
        if p.is_dir() and self.args.batch: return [x for x in p.iterdir() if x.is_file()]
        raise SystemExit('Nieprawidłowa ścieżka wejściowa')

    def process_sample(self, sample):
        session = self.new_session(sample)
        if not self.args.dynamic_only:
            self.static_analysis(sample, session)
        if not self.args.static_only:
            vm1 = self.build_vm('vm1','aarch64','qemu_disk','qemu_snapshot','qemu_mem','qemu_smp','qemu_ssh_port','qemu_monitor_port',session.session_dir)
            vm2 = self.build_vm('vm2','x86_64','qemu_disk_x86','qemu_snapshot_x86','qemu_mem_x86','qemu_smp_x86','qemu_ssh_port_x86','qemu_monitor_port_x86',session.session_dir)
            if self.cfg['dual_vm_mode'] and self.cfg['parallel_dual_vm'] and vm2.disk.exists():
                t1 = threading.Thread(target=self.collect_and_analyze, args=(vm1,sample,session,'vm1'))
                t2 = threading.Thread(target=self.collect_and_analyze, args=(vm2,sample,session,'vm2'))
                t1.start(); t2.start(); t1.join(); t2.join()
            else:
                self.collect_and_analyze(vm1, sample, session, 'vm1')
                if self.cfg['dual_vm_mode'] and vm2.disk.exists():
                    self.collect_and_analyze(vm2, sample, session, 'vm2')
        export_session(session, VERSION, self.cfg['analysis_profile'], self.host_info)
        return session

    def export_campaign(self, sessions):
        import csv, json
        with (self.root_dir / 'campaign_summary.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['sample','static_score','dynamic_score','errors','mitre_hits'])
            for s in sessions:
                w.writerow([str(s.sample_file), s.static_score, s.dynamic_score, ' | '.join(s.errors), ','.join(sorted(set(s.mitre_hits)))])
        (self.root_dir / 'campaign_summary.json').write_text(json.dumps([
            {'sample': str(s.sample_file), 'static_score': s.static_score, 'dynamic_score': s.dynamic_score, 'errors': s.errors, 'mitre_hits': s.mitre_hits} for s in sessions
        ], indent=2, ensure_ascii=False), encoding='utf-8')

    def main(self):
        self.parse_args()
        if self.args.prepare:
            prep_file, prep_script, guest_file, plan = prepare_environment(self.cfg)
            print(json.dumps({'prepare_file': str(prep_file), 'prepare_script': str(prep_script), 'guest_checklist_file': str(guest_file), 'plan': plan}, indent=2, ensure_ascii=False))
            return
        self.preflight()
        if self.args.preflight_only: return
        sessions = [self.process_sample(s) for s in self.queue()]
        self.export_campaign(sessions)

if __name__ == '__main__':
    App().main()

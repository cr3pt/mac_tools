"""Linux malware analyzer - dynamic analysis on Linux sandbox."""
import asyncio
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, TypedDict
import shutil
import sys
import platform

# Define TypedDict for result structure
class LinuxAnalysisResult(TypedDict, total=False):
    os: str
    processes: List[str]
    network_iocs: List[str]
    files_created: List[str]
    files_deleted: List[str]
    registry: List[str]
    api_calls: List[str]
    cpu_usage: float
    memory_usage: int
    exit_code: int
    timeout: bool
    scores: Dict[str, int]
    error: str

# Configure basic logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _ensure_tool(tool_name: str) -> None:
    """Check if a tool is available in PATH, otherwise try to install it via apt.
    Raises RuntimeError if installation fails.
    """
    if shutil.which(tool_name) is None:
        logger.info("%s not found, attempting to install...", tool_name)
        # Use apt-get for Debian/Ubuntu based systems
        install_cmd = ['sudo', 'apt-get', 'update', '-qq']
        subprocess.run(install_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        install_cmd = ['sudo', 'apt-get', 'install', '-y', tool_name]
        result = subprocess.run(install_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to install required tool: {tool_name}")
        logger.info("%s installed successfully.", tool_name)

def _get_trace_commands(sample_path: Path):
    """Return appropriate trace commands based on OS.
    For Linux use strace/ltrace, for macOS use dtrace.
    """
    if platform.system() == 'Darwin':
        # dtrace script to capture file, exec, network syscalls
        dtrace_script = "syscall::open*:entry, syscall::execve:entry, syscall::connect*:entry { printf(\"%s %s\\n\", probefunc, copyinstr(arg0)); }"
        dtrace_cmd = ['sudo', 'dtrace', '-n', dtrace_script, '-c', str(sample_path)]
        return {'trace_cmd': dtrace_cmd, 'type': 'dtrace'}
    else:
        strace_cmd = ['timeout', '30', 'strace', '-e', 'trace=file,process,network', '-o', '/tmp/strace.log', str(sample_path)]
        ltrace_cmd = ['timeout', '30', 'ltrace', '-e', '*', '-o', '/tmp/ltrace.log', str(sample_path)]
        return {'strace_cmd': strace_cmd, 'ltrace_cmd': ltrace_cmd, 'type': 'linux'}

async def _run_subprocess(cmd: List[str]) -> subprocess.CompletedProcess:
    """Run a subprocess asynchronously using asyncio.create_subprocess_exec.
    Returns a CompletedProcess-like object for compatibility.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode,
        stdout=stdout.decode(),
        stderr=stderr.decode(),
    )

async def run_linux_analysis(sample_path: Path) -> LinuxAnalysisResult:
    """Run dynamic analysis on Linux or macOS sandbox.
    Returns a dictionary with detailed analysis results.
    """
    # Ensure required external tools are present
    try:
        if platform.system() == 'Darwin':
            _ensure_tool('dtrace')
        else:
            _ensure_tool('strace')
            _ensure_tool('ltrace')
            _ensure_tool('timeout')
    except RuntimeError as e:
        logger.error(str(e))
        return {'error': str(e), 'os': platform.system()}

    if not sample_path.is_file():
        logger.error("Sample path does not exist or is not a file: %s", sample_path)
        return {'error': 'Invalid sample path', 'os': platform.system()}

    result: LinuxAnalysisResult = {
        'os': platform.system(),
        'processes': [],
        'network_iocs': [],
        'files_created': [],
        'files_deleted': [],
        'registry': [],
        'api_calls': [],
        'cpu_usage': 0.0,
        'memory_usage': 0,
        'exit_code': 0,
        'timeout': False,
        'scores': {'suspicious': 0, 'max': 0},
    }

    cmds = _get_trace_commands(sample_path)
    if cmds['type'] == 'linux':
        # Linux path – existing logic (unchanged) – use strace and ltrace
        strace_cmd = cmds['strace_cmd']
        ltrace_cmd = cmds['ltrace_cmd']
        proc_result = await _run_subprocess(strace_cmd)
        if proc_result.returncode == 124:
            result['timeout'] = True
            logger.warning('strace timed out')

        # Parse strace output if file exists
        strace_log = Path('/tmp/strace.log')
        ltrace_log = Path('/tmp/ltrace.log')
        if strace_log.exists():
            strace_output = strace_log.read_text()
            import re
            for line in strace_output.split('\n'):
                if re.search(r'\bopen\b', line) and 'ENOENT' not in line:
                    result['files_created'].append(line.strip())
                elif re.search(r'\bexecve\b', line):
                    result['processes'].append(line.strip())
                elif re.search(r'\bconnect\b', line):
                    result['network_iocs'].append(line.strip())
                    result['scores']['suspicious'] += 15
            # Additional suspicious checks
            if re.search(r'\bfork\b', strace_output):
                result['scores']['suspicious'] += 10
            if re.search(r'\bptrace\b', strace_output):
                result['scores']['suspicious'] += 30
            if re.search(r'\bsocket\b', strace_output):
                result['scores']['suspicious'] += 20
            # Clean up strace log
            try:
                strace_log.unlink()
            except Exception:
                pass

        # Run ltrace asynchronously
        ltrace_result = await _run_subprocess(ltrace_cmd)
        if ltrace_result.returncode == 124:
            result['timeout'] = True
            logger.warning('ltrace timed out')

        if ltrace_log.exists():
            ltrace_output = ltrace_log.read_text()
            result['api_calls'] = ltrace_output.split('\n')[:50]
            try:
                ltrace_log.unlink()
            except Exception:
                pass
    else:
        # macOS – use dtrace output directly
        dtrace_cmd = cmds['trace_cmd']
        dtrace_result = await _run_subprocess(dtrace_cmd)
        if dtrace_result.returncode != 0:
            result['error'] = 'dtrace failed'
            return result
        dtrace_output = dtrace_result.stdout
        import re
        for line in dtrace_output.split('\n'):
            if re.search(r'open', line):
                result['files_created'].append(line.strip())
            elif re.search(r'execve', line):
                result['processes'].append(line.strip())
            elif re.search(r'connect', line):
                result['network_iocs'].append(line.strip())
                result['scores']['suspicious'] += 15
        # macOS specific suspicious checks could be added similarly
        # No separate api_calls collection on macOS

    # Capture exit code if available
    if 'proc_result' in locals():
        result['exit_code'] = proc_result.returncode if proc_result else 0
    else:
        result['exit_code'] = dtrace_result.returncode if dtrace_result else 0

    result['scores']['max'] = min(result['scores']['suspicious'], 100)
    return result


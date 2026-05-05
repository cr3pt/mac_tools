"""Linux malware analyzer - dynamic analysis on Linux sandbox."""
import asyncio
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, TypedDict

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
    """Run dynamic analysis on Linux sandbox.
    Returns a dictionary with detailed analysis results.
    """
    if not sample_path.is_file():
        logger.error("Sample path does not exist or is not a file: %s", sample_path)
        return {'error': 'Invalid sample path', 'os': 'Linux'}

    result: LinuxAnalysisResult = {
        'os': 'Linux',
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

    strace_log = Path('/tmp/strace.log')
    ltrace_log = Path('/tmp/ltrace.log')

    # Run strace asynchronously
    strace_cmd = ['timeout', '30', 'strace', '-e', 'trace=file,process,network', '-o', str(strace_log), str(sample_path)]
    proc_result = await _run_subprocess(strace_cmd)
    if proc_result.returncode == 124:
        result['timeout'] = True
        logger.warning('strace timed out')

    # Parse strace output if file exists
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
    ltrace_cmd = ['timeout', '30', 'ltrace', '-e', '*', '-o', str(ltrace_log), str(sample_path)]
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

    # Capture exit code of the sample (from strace subprocess)
    result['exit_code'] = proc_result.returncode if proc_result else 0

    # Placeholder for resource usage (could be extended with psutil)
    result['cpu_usage'] = 0.0
    result['memory_usage'] = 0

    result['scores']['max'] = min(result['scores']['suspicious'], 100)
    return result


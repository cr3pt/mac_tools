import asyncio, hashlib, subprocess
from pathlib import Path
from .yara_engine      import run_yara_scan
from .sigma_engine     import run_sigma_scan
from .evtx_parser      import parse_evtx
from .qemu_engine      import run_dynamic_analysis
from .results_merger   import merge_dual_results
from .db               import save_result
from .linux_analyzer   import run_linux_analysis
from .cache import get_cached, set_cached
from noriben_soc.scanners.base import load_plugins

import logging
from noriben_soc.logging_config import configure_logging
from noriben_soc.config import settings

# Ensure logging configured according to settings
configure_logging()
logger = logging.getLogger('noriben')

async def analyze_sample(sample_path: Path) -> dict:
    logger.info('Starting analysis for %s', sample_path)
    raw    = sample_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    md5    = hashlib.md5(raw).hexdigest()
    sha1   = hashlib.sha1(raw).hexdigest()
    text   = raw.decode('utf-8', errors='ignore')

    yara_hits  = run_yara_scan(raw)
    sigma_hits = run_sigma_scan(text)
    evtx_evts  = parse_evtx(sample_path) if sample_path.suffix == '.evtx' else []

    strings = _extract_strings(raw)
    entropy = _calculate_entropy(raw)
    pe_info = _analyze_pe(raw) if sample_path.suffix in ('.exe', '.dll') else {}
    file_type = _detect_file_type(raw)

    # Additional scans
    vt_result = _check_virustotal(sha256)
    clam_result = _scan_clamav(sample_path)
    office_result = _analyze_office(sample_path) if sample_path.suffix in ('.doc', '.xls', '.docx', '.xlsx') else {}
    pdf_result = _analyze_pdf(sample_path) if sample_path.suffix == '.pdf' else {}
    otx_result = _check_otx(sha256)

    static_score = min(
        sum(25 for h in yara_hits  if h.get('severity') == 'HIGH')  +
        sum(15 for h in yara_hits  if h.get('severity') == 'MEDIUM')+
        sum(20 for h in sigma_hits if h.get('severity') == 'HIGH')  +
        sum(10 for h in sigma_hits if h.get('severity') == 'MEDIUM')+
        (50 if vt_result.get('positives', 0) > 0 else 0) +
        (30 if clam_result.get('infected') else 0), 100)

    # Run optional scanner plugins and cache their results
    plugin_results = []
    for plugin in load_plugins():
        cache_key = f"{plugin.__class__.__name__}:{sample_path}"
        cached = get_cached(plugin.__class__.__name__, str(sample_path))
        if cached is not None:
            plugin_results.append(cached)
            continue
        try:
            result = plugin.scan(str(sample_path))
            set_cached(plugin.__class__.__name__, str(sample_path), result)
            plugin_results.append(result)
        except Exception as e:
            logger.exception("Plugin %s failed", plugin.__class__.__name__)

    dynamic_win10 = None
    dynamic_win11 = None

    if static_score >= 70 or sample_path.suffix in ('.exe','.dll','.scr','.ps1'):
        # Rownolegla analiza na Win10 i Win11
        dynamic_win10, dynamic_win11 = await asyncio.gather(
            run_dynamic_analysis(sample_path, vm='win10'),
            run_dynamic_analysis(sample_path, vm='win11'),
        )

    # Additional analyses: Linux sandbox and memory analysis
    linux_dynamic = None
    memory_analysis = None
    if sample_path.suffix not in ('.evtx', '.pdf', '.doc', '.docx', '.xls', '.xlsx'):
        # Run Linux sandbox analysis in parallel with Windows if needed
        linux_dynamic = await run_linux_analysis(sample_path)
        # Simple memory analysis using Volatility if a memory dump is provided
        if sample_path.suffix in ('.raw', '.mem'):
            memory_analysis = await _analyze_memory(sample_path)

    # Polacz wyniki dual-VM
    merged = merge_dual_results(dynamic_win10, dynamic_win11)

    result = dict(
        sha256         = sha256,
        md5            = md5,
        sha1           = sha1,
        filename       = sample_path.name,
        file_size      = len(raw),
        file_type      = file_type,
        static         = dict(yara=yara_hits, sigma=sigma_hits, evtx=evtx_evts, strings=strings, entropy=entropy, pe=pe_info, vt=vt_result, clam=clam_result, office=office_result, pdf=pdf_result, otx=otx_result, score=static_score),
        dynamic_win10  = dynamic_win10,
        dynamic_win11  = dynamic_win11,
        dynamic_linux  = linux_dynamic,
        memory_analysis = memory_analysis,
        dynamic_merged = merged,
        severity       = max(static_score, merged.get('max_score', 0)),
        mitre          = _map_mitre(yara_hits + sigma_hits),
    )
    await save_result(result)
    logger.info('Analysis completed for %s, severity: %s', sample_path, result['severity'])
    _generate_report(result)
    _send_alert(result)
    return result

def _map_mitre(hits):
    m = {'powershell':'T1059.001','lsass':'T1003.001','wevtutil':'T1070.001',
         'reg add':'T1547.001','schtasks':'T1053.005','mimikatz':'T1003.001',
         'certutil':'T1140','mshta':'T1218.005','regsvr32':'T1218.010'}
    return list({tid for h in hits for kw,tid in m.items() if kw in h.get('rule','').lower()})

def _extract_strings(raw):
    """Extract printable strings from binary data."""
    strings = []
    current = b''
    for byte in raw:
        if 32 <= byte <= 126:  # printable ASCII
            current += bytes([byte])
        else:
            if len(current) >= 4:
                strings.append(current.decode('ascii', errors='ignore'))
            current = b''
    if len(current) >= 4:
        strings.append(current.decode('ascii', errors='ignore'))
    return strings[:100]  # limit to 100 strings

def _calculate_entropy(raw):
    """Calculate Shannon entropy of the data."""
    import math
    if not raw:
        return 0.0
    freq = {}
    for byte in raw:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = -sum((f / len(raw)) * math.log2(f / len(raw)) for f in freq.values())
    return round(entropy, 2)

def _analyze_pe(raw):
    """Analyze PE file using pefile if available."""
    try:
        import pefile
        pe = pefile.PE(data=raw)
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            for imp in entry.imports:
                if imp.name:
                    func = imp.name.decode('utf-8', errors='ignore')
                    imports.append(f'{dll}:{func}')
        sections = [s.Name.decode('utf-8', errors='ignore').strip('\x00') for s in pe.sections]
        return {'imports': imports[:50], 'sections': sections}
    except ImportError:
        return {'error': 'pefile not installed'}
    except Exception as e:
        return {'error': str(e)}

def _detect_file_type(raw):
    """Detect file type based on magic bytes."""
    if raw.startswith(b'MZ'):
        return 'PE Executable'
    elif raw.startswith(b'PK\x03\x04'):
        return 'ZIP Archive'
    elif raw.startswith(b'\x7fELF'):
        return 'ELF Executable'
    elif raw.startswith(b'%PDF'):
        return 'PDF Document'
    elif raw.startswith(b'#!/'):
        return 'Script'
    else:
        return 'Unknown'

def _check_virustotal(sha256):
    """Check file reputation using VirusTotal API."""
    try:
        if requests is None or not settings.VIRUSTOTAL_API_KEY:
            logger.debug('VirusTotal not configured or requests missing')
            return {}
        api_key = settings.VIRUSTOTAL_API_KEY
        url = f'https://www.virustotal.com/api/v3/files/{sha256}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    except Exception as e:
        logger.exception('VirusTotal check failed for %s', sha256)
        return {}

def _scan_clamav(sample_path):
    """Scan file using ClamAV."""
    try:
        result = subprocess.run(['clamscan', str(sample_path)], capture_output=True, text=True)
        if 'Infected files: 0' in result.stdout:
            return {'infected': False}
        else:
            return {'infected': True, 'details': result.stdout}
    except Exception as e:
        logger.exception('ClamAV scan failed for %s', sample_path)
        return {}

def _analyze_office(sample_path):
    """Extract metadata and macros from Office files."""
    try:
        import olefile
        from xml.etree import ElementTree as ET

        metadata = {}
        macros = []

        # Extract metadata
        if olefile.isOleFile(str(sample_path)):
            with olefile.OleFileIO(str(sample_path)) as ole:
                if ole.exists('SummaryInformation'):
                    stream = ole.openstream('SummaryInformation')
                    metadata['author'], metadata['title'], metadata['subject'], metadata['keywords'], metadata['last_modified_by'], metadata['created'], metadata['modified'] = stream.read().decode('utf-8', errors='ignore').split('\x00')[:7]
                if ole.exists('DocumentSummaryInformation'):
                    stream = ole.openstream('DocumentSummaryInformation')
                    metadata['company'], metadata['category'], metadata['content_status'], metadata['identifier'], metadata['language'], metadata['last_author'], metadata['revision_number'], metadata['version'] = stream.read().decode('utf-8', errors='ignore').split('\x00')[:8]

        # Extract macros
        if sample_path.suffix in ('.doc', '.docx'):
            xml_path = 'word/vbaProject.bin' if sample_path.suffix == '.docx' else 'vbaProject.bin'
            with olefile.OleFileIO(str(sample_path)) as ole:
                if ole.exists(xml_path):
                    with ole.openstream(xml_path) as stream:
                        content = stream.read()
                        if content.startswith(b'0x'):
                            content = content[2:]
                        macros.append(content.decode('utf-8', errors='ignore'))

        return {'metadata': metadata, 'macros': macros}
    except Exception as e:
        logger.exception('Office analysis failed for %s', sample_path)
        return {}

def _analyze_pdf(sample_path):
    """Extract metadata and text from PDF files."""
    try:
        from PyPDF2 import PdfReader

        metadata = {}
        text = ''

        with open(sample_path, 'rb') as f:
            reader = PdfReader(f)
            metadata = reader.metadata
            for page in reader.pages:
                text += page.extract_text() + '\n'

        return {'metadata': metadata, 'text': text}
    except Exception as e:
        logger.exception('PDF analysis failed for %s', sample_path)
        return {}

def _check_otx(sha256):
    """Check file reputation using OTX (Open Threat Exchange)."""
    try:
        api_key = 'YOUR_OTX_API_KEY'
        url = f'https://otx.alienvault.com/api/v1/indicators/sha256/{sha256}/general'
        headers = {'X-OTX-API-KEY': api_key}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get('pulse_info', {})
    except Exception as e:
        logger.exception('OTX check failed for %s', sha256)
        return {}

def _generate_report(result):
    """Generate a report for the analysis."""
    try:
        with open(f"{result['sha256']}_report.txt", "w") as report_file:
            report_file.write(f"Analysis Report for {result['filename']}\n")
            report_file.write(f"SHA256: {result['sha256']}\n")
            report_file.write(f"MD5: {result['md5']}\n")
            report_file.write(f"SHA1: {result['sha1']}\n")
            report_file.write(f"File Size: {result['file_size']} bytes\n")
            report_file.write(f"File Type: {result['file_type']}\n")
            report_file.write(f"Static Analysis Score: {result['static']['score']}\n")
            report_file.write(f"Dynamic Analysis (Win10): {result['dynamic_win10']}\n")
            report_file.write(f"Dynamic Analysis (Win11): {result['dynamic_win11']}\n")
            report_file.write(f"Linux Analysis: {result['dynamic_linux']}\n")
            report_file.write(f"VirusTotal Results: {result['static']['vt']}\n")
            report_file.write(f"ClamAV Results: {result['static']['clam']}\n")
            report_file.write(f"Office Analysis: {result['static']['office']}\n")
            report_file.write(f"PDF Analysis: {result['static']['pdf']}\n")
            report_file.write(f"OTX Results: {result['static']['otx']}\n")
            report_file.write(f"MITRE ATT&CK Tactics: {result['mitre']}\n")
            report_file.write(f"Severity: {result['severity']}\n")
        logger.info('Report generated for %s', result['filename'])
    except Exception as e:
        logger.exception('Report generation failed for %s', result['filename'])

def _send_alert(result):
    """Send an alert based on the analysis results."""
    try:
        if result['severity'] >= 70:
            # Send email alert (placeholder)
            logger.info('Alert sent for %s, severity: %s', result['filename'], result['severity'])
    except Exception as e:
        logger.exception('Alert sending failed for %s', result['filename'])

async def _analyze_memory(memory_dump_path):
    """Analyze memory dump using Volatility."""
    try:
        import subprocess
        results = {'processes': [], 'dlls': [], 'network': [], 'registry': []}

        # List processes
        proc_result = subprocess.run(['vol', '-f', str(memory_dump_path), 'windows.pslist'], 
                                   capture_output=True, text=True)
        if proc_result.returncode == 0:
            results['processes'] = proc_result.stdout.split('\n')[:20]  # limit

        # List loaded DLLs
        dll_result = subprocess.run(['vol', '-f', str(memory_dump_path), 'windows.dlllist'], 
                                  capture_output=True, text=True)
        if dll_result.returncode == 0:
            results['dlls'] = dll_result.stdout.split('\n')[:20]  # limit

        # Network connections
        net_result = subprocess.run(['vol', '-f', str(memory_dump_path), 'windows.netscan'], 
                                  capture_output=True, text=True)
        if net_result.returncode == 0:
            results['network'] = net_result.stdout.split('\n')[:20]  # limit

        # Registry hives
        reg_result = subprocess.run(['vol', '-f', str(memory_dump_path), 'windows.registry.hivelist'], 
                                  capture_output=True, text=True)
        if reg_result.returncode == 0:
            results['registry'] = reg_result.stdout.split('\n')[:20]  # limit

        logger.info('Memory analysis completed for %s', memory_dump_path)
        return results
    except Exception as e:
        logger.exception('Memory analysis failed for %s', memory_dump_path)
        return {'error': str(e)}

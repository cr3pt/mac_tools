import re, uuid, datetime
from ..core.models import CanonicalEvent

def parse_text_to_events(text: str, source='text'):
    events = []
    ts = datetime.datetime.utcnow().isoformat() + 'Z'
    for line in [x.strip() for x in text.splitlines() if x.strip()]:
        lower = line.lower()
        event_type = 'generic'
        network = {}
        registry = {}
        file = {}
        process = {'pid': None, 'ppid': None, 'image': None, 'command_line': line, 'user': None, 'integrity_level': None}
        if any(x in lower for x in ['http://','https://','tcp','udp','dns']):
            event_type = 'network'
            m = re.search(r'(https?://[^\s]+)', line)
            if m: network['url'] = m.group(1)
            m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if m: network['dst_ip'] = m.group(0)
        elif 'hklm\\' in lower or 'hkcu\\' in lower:
            event_type = 'registry'
            m = re.search(r'((?:HKLM|HKCU)\\.+)', line, re.I)
            if m: registry['key'] = m.group(1)
        elif re.search(r'[A-Za-z]:\\', line):
            event_type = 'file'
            m = re.search(r'([A-Za-z]:\\[^\r\n\t]+)', line)
            if m: file['path'] = m.group(1)
        elif any(x in lower for x in ['powershell','cmd.exe','rundll32','regsvr32','mshta','schtasks','wevtutil']):
            event_type = 'process'
            process['image'] = line.split()[0]
        events.append(CanonicalEvent(event_id=str(uuid.uuid4()), timestamp=ts, source=source, event_type=event_type, host={'hostname':'sandbox-win','vm_id':'vm1','os':'windows'}, process=process, file=file, registry=registry, network=network, raw=line, tags=[]))
    return events

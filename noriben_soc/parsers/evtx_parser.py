import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

def try_import_evtx():
    try:
        from Evtx.Evtx import Evtx
        return Evtx
    except Exception:
        return None

def parse_xml_event(xml_text):
    root = ET.fromstring(xml_text)
    timestamp=''; data_map={}
    for tc in root.findall('.//TimeCreated'): timestamp = tc.attrib.get('SystemTime','')
    for d in root.findall('.//EventData/Data'): data_map[d.attrib.get('Name','Data')] = d.text
    return {'event_id': str(uuid.uuid4()), 'timestamp': timestamp, 'source': 'evtx', 'event_type': 'process', 'host': {'hostname':'windows-guest','vm_id':'vm1','os':'windows'}, 'process': {'pid':None,'ppid':None,'image': data_map.get('Image'), 'command_line': data_map.get('CommandLine'), 'user': data_map.get('User'), 'integrity_level': None}, 'file': {'path': data_map.get('TargetFilename')} if data_map.get('TargetFilename') else {}, 'registry': {'key': data_map.get('TargetObject')} if data_map.get('TargetObject') else {}, 'network': {}, 'raw': data_map, 'tags': []}

def parse_evtx_to_events(path):
    p=Path(path); Evtx=try_import_evtx(); out=[]
    if Evtx and p.suffix.lower()=='.evtx':
        with Evtx(str(p)) as log:
            for rec in log.records():
                try: out.append(parse_xml_event(rec.xml()))
                except Exception: pass
        return out
    text=p.read_text(encoding='utf-8', errors='ignore')
    for chunk in text.split('</Event>'):
        if '<Event' in chunk:
            try: out.append(parse_xml_event(chunk+'</Event>'))
            except Exception: pass
    return out

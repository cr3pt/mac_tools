import re

def extract_iocs(text):
    patterns = {'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b','domain': r'\b[a-zA-Z0-9.-]+\.(?:com|net|org|ru|io|biz|co)\b','url': r'https?://[^\s\"]+','hash': r'\b[a-fA-F0-9]{32,64}\b','registry': r'(?:HKLM|HKCU)\\[^\r\n\t ]+','path': r'[A-Za-z]:\\[^\r\n\t]+'}
    out, seen = [], set()
    for kind, rx in patterns.items():
        for m in re.findall(rx, text):
            if (kind,m) not in seen:
                seen.add((kind,m)); out.append({'kind': kind, 'value': m, 'source': 'text'})
    return out

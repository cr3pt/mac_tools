from pathlib import Path
import time

def analyze_pcap(pcap_path: Path) -> list:
    """Parsuje PCAP i zwraca IOC: IP, domeny, URL, SNI, protokoly, FTP, SMTP, SSH, RDP, SMB, NTP, DHCP"""
    iocs = []
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest, TLS, FTP, SMTP, SSH, RDP, SMB, NTP, DHCP
        packets = rdpcap(str(pcap_path))
        seen_ips = set(); seen_dns = set(); seen_urls = set(); seen_sni = set()
        seen_ftp = set(); seen_smtp = set(); seen_ssh = set(); seen_rdp = set(); seen_smb = set(); seen_ntp = set(); seen_dhcp = set()
        beaconing = {}  # IP -> list of timestamps
        dga_domains = set()

        for pkt in packets:
            timestamp = pkt.time if hasattr(pkt, 'time') else time.time()

            # Zewnetrzne IP (nie RFC1918, nie loopback)
            if IP in pkt:
                dst = pkt[IP].dst; src = pkt[IP].src
                for ip in (dst, src):
                    if ip not in seen_ips and not _is_private(ip):
                        seen_ips.add(ip)
                        iocs.append({'type': 'IP', 'value': ip,
                                     'proto': _proto(pkt), 'severity': 'MEDIUM'})
                        # Beaconing check
                        if ip not in beaconing:
                            beaconing[ip] = []
                        beaconing[ip].append(timestamp)
                        if len(beaconing[ip]) > 5:  # arbitrary threshold
                            intervals = [beaconing[ip][i] - beaconing[ip][i-1] for i in range(1, len(beaconing[ip]))]
                            avg_interval = sum(intervals) / len(intervals)
                            if avg_interval < 60:  # <1 min
                                iocs.append({'type': 'BEACONING', 'value': f'Beaconing to {ip} every {avg_interval:.2f}s', 'severity': 'HIGH'})

            # DNS queries (TCP/UDP)
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                domain = pkt[DNSQR].qname.decode().rstrip('.')
                if domain not in seen_dns and not domain.endswith('.local'):
                    seen_dns.add(domain)
                    severity = _dns_severity(domain)
                    # DGA check
                    if _is_dga(domain):
                        dga_domains.add(domain)
                        severity = 'HIGH'
                        iocs.append({'type': 'DGA', 'value': domain, 'severity': 'HIGH'})
                    iocs.append({'type': 'DNS', 'value': domain, 'severity': severity})

            # HTTP (port 80)
            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('GET','POST','PUT','HEAD')):
                        line = payload.split('\n')[0].strip()
                        if line not in seen_urls:
                            seen_urls.add(line)
                            iocs.append({'type': 'HTTP', 'value': line, 'severity': 'HIGH'})
                        # MIME type
                        for line in payload.split('\n'):
                            if line.lower().startswith('content-type:'):
                                ct = line.split(':', 1)[1].strip()
                                if 'application/x-msdownload' in ct or 'application/octet-stream' in ct:
                                    iocs.append({'type': 'MIME_EXE', 'value': ct, 'severity': 'HIGH'})
                                break
                except Exception:
                    pass

            # HTTPS SNI (port 443, TLS Client Hello)
            if TCP in pkt and pkt[TCP].dport == 443 and TLS in pkt:
                try:
                    tls = pkt[TLS]
                    if hasattr(tls, 'msg') and tls.msg:
                        for msg in tls.msg:
                            if hasattr(msg, 'ext') and msg.ext:
                                for ext in msg.ext:
                                    if hasattr(ext, 'servernames') and ext.servernames:
                                        for sn in ext.servernames:
                                            sni = sn.servername.decode() if isinstance(sn.servername, bytes) else str(sn.servername)
                                            if sni not in seen_sni:
                                                seen_sni.add(sni)
                                                iocs.append({'type': 'SNI', 'value': sni, 'severity': _dns_severity(sni)})
                except Exception:
                    pass

            # FTP (port 21)
            if TCP in pkt and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21) and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('USER ', 'PASS ', 'RETR ', 'STOR ', 'EPSV ', 'PASV ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_ftp:
                            seen_ftp.add(cmd)
                            iocs.append({'type': 'FTP', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SMTP (port 25)
            if TCP in pkt and pkt[TCP].dport == 25 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('MAIL FROM:', 'RCPT TO:')):
                        addr = payload.split(':')[1].strip()
                        if addr not in seen_smtp:
                            seen_smtp.add(addr)
                            iocs.append({'type': 'SMTP', 'value': addr, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SSH (port 22)
            if TCP in pkt and pkt[TCP].dport == 22 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if 'SSH-' in payload:
                        version = payload.split('\n')[0].strip()
                        if version not in seen_ssh:
                            seen_ssh.add(version)
                            iocs.append({'type': 'SSH', 'value': version, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # RDP (port 3389)
            if TCP in pkt and pkt[TCP].dport == 3389 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith('\x03\x00\x00'):  # RDP header
                        if 'RDP' not in seen_rdp:
                            seen_rdp.add('RDP Connection')
                            iocs.append({'type': 'RDP', 'value': 'RDP Connection Attempt', 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # SMB (port 445)
            if TCP in pkt and pkt[TCP].dport == 445 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if '\xffSMB' in payload:  # SMB header
                        if 'SMB' not in seen_smb:
                            seen_smb.add('SMB Connection')
                            iocs.append({'type': 'SMB', 'value': 'SMB Connection Attempt', 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # NTP (port 123, UDP)
            if UDP in pkt and pkt[UDP].dport == 123 and NTP in pkt:
                try:
                    ntp = pkt[NTP]
                    server = pkt[IP].dst
                    if server not in seen_ntp:
                        seen_ntp.add(server)
                        iocs.append({'type': 'NTP', 'value': server, 'severity': 'LOW'})
                except Exception:
                    pass

            # DHCP (ports 67/68, UDP)
            if UDP in pkt and (pkt[UDP].dport == 67 or pkt[UDP].sport == 67) and DHCP in pkt:
                try:
                    dhcp = pkt[DHCP]
                    options = dhcp.options
                    for opt in options:
                        if opt[0] == 'domain':
                            domain = opt[1].decode() if isinstance(opt[1], bytes) else str(opt[1])
                            if domain not in seen_dhcp:
                                seen_dhcp.add(domain)
                                iocs.append({'type': 'DHCP', 'value': domain, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # HTTP responses (port 80)
            if TCP in pkt and pkt[TCP].sport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith('HTTP/'):
                        status_line = payload.split('\n')[0].strip()
                        if status_line not in seen_urls:
                            seen_urls.add(status_line)
                            iocs.append({'type': 'HTTP_RESP', 'value': status_line, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # POP3 (port 110)
            if TCP in pkt and pkt[TCP].dport == 110 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('USER ', 'PASS ', 'RETR ', 'DELE ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'POP3', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # IMAP (port 143)
            if TCP in pkt and pkt[TCP].dport == 143 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('LOGIN ', 'SELECT ', 'FETCH ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'IMAP', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # Telnet (port 23)
            if TCP in pkt and pkt[TCP].dport == 23 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload and not payload.startswith('\xff'):  # avoid telnet control chars
                        cmd = payload[:50]  # first 50 chars
                        if cmd not in seen_ssh:  # reuse set
                            seen_ssh.add(cmd)
                            iocs.append({'type': 'TELNET', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SNMP (port 161, UDP)
            if UDP in pkt and pkt[UDP].dport == 161 and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) > 6 and payload[0] == 0x30:  # ASN.1 SEQUENCE
                        community = payload[6:].decode('utf-8', errors='ignore').split('\x00')[0]
                        if community and community not in seen_dhcp:  # reuse set
                            seen_dhcp.add(community)
                            iocs.append({'type': 'SNMP', 'value': community, 'severity': 'HIGH'})
                except Exception:
                    pass

            # IRC (port 6667)
            if TCP in pkt and pkt[TCP].dport == 6667 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('NICK ', 'USER ', 'JOIN ', 'PRIVMSG ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'IRC', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # HTTP User-Agent and Referer (port 80)
            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    lines = payload.split('\n')
                    for line in lines:
                        if line.lower().startswith('user-agent:'):
                            ua = line.split(':', 1)[1].strip()
                            if ua not in seen_urls:
                                seen_urls.add(ua)
                                severity = 'HIGH' if _is_malware_ua(ua) else 'LOW'
                                iocs.append({'type': 'HTTP_UA', 'value': ua, 'severity': severity})
                        elif line.lower().startswith('referer:'):
                            ref = line.split(':', 1)[1].strip()
                            if ref not in seen_urls:
                                seen_urls.add(ref)
                                iocs.append({'type': 'HTTP_REF', 'value': ref, 'severity': 'MEDIUM'})
                        elif line.lower().startswith('cookie:'):
                            cookie = line.split(':', 1)[1].strip()
                            if cookie not in seen_urls:
                                seen_urls.add(cookie)
                                iocs.append({'type': 'COOKIE', 'value': cookie, 'severity': 'MEDIUM'})
                    # Parse JSON/XML in payload
                    body_start = payload.find('\r\n\r\n')
                    if body_start != -1:
                        body = payload[body_start + 4:]
                        _parse_json_xml(body, iocs, seen_urls, seen_smtp)
                except Exception:
                    pass

            # BitTorrent (various ports, handshake)
            if TCP in pkt and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) >= 68 and payload[:20] == b'\x13BitTorrent protocol':  # Handshake
                        peer_id = payload[48:68].decode('utf-8', errors='ignore')
                        if peer_id not in seen_dhcp:  # reuse
                            seen_dhcp.add(peer_id)
                            iocs.append({'type': 'BITTORRENT', 'value': f'Handshake with peer {peer_id}', 'severity': 'LOW'})
                except Exception:
                    pass

            # DNS tunneling (large TXT records)
            if DNS in pkt and DNSQR in pkt:
                for qr in pkt[DNS].qd or []:
                    if hasattr(qr, 'qtype') and qr.qtype == 16:  # TXT
                        if DNS in pkt and pkt[DNS].an:
                            for rr in pkt[DNS].an:
                                if hasattr(rr, 'rdata') and len(rr.rdata) > 100:  # arbitrary large
                                    txt = rr.rdata.decode('utf-8', errors='ignore')
                                    if txt not in seen_dns:
                                        seen_dns.add(txt)
                                        iocs.append({'type': 'DNS_TUNNEL', 'value': txt[:100], 'severity': 'HIGH'})

            # MQTT (port 1883)
            if TCP in pkt and pkt[TCP].dport == 1883 and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) > 2 and payload[0] & 0xF0 == 0x30:  # PUBLISH
                        topic_len = (payload[2] << 8) | payload[3]
                        topic = payload[4:4+topic_len].decode('utf-8', errors='ignore')
                        if topic not in seen_smtp:  # reuse
                            seen_smtp.add(topic)
                            iocs.append({'type': 'MQTT', 'value': topic, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # ICMP types
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                if icmp_type not in seen_ntp:  # reuse
                    seen_ntp.add(str(icmp_type))
                    iocs.append({'type': 'ICMP', 'value': f'ICMP Type {icmp_type}', 'severity': 'LOW'})

            # Anomalies: Large payloads, Rare ports
            if Raw in pkt:
                payload_len = len(pkt[Raw].load)
                if payload_len > 10000:  # arbitrary large
                    iocs.append({'type': 'ANOMALY', 'value': f'Large payload {payload_len} bytes', 'severity': 'MEDIUM'})
                port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                if port > 1024 and port not in [80,443,21,25,22,110,143,23,161,6667,3389,445,123,67,5060,3306,5432,389,88,1883]:
                    iocs.append({'type': 'RARE_PORT', 'value': f'Port {port}', 'severity': 'LOW'})
    except Exception as e:
        iocs.append({'type': 'ERROR', 'value': str(e), 'severity': 'LOW'})
    return iocs

def _is_private(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4: return True
    a = int(parts[0]); b = int(parts[1])
    return (a==10 or a==127 or (a==172 and 16<=b<=31) or (a==192 and b==168) or a>=224)

def _proto(pkt) -> str:
    from scapy.all import TCP, UDP, ICMP
    if TCP in pkt:   return f'TCP/{pkt["TCP"].dport}'
    if UDP in pkt:   return f'UDP/{pkt["UDP"].dport}'
    return 'OTHER'

def _dns_severity(domain: str) -> str:
    suspicious = ['.ru','.cn','.tk','.xyz','.top','.click','dyndns','no-ip','ngrok']
    return 'HIGH' if any(s in domain for s in suspicious) else 'MEDIUM'

def _is_dga(domain: str) -> bool:
    """Simple DGA detection based on entropy."""
    import math
    chars = [c for c in domain if c.isalnum()]
    if len(chars) < 5: return False
    freq = {}
    for c in chars:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f / len(chars)) * math.log2(f / len(chars)) for f in freq.values())
    return entropy > 3.5  # arbitrary threshold

def _is_malware_ua(ua: str) -> bool:
    """Check for known malware User-Agents."""
    malware_uas = ['malware', 'botnet', 'trojan', 'ransomware']
    return any(m in ua.lower() for m in malware_uas)

def _parse_json_xml(body: str, iocs: list, seen_urls: set, seen_smtp: set):
    """Parses JSON or XML in HTTP payload and extracts potential IOCs."""
    try:
        import json
        from xml.etree import ElementTree as ET

        # Try parsing as JSON
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and value not in seen_urls:
                        seen_urls.add(value)
                        iocs.append({'type': 'URL', 'value': value, 'severity': 'MEDIUM'})
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item not in seen_urls:
                                seen_urls.add(item)
                                iocs.append({'type': 'URL', 'value': item, 'severity': 'MEDIUM'})
        except json.JSONDecodeError:
            pass  # Not JSON, ignore

        # Try parsing as XML
        try:
            root = ET.fromstring(body)
            for elem in root.iter():
                if elem.tag and elem.text and elem.text.strip() and elem.text not in seen_urls:
                    seen_urls.add(elem.text.strip())
                    iocs.append({'type': 'URL', 'value': elem.text.strip(), 'severity': 'MEDIUM'})
        except ET.ParseError:
            pass  # Not XML, ignore
    except Exception:
        pass  # Ignore parsing errors
